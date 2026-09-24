use std::collections::{BTreeMap, BTreeSet};

const DEFAULT_PER_SOURCE_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_GLOBAL_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_FRAGMENT_TIMEOUT_SECONDS: u64 = 15;

/// A fragment was invalid before it could be presented to policy evaluation.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum ReassemblyError {
    /// The packet header or fragment alignment is invalid.
    #[error("fragment is malformed")]
    Malformed,
    /// Two fragments cover any of the same bytes.
    #[error("fragment overlaps an existing fragment")]
    Overlap,
    /// A final length conflicts with another fragment.
    #[error("fragment set has contradictory lengths")]
    Contradictory,
    /// Per-source or global retained-memory limit was reached.
    #[error("fragment reassembly quota exceeded")]
    QuotaExceeded,
}

/// A complete datagram and the authenticated original packets that formed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReassembledDatagram {
    /// Canonical packet with the fragment header/flags removed.
    pub packet: Vec<u8>,
    /// Original packets ordered by fragment offset, suitable for MTU-safe forwarding.
    pub original_fragments: Vec<Vec<u8>>,
}

/// Result of submitting one IP packet to a reassembler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReassemblyStatus {
    /// More non-overlapping fragments are required.
    Pending,
    /// A non-fragmented packet or a fully reassembled datagram is ready for policy.
    Complete(ReassembledDatagram),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ReassemblyKey {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    identification: u32,
}

#[derive(Debug, Clone)]
enum HeaderTemplate {
    Ipv4(Vec<u8>),
    Ipv6 {
        prefix: Vec<u8>,
        previous_next_header: usize,
        fragment_next_header: u8,
    },
}

#[derive(Debug, Clone)]
struct StoredFragment {
    payload: Vec<u8>,
    original: Vec<u8>,
}

#[derive(Debug, Clone)]
struct FragmentSet {
    source: IpAddr,
    expires_at: u64,
    retained_bytes: usize,
    payload_bytes: usize,
    template: Option<HeaderTemplate>,
    final_length: Option<usize>,
    fragments: BTreeMap<usize, StoredFragment>,
}

/// Bounded IPv4/IPv6 fragment reassembly keyed by authenticated source address.
///
/// The default limits retain at most 4 MiB per source, 64 MiB globally, and 15 seconds.
#[derive(Debug)]
pub struct FragmentReassembler {
    sets: HashMap<ReassemblyKey, FragmentSet>,
    expirations: BTreeSet<(u64, ReassemblyKey)>,
    source_bytes: HashMap<IpAddr, usize>,
    retained_bytes: usize,
    per_source_bytes: usize,
    global_bytes: usize,
    timeout_seconds: u64,
}

impl Default for FragmentReassembler {
    fn default() -> Self {
        Self::new(
            DEFAULT_PER_SOURCE_BYTES,
            DEFAULT_GLOBAL_BYTES,
            DEFAULT_FRAGMENT_TIMEOUT_SECONDS,
        )
        .expect("fixed reassembly limits are valid")
    }
}

impl FragmentReassembler {
    /// Creates a reassembler with exact retained-memory and timeout limits.
    pub fn new(
        per_source_bytes: usize,
        global_bytes: usize,
        timeout_seconds: u64,
    ) -> Result<Self, ReassemblyError> {
        if per_source_bytes == 0
            || global_bytes < per_source_bytes
            || timeout_seconds == 0
        {
            return Err(ReassemblyError::Malformed);
        }
        Ok(Self {
            sets: HashMap::new(),
            expirations: BTreeSet::new(),
            source_bytes: HashMap::new(),
            retained_bytes: 0,
            per_source_bytes,
            global_bytes,
            timeout_seconds,
        })
    }

    /// Submits one exact IP packet. Errors discard the affected fragment set.
    pub fn push(
        &mut self,
        packet: &[u8],
        now_seconds: u64,
    ) -> Result<ReassemblyStatus, ReassemblyError> {
        self.expire(now_seconds);
        let parsed = parse_packet(packet).map_err(|_| ReassemblyError::Malformed)?;
        let Some(fragment) = parsed.fragment else {
            return Ok(ReassemblyStatus::Complete(ReassembledDatagram {
                packet: packet.to_vec(),
                original_fragments: vec![packet.to_vec()],
            }));
        };
        if fragment.offset == 0 && !fragment.more {
            return Ok(ReassemblyStatus::Complete(ReassembledDatagram {
                packet: packet.to_vec(),
                original_fragments: vec![packet.to_vec()],
            }));
        }
        let key = ReassemblyKey {
            source: parsed.source,
            destination: parsed.destination,
            // IPv6 reassembly is scoped by source/destination/identification;
            // only offset zero supplies the fragmentable Next Header (RFC 8200).
            protocol: if parsed.source.is_ipv6() { 0 } else { parsed.protocol },
            identification: fragment.identification,
        };
        let prepared = (|| {
            let decoded = decode_fragment(packet, fragment)?;
            let offset = usize::from(fragment.offset) * 8;
            let end = offset
                .checked_add(decoded.payload.len())
                .filter(|end| u16::try_from(*end).is_ok())
                .ok_or(ReassemblyError::Malformed)?;
            if decoded.payload.is_empty() || (fragment.more && decoded.payload.len() % 8 != 0) {
                return Err(ReassemblyError::Malformed);
            }
            let charge = decoded
                .payload
                .len()
                .checked_add(packet.len())
                .ok_or(ReassemblyError::QuotaExceeded)?;
            Ok((decoded, offset, end, charge))
        })();
        let (decoded, offset, end, charge) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                self.remove_set(&key);
                return Err(error);
            }
        };

        let result = self.insert_fragment(
            key,
            fragment,
            offset,
            end,
            decoded,
            packet,
            charge,
            now_seconds,
        );
        if result.is_err() {
            self.remove_set(&key);
        }
        result
    }

    /// Expires old incomplete sets and returns how many were discarded.
    pub fn expire(&mut self, now_seconds: u64) -> usize {
        let mut count = 0;
        while let Some(&(deadline, key)) = self.expirations.first() {
            if deadline > now_seconds {
                break;
            }
            self.remove_set(&key);
            count += 1;
        }
        count
    }

    /// Current retained bytes, including original packets and fragment payloads.
    pub const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    fn insert_fragment(
        &mut self,
        key: ReassemblyKey,
        fragment: Fragment,
        offset: usize,
        end: usize,
        decoded: DecodedFragment,
        packet: &[u8],
        charge: usize,
        now_seconds: u64,
    ) -> Result<ReassemblyStatus, ReassemblyError> {
        let source_retained = self.source_bytes.get(&key.source).copied().unwrap_or(0);
        if source_retained.saturating_add(charge) > self.per_source_bytes
            || self.retained_bytes.saturating_add(charge) > self.global_bytes
        {
            return Err(ReassemblyError::QuotaExceeded);
        }
        let set = self.sets.entry(key).or_insert_with(|| {
            let expires_at = now_seconds.saturating_add(self.timeout_seconds);
            self.expirations.insert((expires_at, key));
            FragmentSet {
                source: key.source,
                expires_at,
                retained_bytes: 0,
                payload_bytes: 0,
                template: None,
                final_length: None,
                fragments: BTreeMap::new(),
            }
        });
        // Previously accepted fragments never overlap, so only the two
        // neighbors can intersect this interval.
        if set.fragments.range(..=offset).next_back().is_some_and(|(start, fragment)| {
            start + fragment.payload.len() > offset
        }) || set.fragments.range(offset..).next().is_some_and(|(start, _)| *start < end) {
            return Err(ReassemblyError::Overlap);
        }
        if set.final_length.is_some_and(|length| end > length) {
            return Err(ReassemblyError::Contradictory);
        }
        if !fragment.more {
            if set.final_length.is_some_and(|length| length != end)
                || set.fragments.last_key_value().is_some_and(|(existing_offset, existing)| {
                    existing_offset + existing.payload.len() > end
                })
            {
                return Err(ReassemblyError::Contradictory);
            }
            set.final_length = Some(end);
        }
        if offset == 0 {
            if set.template.is_some() {
                return Err(ReassemblyError::Overlap);
            }
            set.template = Some(decoded.template);
        }
        set.retained_bytes += charge;
        set.payload_bytes += decoded.payload.len();
        set.fragments.insert(
            offset,
            StoredFragment {
                payload: decoded.payload,
                original: packet.to_vec(),
            },
        );
        *self.source_bytes.entry(key.source).or_default() += charge;
        self.retained_bytes += charge;

        if !is_complete(set) {
            return Ok(ReassemblyStatus::Pending);
        }
        let set = self.sets.remove(&key).expect("complete set exists");
        self.expirations.remove(&(set.expires_at, key));
        self.release_usage(&set);
        let datagram = assemble(set)?;
        parse_packet(&datagram.packet).map_err(|_| ReassemblyError::Malformed)?;
        Ok(ReassemblyStatus::Complete(datagram))
    }

    fn remove_set(&mut self, key: &ReassemblyKey) {
        if let Some(set) = self.sets.remove(key) {
            self.expirations.remove(&(set.expires_at, *key));
            self.release_usage(&set);
        }
    }

    fn release_usage(&mut self, set: &FragmentSet) {
        self.retained_bytes = self.retained_bytes.saturating_sub(set.retained_bytes);
        if let Some(source) = self.source_bytes.get_mut(&set.source) {
            *source = source.saturating_sub(set.retained_bytes);
            if *source == 0 {
                self.source_bytes.remove(&set.source);
            }
        }
    }
}

struct DecodedFragment {
    template: HeaderTemplate,
    payload: Vec<u8>,
}

fn decode_fragment(packet: &[u8], fragment: Fragment) -> Result<DecodedFragment, ReassemblyError> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => {
            let header_length = usize::from(packet[0] & 0x0f) * 4;
            let payload = packet
                .get(header_length..)
                .ok_or(ReassemblyError::Malformed)?
                .to_vec();
            let template = if fragment.offset == 0 {
                HeaderTemplate::Ipv4(packet[..header_length].to_vec())
            } else {
                HeaderTemplate::Ipv4(Vec::new())
            };
            Ok(DecodedFragment { template, payload })
        }
        Some(6) => {
            let (cursor, previous_next_header) = ipv6_fragment_header(packet)?;
            let payload = packet
                .get(cursor + 8..)
                .ok_or(ReassemblyError::Malformed)?
                .to_vec();
            let template = if fragment.offset == 0 {
                HeaderTemplate::Ipv6 {
                    prefix: packet[..cursor].to_vec(),
                    previous_next_header,
                    fragment_next_header: packet[cursor],
                }
            } else {
                HeaderTemplate::Ipv6 {
                    prefix: Vec::new(),
                    previous_next_header: 0,
                    fragment_next_header: 0,
                }
            };
            Ok(DecodedFragment { template, payload })
        }
        _ => Err(ReassemblyError::Malformed),
    }
}

fn ipv6_fragment_header(packet: &[u8]) -> Result<(usize, usize), ReassemblyError> {
    if packet.len() < 48 {
        return Err(ReassemblyError::Malformed);
    }
    let mut next = packet[6];
    let mut previous_next_header = 6_usize;
    let mut cursor = 40_usize;
    for _ in 0..8 {
        match next {
            44 => return Ok((cursor, previous_next_header)),
            0 | 43 | 60 => {
                let extension_length = (usize::from(*packet.get(cursor + 1).ok_or(
                    ReassemblyError::Malformed,
                )?) + 1)
                    * 8;
                let extension_next = *packet.get(cursor).ok_or(ReassemblyError::Malformed)?;
                previous_next_header = cursor;
                cursor = cursor
                    .checked_add(extension_length)
                    .filter(|cursor| *cursor <= packet.len())
                    .ok_or(ReassemblyError::Malformed)?;
                next = extension_next;
            }
            _ => return Err(ReassemblyError::Malformed),
        }
    }
    Err(ReassemblyError::Malformed)
}

fn is_complete(set: &FragmentSet) -> bool {
    // Non-overlapping intervals are confined to [0, final_length). Their total
    // length reaches that boundary exactly when there are no missing bytes.
    set.template.is_some() && set.final_length == Some(set.payload_bytes)
}

fn assemble(set: FragmentSet) -> Result<ReassembledDatagram, ReassemblyError> {
    let mut payload = Vec::with_capacity(set.final_length.unwrap_or_default());
    let mut original_fragments = Vec::with_capacity(set.fragments.len());
    for fragment in set.fragments.into_values() {
        payload.extend_from_slice(&fragment.payload);
        original_fragments.push(fragment.original);
    }
    let packet = match set.template.ok_or(ReassemblyError::Malformed)? {
        HeaderTemplate::Ipv4(mut header) => {
            if header.len() < 20 || header.len() + payload.len() > u16::MAX as usize {
                return Err(ReassemblyError::Malformed);
            }
            let original_flags = u16::from_be_bytes([header[6], header[7]]) & 0x4000;
            header[6..8].copy_from_slice(&original_flags.to_be_bytes());
            let total = u16::try_from(header.len() + payload.len())
                .map_err(|_| ReassemblyError::Malformed)?;
            header[2..4].copy_from_slice(&total.to_be_bytes());
            header[10..12].fill(0);
            let checksum = ipv4_checksum(&header);
            header[10..12].copy_from_slice(&checksum.to_be_bytes());
            header.extend_from_slice(&payload);
            header
        }
        HeaderTemplate::Ipv6 {
            mut prefix,
            previous_next_header,
            fragment_next_header,
        } => {
            if prefix.len() < 40
                || previous_next_header >= prefix.len()
                || prefix.len() + payload.len() - 40 > u16::MAX as usize
            {
                return Err(ReassemblyError::Malformed);
            }
            prefix[previous_next_header] = fragment_next_header;
            let length = u16::try_from(prefix.len() + payload.len() - 40)
                .map_err(|_| ReassemblyError::Malformed)?;
            prefix[4..6].copy_from_slice(&length.to_be_bytes());
            prefix.extend_from_slice(&payload);
            prefix
        }
    };
    Ok(ReassembledDatagram {
        packet,
        original_fragments,
    })
}
