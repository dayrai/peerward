const PRESENCE_WIRE_VERSION: u8 = 1;
const PRESENCE_WIRE_LENGTH: usize = 67;

/// Authenticated in-memory routing and fencing view shared across the Relay mesh.
#[derive(Debug, Default)]
struct PresenceCache {
    entries: BTreeMap<(PeerId, PresenceRole, Option<RelayId>), PresenceCacheEntry>,
    generations: BTreeMap<(PeerId, PresenceRole, Option<RelayId>), i64>,
    updates: BTreeMap<(PeerId, PresenceRole, Option<RelayId>), u64>,
    revision: u64,
}

/// One exact presence incarnation learned from a database snapshot or authenticated Relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PresenceCacheEntry {
    peer_id: PeerId,
    relay_id: RelayId,
    attachment_id: AttachmentId,
    role: PresenceRole,
    generation: i64,
    lease_deadline: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PresenceAnnouncement {
    entry: PresenceCacheEntry,
    released: bool,
}

impl PresenceCache {
    fn install_snapshot(
        &mut self,
        rows: &[peerward_store::PresenceSnapshot],
        started: u64,
    ) -> Result<(), RelayError> {
        let keys: BTreeSet<_> = rows
            .iter()
            .map(|row| {
                (
                    row.peer_id,
                    row.role,
                    (row.role == PresenceRole::Standby).then_some(row.relay_id),
                )
            })
            .collect();
        // The DB query runs without this mutex. Retain arrivals/renewals made after
        // it started, and retain fencing tombstones so old snapshots cannot resurrect
        // a session already released locally or by an authenticated backbone update.
        self.entries.retain(|key, _| {
            keys.contains(key)
                || self
                    .updates
                    .get(key)
                    .is_some_and(|revision| *revision > started)
        });
        for row in rows {
            let entry = PresenceCacheEntry {
                peer_id: row.peer_id,
                relay_id: row.relay_id,
                attachment_id: row.attachment_id,
                role: row.role,
                generation: row.generation,
                lease_deadline: row.lease_deadline,
            };
            let key = presence_key(entry);
            if (self
                .updates
                .get(&key)
                .is_some_and(|revision| *revision > started)
                && self
                    .generations
                    .get(&key)
                    .is_some_and(|generation| entry.generation <= *generation))
                || self.entries.get(&key).is_some_and(|current| {
                    current.generation == entry.generation
                        && current.lease_deadline > entry.lease_deadline
                })
            {
                continue;
            }
            self.observe_local(entry)?;
        }
        Ok(())
    }

    fn observe_local(&mut self, entry: PresenceCacheEntry) -> Result<bool, RelayError> {
        self.observe(
            entry.relay_id,
            PresenceAnnouncement {
                entry,
                released: false,
            },
        )
    }

    fn release_local(&mut self, entry: PresenceCacheEntry) -> Result<bool, RelayError> {
        self.observe(
            entry.relay_id,
            PresenceAnnouncement {
                entry,
                released: true,
            },
        )
    }

    fn observe(
        &mut self,
        authenticated_relay: RelayId,
        update: PresenceAnnouncement,
    ) -> Result<bool, RelayError> {
        let entry = update.entry;
        if entry.relay_id != authenticated_relay || entry.generation <= 0 {
            tracing::warn!(
                peer_id = %entry.peer_id,
                announced_relay = %entry.relay_id,
                authenticated_relay = %authenticated_relay,
                generation = entry.generation,
                "authenticated Relay presence identity is invalid"
            );
            return Err(RelayError::StaleFence);
        }
        let key = presence_key(entry);
        let current_generation = self.generations.get(&key).copied();
        if current_generation.is_some_and(|current| entry.generation < current) {
            tracing::warn!(
                peer_id = %entry.peer_id,
                announced_generation = entry.generation,
                current_generation,
                "authenticated Relay presence generation rolled back"
            );
            return Ok(false);
        }
        if let Some(current) = self.entries.get(&key) {
            if entry.generation == current.generation
                && (entry.relay_id != current.relay_id
                    || entry.attachment_id != current.attachment_id
                    || entry.role != current.role
                    || (!update.released
                        && entry.lease_deadline.unix_timestamp()
                            < current.lease_deadline.unix_timestamp()))
            {
                tracing::warn!(
                    peer_id = %entry.peer_id,
                    relay_id = %entry.relay_id,
                    generation = entry.generation,
                    "authenticated Relay presence reused a generation with different fields"
                );
                return Err(RelayError::StaleFence);
            }
        } else if current_generation == Some(entry.generation) {
            return Ok(false);
        }
        let advanced = current_generation.is_none_or(|current| entry.generation > current);
        self.revision = self.revision.checked_add(1).ok_or(RelayError::StaleFence)?;
        self.updates.insert(key, self.revision);
        self.generations.insert(key, entry.generation);
        if update.released {
            self.entries.remove(&key);
        } else {
            self.entries.insert(key, entry);
        }
        Ok(advanced || update.released)
    }

    fn primary_owner(
        &self,
        peer_id: PeerId,
        now: OffsetDateTime,
        permit_expired: bool,
    ) -> Result<peerward_store::PresenceOwner, RelayError> {
        let entry = self
            .entries
            .get(&(peer_id, PresenceRole::Primary, None))
            .filter(|entry| permit_expired || entry.lease_deadline > now)
            .ok_or(RelayError::NoRoute)?;
        Ok(peerward_store::PresenceOwner {
            relay_id: entry.relay_id,
            generation: entry.generation,
        })
    }

    fn matches_attachment(&self, lease: &PresenceLease, generation: i64) -> bool {
        let key = (
            lease.peer_id,
            lease.role,
            (lease.role == PresenceRole::Standby).then_some(lease.relay_id),
        );
        self.entries.get(&key).is_some_and(|entry| {
            entry.generation == generation
                && entry.relay_id == lease.relay_id
                && entry.attachment_id == lease.attachment_id
        })
    }

    fn authenticates_source(
        &self,
        peer_id: PeerId,
        relay_id: RelayId,
        generation: i64,
        now: OffsetDateTime,
        permit_expired: bool,
    ) -> bool {
        [
            (peer_id, PresenceRole::Primary, None),
            (peer_id, PresenceRole::Standby, Some(relay_id)),
        ]
        .into_iter()
        .filter_map(|key| self.entries.get(&key))
        .any(|entry| {
            entry.relay_id == relay_id
                && entry.generation == generation
                && (permit_expired || entry.lease_deadline > now)
        })
    }

    fn announcements_owned_by(&self, relay_id: RelayId) -> Vec<PresenceAnnouncement> {
        self.entries
            .values()
            .filter(|entry| entry.relay_id == relay_id)
            .copied()
            .map(|entry| PresenceAnnouncement {
                entry,
                released: false,
            })
            .collect()
    }
}

fn presence_key(entry: PresenceCacheEntry) -> (PeerId, PresenceRole, Option<RelayId>) {
    (
        entry.peer_id,
        entry.role,
        (entry.role == PresenceRole::Standby).then_some(entry.relay_id),
    )
}

fn encode_presence(update: PresenceAnnouncement) -> Vec<u8> {
    let mut body = Vec::with_capacity(PRESENCE_WIRE_LENGTH);
    body.push(PRESENCE_WIRE_VERSION);
    body.push(u8::from(update.released));
    body.extend_from_slice(update.entry.peer_id.as_bytes());
    body.extend_from_slice(update.entry.relay_id.as_bytes());
    body.extend_from_slice(update.entry.attachment_id.as_bytes());
    body.push(match update.entry.role {
        PresenceRole::Primary => 1,
        PresenceRole::Standby => 2,
    });
    body.extend_from_slice(&update.entry.generation.to_be_bytes());
    body.extend_from_slice(&update.entry.lease_deadline.unix_timestamp().to_be_bytes());
    body
}

fn decode_presence(body: &[u8]) -> Result<PresenceAnnouncement, RelayError> {
    if body.len() != PRESENCE_WIRE_LENGTH || body[0] != PRESENCE_WIRE_VERSION || body[1] > 1 {
        return Err(RelayError::Wire(WireError::KindMismatch));
    }
    let peer_id = PeerId::from_uuid(
        uuid::Uuid::from_slice(&body[2..18])
            .map_err(|_| RelayError::Wire(WireError::KindMismatch))?,
    )
    .map_err(|_| RelayError::Wire(WireError::KindMismatch))?;
    let relay_id = RelayId::from_uuid(
        uuid::Uuid::from_slice(&body[18..34])
            .map_err(|_| RelayError::Wire(WireError::KindMismatch))?,
    )
    .map_err(|_| RelayError::Wire(WireError::KindMismatch))?;
    let attachment_id = AttachmentId::from_uuid(
        uuid::Uuid::from_slice(&body[34..50])
            .map_err(|_| RelayError::Wire(WireError::KindMismatch))?,
    )
    .map_err(|_| RelayError::Wire(WireError::KindMismatch))?;
    let role = match body[50] {
        1 => PresenceRole::Primary,
        2 => PresenceRole::Standby,
        _ => return Err(RelayError::Wire(WireError::KindMismatch)),
    };
    let generation = i64::from_be_bytes(
        body[51..59]
            .try_into()
            .map_err(|_| RelayError::Wire(WireError::KindMismatch))?,
    );
    let deadline = i64::from_be_bytes(
        body[59..67]
            .try_into()
            .map_err(|_| RelayError::Wire(WireError::KindMismatch))?,
    );
    let lease_deadline = OffsetDateTime::from_unix_timestamp(deadline)
        .map_err(|_| RelayError::Wire(WireError::KindMismatch))?;
    Ok(PresenceAnnouncement {
        entry: PresenceCacheEntry {
            peer_id,
            relay_id,
            attachment_id,
            role,
            generation,
            lease_deadline,
        },
        released: body[1] == 1,
    })
}
