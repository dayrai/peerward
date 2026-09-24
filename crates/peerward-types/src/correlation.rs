use core::fmt::Write as _;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::{Uuid, Variant, Version};

/// Transport-neutral request and W3C trace correlation values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelationContext {
    /// Independent operational request identity.
    pub request_id: Uuid,
    /// Nonzero W3C 16-byte trace identity.
    pub trace_id: [u8; 16],
    /// Nonzero W3C 8-byte parent/span identity.
    pub span_id: [u8; 8],
    /// W3C trace flags. Only the sampled low bit has defined semantics.
    pub flags: u8,
}

/// Strict correlation context validation error.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum CorrelationError {
    /// The request UUID, trace ID, or span ID is structurally invalid.
    #[error("correlation identifier is invalid")]
    InvalidIdentifier,
    /// The W3C `traceparent` syntax or version is unsupported.
    #[error("traceparent is malformed")]
    MalformedTraceparent,
}

impl CorrelationContext {
    /// Creates a fresh root context. Sampling remains a local configuration decision.
    pub fn root(sampled: bool) -> Self {
        let request_id = Uuid::new_v4();
        let trace_id = *Uuid::new_v4().as_bytes();
        let span_source = Uuid::new_v4();
        let mut span_id = [0_u8; 8];
        span_id.copy_from_slice(&span_source.as_bytes()[..8]);
        Self {
            request_id,
            trace_id,
            span_id,
            flags: u8::from(sampled),
        }
    }

    /// Strictly combines a `UUIDv4` request ID with an inbound W3C parent.
    pub fn from_traceparent(request_id: Uuid, traceparent: &str) -> Result<Self, CorrelationError> {
        if request_id.get_version() != Some(Version::Random)
            || traceparent.len() != 55
            || !traceparent.is_ascii()
            || &traceparent[2..3] != "-"
            || &traceparent[35..36] != "-"
            || &traceparent[52..53] != "-"
            || &traceparent[..2] == "ff"
        {
            return Err(CorrelationError::MalformedTraceparent);
        }
        let version = decode_hex::<1>(&traceparent[..2])?[0];
        if version != 0 {
            return Err(CorrelationError::MalformedTraceparent);
        }
        Self::from_parts(
            request_id,
            decode_hex(&traceparent[3..35])?,
            decode_hex(&traceparent[36..52])?,
            decode_hex::<1>(&traceparent[53..55])?[0],
        )
    }

    /// Validates explicitly transported fields.
    pub fn from_parts(
        request_id: Uuid,
        trace_id: [u8; 16],
        span_id: [u8; 8],
        flags: u8,
    ) -> Result<Self, CorrelationError> {
        if request_id.get_version() != Some(Version::Random)
            || request_id.get_variant() != Variant::RFC4122
            || trace_id.iter().all(|byte| *byte == 0)
            || span_id.iter().all(|byte| *byte == 0)
        {
            return Err(CorrelationError::InvalidIdentifier);
        }
        Ok(Self {
            request_id,
            trace_id,
            span_id,
            flags,
        })
    }

    /// Creates a child span with a distinct span ID and unchanged trace/request identity.
    #[must_use]
    pub fn child(self) -> Self {
        let source = Uuid::new_v4();
        let mut span_id = [0_u8; 8];
        span_id.copy_from_slice(&source.as_bytes()[..8]);
        Self { span_id, ..self }
    }

    /// Formats the canonical version-00 W3C header without baggage or vendor state.
    pub fn traceparent(self) -> String {
        let mut value = String::with_capacity(55);
        value.push_str("00-");
        append_hex(&mut value, &self.trace_id);
        value.push('-');
        append_hex(&mut value, &self.span_id);
        value.push('-');
        append_hex(&mut value, &[self.flags]);
        value
    }
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], CorrelationError> {
    if value.len() != N * 2
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(CorrelationError::MalformedTraceparent);
    }
    let mut bytes = [0_u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| CorrelationError::MalformedTraceparent)?;
    }
    Ok(bytes)
}

fn append_hex(output: &mut String, bytes: &[u8]) {
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traceparent_round_trip_and_child_are_strict() {
        let root = CorrelationContext::root(true);
        let parsed = CorrelationContext::from_traceparent(root.request_id, &root.traceparent())
            .expect("generated context is valid");
        assert_eq!(parsed, root);
        let child = root.child();
        assert_eq!(child.trace_id, root.trace_id);
        assert_ne!(child.span_id, root.span_id);
        assert!(CorrelationContext::from_traceparent(root.request_id, "00-0-0-01").is_err());
        assert!(
            CorrelationContext::from_traceparent(
                root.request_id,
                &root.traceparent().to_ascii_uppercase()
            )
            .is_err()
        );
        assert!(CorrelationContext::from_parts(root.request_id, [0; 16], [1; 8], 0).is_err());
        let mut bytes = *root.request_id.as_bytes();
        bytes[8] = 0;
        let invalid_variant = Uuid::from_bytes(bytes);
        assert!(CorrelationContext::from_parts(invalid_variant, [1; 16], [1; 8], 0).is_err());
        assert!(
            CorrelationContext::from_traceparent(invalid_variant, &root.traceparent()).is_err()
        );
    }
}
