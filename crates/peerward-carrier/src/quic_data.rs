//! Preserve the complete existing backbone wrapper, including routing fences.
use peerward_wire::control_envelope::Message as Kind;
use peerward_wire::{ControlEnvelope, ForwardedPacket, OpaqueFrameKind, RelayEnvelopeV2};
use prost::Message;
use std::io;

pub(super) fn opaque(control: &ControlEnvelope) -> io::Result<Option<RelayEnvelopeV2>> {
    match &control.message {
        Some(Kind::Opaque(frame)) if frame.kind == OpaqueFrameKind::Session as i32 => {
            Ok(Some(frame.clone()))
        }
        Some(Kind::Forwarded(frame)) => backbone_opaque(frame),
        _ => Ok(None),
    }
}
fn backbone_opaque(frame: &ForwardedPacket) -> io::Result<Option<RelayEnvelopeV2>> {
    let body = &frame.body;
    let payload = match body.first() {
        Some(2) => &body[1..],
        Some(3) if body.get(1) == Some(&1) => {
            if body.len() < 48 {
                return Err(super::invalid("truncated backbone route"));
            }
            let count = usize::from(body[43]);
            if !(1..=4).contains(&count) || !(1..=4).contains(&body[42]) {
                return Err(super::invalid("invalid backbone route bound"));
            }
            let end = 44 + count * 16;
            if body.len() < end + 4 {
                return Err(super::invalid("truncated backbone path"));
            }
            let size =
                u32::from_be_bytes(body[end..end + 4].try_into().expect("checked route")) as usize;
            if end + 4 + size != body.len() {
                return Err(super::invalid("invalid backbone body size"));
            }
            &body[end + 4..]
        }
        _ => return Ok(None), // Presence/control still uses the reliable stream.
    };
    if payload.len() < 44 {
        return Err(super::invalid("truncated backbone source fence"));
    }
    let size = u32::from_be_bytes(payload[40..44].try_into().expect("checked payload")) as usize;
    if size + 44 != payload.len() || size > 60 * 1024 {
        return Err(super::invalid("invalid backbone payload size"));
    }
    let control = ControlEnvelope::decode(&payload[44..]).map_err(io::Error::other)?;
    if control.encode_to_vec() != payload[44..] {
        return Err(super::invalid("noncanonical backbone control"));
    }
    let Some(Kind::Opaque(opaque)) = control.message else {
        return Ok(None);
    };
    if opaque.kind != OpaqueFrameKind::Session as i32 {
        return Ok(None);
    }
    if opaque.mesh_id != frame.mesh_id
        || opaque.source_peer != payload[..16]
        || opaque.destination_peer != payload[16..32]
    {
        return Err(super::invalid("backbone source or destination mismatch"));
    }
    Ok(Some(opaque))
}
