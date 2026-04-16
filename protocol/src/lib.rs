//! Komms transaction payload (KOMMS Protocol v0, Appendix A).

mod encode;

pub use encode::{
    channel_id, dm_thread_id, encode_cbor_map, encode_komms_payload, message_id, ref_from_cid_str,
    ref_from_content_hash, server_id, signing_payload_cbor, RefBuildError,
};

use ciborium::Value;
use std::collections::BTreeMap;
use thiserror::Error;

pub const KOMMS_PAYLOAD_PREFIX: [u8; 4] = [0x4B, 0x43, 0x4F, 0x4D];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EventType {
    ServerCreate = 0,
    ServerUpdate = 1,
    ChannelCreate = 2,
    ChannelUpdate = 3,
    MessagePost = 4,
    MessageEdit = 5,
    MessageDelete = 6,
    DmMessagePost = 7,
    ReactionAdd = 8,
    ReactionRemove = 9,
    MemberJoin = 10,
    MemberLeave = 11,
    RoleAssign = 12,
    RoleRevoke = 13,
    ModerationAction = 14,
}

impl TryFrom<u64> for EventType {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ServerCreate),
            1 => Ok(Self::ServerUpdate),
            2 => Ok(Self::ChannelCreate),
            3 => Ok(Self::ChannelUpdate),
            4 => Ok(Self::MessagePost),
            5 => Ok(Self::MessageEdit),
            6 => Ok(Self::MessageDelete),
            7 => Ok(Self::DmMessagePost),
            8 => Ok(Self::ReactionAdd),
            9 => Ok(Self::ReactionRemove),
            10 => Ok(Self::MemberJoin),
            11 => Ok(Self::MemberLeave),
            12 => Ok(Self::RoleAssign),
            13 => Ok(Self::RoleRevoke),
            14 => Ok(Self::ModerationAction),
            _ => Err(()),
        }
    }
}

/// Parsed KOMMS event (map keys 0–11) after CBOR decode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedKommsEvent {
    pub v: u64,
    pub t: EventType,
    pub sid: Option<[u8; 32]>,
    pub cid: Option<[u8; 32]>,
    pub did: Option<[u8; 32]>,
    pub pid: Option<[u8; 32]>,
    pub mid: Option<[u8; 32]>,
    pub ref_bytes: Option<Vec<u8>>,
    pub enc: bool,
    pub ts: Option<u64>,
    pub n: Option<u64>,
    pub sig: Option<[u8; 64]>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("invalid CBOR: {0}")]
    Cbor(String),
    #[error("top-level CBOR value must be a map")]
    NotAMap,
    #[error("map key must be an unsigned integer in range 0..=11")]
    InvalidKey,
    #[error("duplicate map key {0}")]
    DuplicateKey(u8),
    #[error("field {0}: expected uint")]
    ExpectedUint(&'static str),
    #[error("field t: unknown event type")]
    UnknownEventType,
    #[error("field {0}: expected bool")]
    ExpectedBool(&'static str),
    #[error("field {0}: expected byte string of length 32")]
    ExpectedBytes32(&'static str),
    #[error("field {0}: expected byte string")]
    ExpectedBytes(&'static str),
    #[error("field sig: expected 64 bytes")]
    InvalidSigLength,
    #[error("missing required field {0}")]
    MissingField(&'static str),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("schema version v must be 0")]
    BadVersion,
    #[error("invalid content reference (ref) encoding")]
    InvalidRef,
    #[error("event type {0:?} forbids field {1}")]
    ForbiddenField(EventType, &'static str),
    #[error("event type {0:?} requires field {1}")]
    MissingForType(EventType, &'static str),
    #[error("encryption flag invalid for this event type")]
    InvalidEnc,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KommsPayloadError {
    #[error("payload too short for KOMMS prefix")]
    MissingPrefix,
    #[error(transparent)]
    Parse(#[from] ParseError),
    #[error(transparent)]
    Validation(#[from] ValidationError),
}


/// Strips the 4-byte KOMMS prefix and returns the CBOR slice.
pub fn strip_komms_envelope(raw: &[u8]) -> Option<&[u8]> {
    raw.strip_prefix(&KOMMS_PAYLOAD_PREFIX)
}

/// Decode CBOR map into [`ParsedKommsEvent`] (does not validate A7/A8).
pub fn parse_cbor_map(cbor: &[u8]) -> Result<ParsedKommsEvent, ParseError> {
    let value: Value = ciborium::de::from_reader(cbor).map_err(|e| ParseError::Cbor(e.to_string()))?;
    let Value::Map(entries) = value else {
        return Err(ParseError::NotAMap);
    };

    let mut fields: BTreeMap<u8, Value> = BTreeMap::new();
    for (k, v) in entries {
        let key_int = key_to_u8(&k)?;
        if key_int > 11 {
            return Err(ParseError::InvalidKey);
        }
        if fields.insert(key_int, v).is_some() {
            return Err(ParseError::DuplicateKey(key_int));
        }
    }

    let v = fields
        .remove(&0)
        .ok_or(ParseError::MissingField("v"))?
        .as_integer()
        .ok_or(ParseError::ExpectedUint("v"))?;
    let v = u64::try_from(v).map_err(|_| ParseError::ExpectedUint("v"))?;

    let t_raw = fields
        .remove(&1)
        .ok_or(ParseError::MissingField("t"))?
        .as_integer()
        .ok_or(ParseError::ExpectedUint("t"))?;
    let t_raw = u64::try_from(t_raw).map_err(|_| ParseError::ExpectedUint("t"))?;
    let t = EventType::try_from(t_raw).map_err(|_| ParseError::UnknownEventType)?;

    let enc = fields
        .remove(&8)
        .ok_or(ParseError::MissingField("enc"))?
        .as_bool()
        .ok_or(ParseError::ExpectedBool("enc"))?;

    let sid = pop_bytes32(&mut fields, 2, "sid")?;
    let cid = pop_bytes32(&mut fields, 3, "cid")?;
    let did = pop_bytes32(&mut fields, 4, "did")?;
    let pid = pop_bytes32(&mut fields, 5, "pid")?;
    let mid = pop_bytes32(&mut fields, 6, "mid")?;
    let ref_bytes = pop_bytes(&mut fields, 7, "ref")?;

    let ts = pop_uint_opt(&mut fields, 9, "ts")?;
    let n = pop_uint_opt(&mut fields, 10, "n")?;

    let sig = if let Some(val) = fields.remove(&11) {
        let bytes = val
            .into_bytes()
            .map_err(|_| ParseError::ExpectedBytes("sig"))?;
        if bytes.len() != 64 {
            return Err(ParseError::InvalidSigLength);
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Some(arr)
    } else {
        None
    };

    if !fields.is_empty() {
        return Err(ParseError::InvalidKey);
    }

    Ok(ParsedKommsEvent {
        v,
        t,
        sid,
        cid,
        did,
        pid,
        mid,
        ref_bytes,
        enc,
        ts,
        n,
        sig,
    })
}

fn key_to_u8(k: &Value) -> Result<u8, ParseError> {
    let i = k.as_integer().ok_or(ParseError::InvalidKey)?;
    u8::try_from(i).map_err(|_| ParseError::InvalidKey)
}

fn pop_bytes32(
    fields: &mut BTreeMap<u8, Value>,
    key: u8,
    name: &'static str,
) -> Result<Option<[u8; 32]>, ParseError> {
    let Some(val) = fields.remove(&key) else {
        return Ok(None);
    };
    let bytes = val
        .into_bytes()
        .map_err(|_| ParseError::ExpectedBytes32(name))?;
    if bytes.len() != 32 {
        return Err(ParseError::ExpectedBytes32(name));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(Some(out))
}

fn pop_bytes(
    fields: &mut BTreeMap<u8, Value>,
    key: u8,
    name: &'static str,
) -> Result<Option<Vec<u8>>, ParseError> {
    let Some(val) = fields.remove(&key) else {
        return Ok(None);
    };
    val.into_bytes()
        .map(Some)
        .map_err(|_| ParseError::ExpectedBytes(name))
}

fn pop_uint_opt(
    fields: &mut BTreeMap<u8, Value>,
    key: u8,
    name: &'static str,
) -> Result<Option<u64>, ParseError> {
    let Some(val) = fields.remove(&key) else {
        return Ok(None);
    };
    let i = val.as_integer().ok_or(ParseError::ExpectedUint(name))?;
    u64::try_from(i).map(Some).map_err(|_| ParseError::ExpectedUint(name))
}


/// Validate `ref` layout (A5) when present.
pub fn validate_ref(ref_bytes: &[u8]) -> Result<(), ValidationError> {
    if ref_bytes.is_empty() {
        return Err(ValidationError::InvalidRef);
    }
    match ref_bytes[0] {
        0x01 => {
            let body = &ref_bytes[1..];
            if body.is_empty() || std::str::from_utf8(body).is_err() {
                return Err(ValidationError::InvalidRef);
            }
        }
        0x02 => {
            if ref_bytes.len() != 1 + 32 {
                return Err(ValidationError::InvalidRef);
            }
        }
        _ => return Err(ValidationError::InvalidRef),
    }
    Ok(())
}

/// A7/A8 validation (required/forbidden fields, enc, ref rules).
pub fn validate_event(ev: &ParsedKommsEvent) -> Result<(), ValidationError> {
    if ev.v != 0 {
        return Err(ValidationError::BadVersion);
    }

    if let Some(ref r) = ev.ref_bytes {
        validate_ref(r)?;
    }

    use EventType::*;

    let require = |cond: bool, field: &'static str| -> Result<(), ValidationError> {
        if cond {
            Ok(())
        } else {
            Err(ValidationError::MissingForType(ev.t, field))
        }
    };

    let forbid = |present: bool, field: &'static str| -> Result<(), ValidationError> {
        if present {
            Err(ValidationError::ForbiddenField(ev.t, field))
        } else {
            Ok(())
        }
    };

    match ev.t {
        ServerCreate | ServerUpdate => {
            require(ev.sid.is_some(), "sid")?;
            forbid(ev.cid.is_some(), "cid")?;
            forbid(ev.did.is_some(), "did")?;
            if !ev.enc {
                Ok(())
            } else {
                Err(ValidationError::InvalidEnc)
            }
        }
        ChannelCreate | ChannelUpdate => {
            require(ev.sid.is_some(), "sid")?;
            require(ev.cid.is_some(), "cid")?;
            forbid(ev.did.is_some(), "did")?;
            if !ev.enc {
                Ok(())
            } else {
                Err(ValidationError::InvalidEnc)
            }
        }
        MessagePost => {
            require(ev.sid.is_some(), "sid")?;
            require(ev.cid.is_some(), "cid")?;
            require(ev.ref_bytes.is_some(), "ref")?;
            forbid(ev.enc, "enc")?;
            Ok(())
        }
        MessageEdit => {
            require(ev.sid.is_some(), "sid")?;
            require(ev.cid.is_some(), "cid")?;
            require(ev.mid.is_some(), "mid")?;
            require(ev.ref_bytes.is_some(), "ref")?;
            forbid(ev.enc, "enc")?;
            Ok(())
        }
        MessageDelete => {
            require(ev.sid.is_some(), "sid")?;
            require(ev.cid.is_some(), "cid")?;
            require(ev.mid.is_some(), "mid")?;
            forbid(ev.enc, "enc")?;
            Ok(())
        }
        DmMessagePost => {
            require(ev.did.is_some(), "did")?;
            require(ev.ref_bytes.is_some(), "ref")?;
            require(ev.enc, "enc")?;
            forbid(ev.sid.is_some(), "sid")?;
            forbid(ev.cid.is_some(), "cid")?;
            Ok(())
        }
        ReactionAdd | ReactionRemove => {
            require(ev.sid.is_some(), "sid")?;
            require(ev.cid.is_some(), "cid")?;
            require(ev.mid.is_some(), "mid")?;
            forbid(ev.enc, "enc")?;
            Ok(())
        }
        MemberJoin | MemberLeave => {
            require(ev.sid.is_some(), "sid")?;
            forbid(ev.cid.is_some(), "cid")?;
            forbid(ev.did.is_some(), "did")?;
            if !ev.enc {
                Ok(())
            } else {
                Err(ValidationError::InvalidEnc)
            }
        }
        RoleAssign | RoleRevoke => {
            require(ev.sid.is_some(), "sid")?;
            if !ev.enc {
                Ok(())
            } else {
                Err(ValidationError::InvalidEnc)
            }
        }
        ModerationAction => {
            require(ev.sid.is_some(), "sid")?;
            forbid(ev.enc, "enc")?;
            Ok(())
        }
    }
}

/// Prefix strip + CBOR parse + A7/A8 validation.
pub fn parse_komms_payload(raw: &[u8]) -> Result<ParsedKommsEvent, KommsPayloadError> {
    let cbor = strip_komms_envelope(raw).ok_or(KommsPayloadError::MissingPrefix)?;
    let ev = parse_cbor_map(cbor)?;
    validate_event(&ev)?;
    Ok(ev)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_map(pairs: Vec<(Value, Value)>) -> Vec<u8> {
        let v = Value::Map(pairs);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&v, &mut buf).unwrap();
        buf
    }

    fn sid() -> [u8; 32] {
        [7u8; 32]
    }

    fn ref_cid() -> Vec<u8> {
        let mut v = vec![0x01u8];
        v.extend_from_slice(b"bagaaa...");
        v
    }

    #[test]
    fn server_create_roundtrip() {
        let cbor = encode_map(vec![
            (Value::Integer(0.into()), Value::Integer(0.into())),
            (Value::Integer(1.into()), Value::Integer(0.into())),
            (Value::Integer(2.into()), Value::Bytes(sid().to_vec())),
            (Value::Integer(8.into()), Value::Bool(false)),
        ]);
        let mut raw = KOMMS_PAYLOAD_PREFIX.to_vec();
        raw.extend_from_slice(&cbor);
        let ev = parse_komms_payload(&raw).unwrap();
        assert_eq!(ev.t, EventType::ServerCreate);
        assert_eq!(ev.sid, Some(sid()));
    }

    #[test]
    fn message_post_requires_ref() {
        let cbor = encode_map(vec![
            (Value::Integer(0.into()), Value::Integer(0.into())),
            (Value::Integer(1.into()), Value::Integer(4.into())),
            (Value::Integer(2.into()), Value::Bytes(sid().to_vec())),
            (Value::Integer(3.into()), Value::Bytes([3u8; 32].to_vec())),
            (Value::Integer(8.into()), Value::Bool(false)),
        ]);
        let mut raw = KOMMS_PAYLOAD_PREFIX.to_vec();
        raw.extend_from_slice(&cbor);
        let err = parse_komms_payload(&raw).unwrap_err();
        assert!(matches!(
            err,
            KommsPayloadError::Validation(ValidationError::MissingForType(
                EventType::MessagePost,
                "ref"
            ))
        ));
    }

    #[test]
    fn dm_must_not_have_sid() {
        let cbor = encode_map(vec![
            (Value::Integer(0.into()), Value::Integer(0.into())),
            (Value::Integer(1.into()), Value::Integer(7.into())),
            (Value::Integer(2.into()), Value::Bytes(sid().to_vec())),
            (Value::Integer(4.into()), Value::Bytes([9u8; 32].to_vec())),
            (Value::Integer(7.into()), Value::Bytes(ref_cid())),
            (Value::Integer(8.into()), Value::Bool(true)),
        ]);
        let mut raw = KOMMS_PAYLOAD_PREFIX.to_vec();
        raw.extend_from_slice(&cbor);
        let err = parse_komms_payload(&raw).unwrap_err();
        assert!(matches!(
            err,
            KommsPayloadError::Validation(ValidationError::ForbiddenField(
                EventType::DmMessagePost,
                "sid"
            ))
        ));
    }

    #[test]
    fn wrong_prefix_rejected() {
        let err = parse_komms_payload(b"XXXX").unwrap_err();
        assert!(matches!(err, KommsPayloadError::MissingPrefix));
    }

    #[test]
    fn duplicate_key_rejected() {
        let v = Value::Map(vec![
            (Value::Integer(0.into()), Value::Integer(0.into())),
            (Value::Integer(0.into()), Value::Integer(0.into())),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&v, &mut buf).unwrap();
        let err = parse_cbor_map(&buf).unwrap_err();
        assert!(matches!(err, ParseError::DuplicateKey(0)));
    }
}