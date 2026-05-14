//! KOMMS transaction-payload codec.
//!
//! This crate is the single source of truth for the KOMMS on-chain
//! payload format. It implements both the historical v0 wire format and
//! the v1 spec (`planning-docs/komms_protocol_v_1.md`). v1 indexers
//! accept v0 events verbatim and treat reserved / vendor event types as
//! opaque so the protocol can grow additively.
//!
//! ## Public API surface
//!
//! - [`parse_komms_payload`] — primary wire-entry parser. Enforces the
//!   `KCOM` prefix, canonical CBOR (`canonical::validate_canonical`), and
//!   v0/v1 validation rules. Use this on every byte stream that arrives
//!   from chain.
//! - [`parse_cbor_map`] — low-level CBOR-only parser. Does NOT enforce
//!   canonicality and is intended for unit tests and round-trip helpers.
//! - [`validate_event`] — pure validation (A7/A8 of v0, §10 of v1).
//! - [`validate_ref`] — `ref_bytes` field layout check.
//! - [`encode::*`] — canonical CBOR encoder + identifier helpers.

pub mod canonical;
pub mod encode;

use ciborium::Value;
use std::collections::BTreeMap;
use thiserror::Error;

pub use canonical::CanonicalError;
pub use encode::{
    RefBuildError, channel_id, dm_thread_id, encode_cbor_map, encode_komms_payload, message_id,
    participant_id, ref_from_cid_str, ref_from_content_hash, server_id, signing_payload_cbor,
};

/// 4-byte ASCII envelope prefix: `KCOM`.
pub const KOMMS_PAYLOAD_PREFIX: [u8; 4] = [0x4B, 0x43, 0x4F, 0x4D];

/// Maximum protocol version this crate parses structurally. Higher `v`
/// values surface as [`KommsPayloadError::UnsupportedVersion`] so the
/// indexer can persist the raw bytes for a future deploy without
/// crashing.
pub const MAX_KNOWN_VERSION: u64 = 1;

/// Highest map key this crate parses at the v1 core level. Keys in
/// [`EXTENSION_KEY_MIN`]..=255 are preserved opaquely as
/// `extension_fields`.
pub const V1_CORE_KEY_MAX: u8 = 23;
pub const EXTENSION_KEY_MIN: u8 = 24;

/// KOMMS event type. Known v0 (0..=14) and v1 (15..=20) variants plus a
/// catch-all [`EventType::Reserved`] for forward-compatible event types
/// (21..=255 except the ephemeral WS-only range 21..=22, which is still
/// representable but rejected by [`validate_event`] for on-chain use).
///
/// The discriminant of `Reserved(n)` is `n` itself, exposed via
/// [`EventType::as_u8`]. Pattern-match on `Reserved(_)` to treat any
/// unknown / future type as opaque.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum EventType {
    // v0 core (frozen)
    #[default]
    ServerCreate,
    ServerUpdate,
    ChannelCreate,
    ChannelUpdate,
    MessagePost,
    MessageEdit,
    MessageDelete,
    DmMessagePost,
    ReactionAdd,
    ReactionRemove,
    MemberJoin,
    MemberLeave,
    RoleAssign,
    RoleRevoke,
    ModerationAction,
    // v1 core
    DeviceRegister,
    DeviceRevoke,
    PinMessage,
    UnpinMessage,
    BookmarkAdd,
    BookmarkRemove,
    /// Any event type not enumerated above. Includes the WS-only
    /// ephemeral range (21..=22) and all reserved / vendor ranges
    /// (23..=255). Always stored opaquely; never validated structurally.
    Reserved(u8),
}

impl EventType {
    /// Discriminant byte as it appears in the wire CBOR map key 1.
    pub const fn as_u8(self) -> u8 {
        match self {
            EventType::ServerCreate => 0,
            EventType::ServerUpdate => 1,
            EventType::ChannelCreate => 2,
            EventType::ChannelUpdate => 3,
            EventType::MessagePost => 4,
            EventType::MessageEdit => 5,
            EventType::MessageDelete => 6,
            EventType::DmMessagePost => 7,
            EventType::ReactionAdd => 8,
            EventType::ReactionRemove => 9,
            EventType::MemberJoin => 10,
            EventType::MemberLeave => 11,
            EventType::RoleAssign => 12,
            EventType::RoleRevoke => 13,
            EventType::ModerationAction => 14,
            EventType::DeviceRegister => 15,
            EventType::DeviceRevoke => 16,
            EventType::PinMessage => 17,
            EventType::UnpinMessage => 18,
            EventType::BookmarkAdd => 19,
            EventType::BookmarkRemove => 20,
            EventType::Reserved(n) => n,
        }
    }

    /// Always-succeeding decode. Unknown discriminants land in
    /// [`EventType::Reserved`]. Note: ephemeral WS-only types (21, 22)
    /// are representable here but [`validate_event`] rejects them
    /// because they MUST NOT appear in on-chain payloads.
    pub const fn from_u8(value: u8) -> Self {
        match value {
            0 => EventType::ServerCreate,
            1 => EventType::ServerUpdate,
            2 => EventType::ChannelCreate,
            3 => EventType::ChannelUpdate,
            4 => EventType::MessagePost,
            5 => EventType::MessageEdit,
            6 => EventType::MessageDelete,
            7 => EventType::DmMessagePost,
            8 => EventType::ReactionAdd,
            9 => EventType::ReactionRemove,
            10 => EventType::MemberJoin,
            11 => EventType::MemberLeave,
            12 => EventType::RoleAssign,
            13 => EventType::RoleRevoke,
            14 => EventType::ModerationAction,
            15 => EventType::DeviceRegister,
            16 => EventType::DeviceRevoke,
            17 => EventType::PinMessage,
            18 => EventType::UnpinMessage,
            19 => EventType::BookmarkAdd,
            20 => EventType::BookmarkRemove,
            n => EventType::Reserved(n),
        }
    }

    /// `true` for v0/v1 core event types this crate validates fully.
    /// `false` for [`EventType::Reserved`].
    pub const fn is_known(self) -> bool {
        !matches!(self, EventType::Reserved(_))
    }
}

impl TryFrom<u64> for EventType {
    type Error = ();

    /// Strict decode: rejects values that don't fit in a u8.
    /// Unknown discriminants still return `Ok(Reserved(_))`; callers
    /// must run [`validate_event`] (or check [`EventType::is_known`])
    /// to enforce structural rules.
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        u8::try_from(value).map(Self::from_u8).map_err(|_| ())
    }
}

/// Parsed KOMMS event after CBOR decode. v0 fields (keys 0..=11) sit
/// alongside v1 additive fields (keys 12..=20); higher keys are
/// preserved in [`ParsedKommsEvent::extension_fields`] for forward
/// compatibility.
///
/// `Default` is implemented so callers can construct an event with
/// struct update syntax:
///
/// ```ignore
/// ParsedKommsEvent {
///     v: 1,
///     t: EventType::MessagePost,
///     sid: Some(sid),
///     cid: Some(cid),
///     ..Default::default()
/// }
/// ```
///
/// `Eq` is intentionally NOT derived: `extension_fields` carries
/// `ciborium::Value` which can contain floats and therefore does not
/// implement `Eq`. `PartialEq` is sufficient for tests and indexing.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct ParsedKommsEvent {
    // --- envelope ---
    pub v: u64,
    pub t: EventType,

    // --- v0 core (keys 2..=11) ---
    pub sid: Option<[u8; 32]>,
    pub cid: Option<[u8; 32]>,
    pub did: Option<[u8; 32]>,
    /// Participant ID. v0-binary semantics: `sha256("KOMMS_PARTICIPANT_V0" || address_bytes)`.
    pub pid: Option<[u8; 32]>,
    pub mid: Option<[u8; 32]>,
    pub ref_bytes: Option<Vec<u8>>,
    pub enc: bool,
    pub ts: Option<u64>,
    pub n: Option<u64>,
    pub sig: Option<[u8; 64]>,

    // --- v1 core (keys 12..=20) ---
    /// Parent message id for threading (v1 key 12).
    pub parent_mid: Option<[u8; 32]>,
    /// Encryption scheme: 0=plain, 1=wallet-x25519, 2=MLS-reserved,
    /// 3=stealth-reserved. v1 key 13. Implicit (`Some(enc as u64)`) for v0
    /// inputs so downstream consumers can rely on this being populated.
    pub enc_scheme: Option<u64>,
    /// Content kind hint: 0=text, 1=image, 2=video, 3=audio, 4=file,
    /// 5=poll, 6=embed. v1 key 14.
    pub kind: Option<u64>,
    /// Optional MIME hint for non-text content. v1 key 15.
    pub mime: Option<String>,
    /// Reference scheme: 0x01=Hippius/IPFS CID UTF-8, 0x02=raw SHA-256.
    /// v1 key 16. v0 events carry this byte inline as the first byte of
    /// `ref_bytes`; the parser surfaces it in both places for symmetry.
    pub ref_type: Option<u64>,
    /// Per-device public key for multi-device key transport. v1 key 17.
    pub device_pk: Option<[u8; 32]>,
    /// Signature scheme: 0=BIP-340 Schnorr/secp256k1. v1 key 18.
    pub sig_scheme: Option<u64>,
    /// Reaction emoji / id (UTF-8 bytes, max 32). v1 key 19.
    /// Replaces the v0 convention of stuffing the reaction into `ref`.
    pub reaction_key: Option<Vec<u8>>,
    /// Receipt / payment hint for paid features. v1 key 20.
    pub payment_hint: Option<Vec<u8>>,

    // --- extension / vendor / future (keys 24..=255) ---
    /// Verbatim CBOR values for every map key the parser does not
    /// recognise. Indexers MUST persist these unchanged so a future
    /// build can re-parse them.
    pub extension_fields: BTreeMap<u8, Value>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("invalid CBOR: {0}")]
    Cbor(String),
    #[error("top-level CBOR value must be a map")]
    NotAMap,
    #[error("map key must be an unsigned integer in 0..=255")]
    InvalidKey,
    #[error("duplicate map key {0}")]
    DuplicateKey(u8),
    #[error("field {0}: expected uint")]
    ExpectedUint(&'static str),
    #[error("field t: event type {0} doesn't fit in u8")]
    EventTypeOverflow(u64),
    #[error("field {0}: expected bool")]
    ExpectedBool(&'static str),
    #[error("field {0}: expected byte string of length 32")]
    ExpectedBytes32(&'static str),
    #[error("field {0}: expected byte string")]
    ExpectedBytes(&'static str),
    #[error("field {0}: expected text string")]
    ExpectedText(&'static str),
    #[error("field sig: expected 64 bytes")]
    InvalidSigLength,
    #[error("missing required field {0}")]
    MissingField(&'static str),
    /// Key in v1 core range (0..=23) is reserved and not yet defined.
    #[error("map key {0} is reserved (not yet allocated in v1 core)")]
    ReservedCoreKey(u8),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("schema version v must be 0 or 1 (got {0})")]
    BadVersion(u64),
    #[error("invalid content reference (ref) encoding")]
    InvalidRef,
    #[error("event type {0:?} forbids field {1}")]
    ForbiddenField(EventType, &'static str),
    #[error("event type {0:?} requires field {1}")]
    MissingForType(EventType, &'static str),
    #[error("encryption flag invalid for this event type")]
    InvalidEnc,
    #[error("enc_scheme {scheme} disagrees with enc={enc}")]
    EncSchemeMismatch { scheme: u64, enc: bool },
    #[error("v1 event missing required field {0}")]
    V1MissingField(&'static str),
    #[error("reaction_key (key 19) must be 1..=32 bytes")]
    InvalidReactionKey,
    #[error("mime (key 15) must be 1..=64 ASCII bytes")]
    InvalidMime,
    #[error("event type {0:?} is ephemeral (WS-only) and MUST NOT appear on chain")]
    EphemeralOnChain(EventType),
    #[error("event type {0:?} is reserved/opaque; indexers persist but do not validate")]
    OpaqueEventType(EventType),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KommsPayloadError {
    #[error("payload too short for KOMMS prefix")]
    MissingPrefix,
    #[error("non-canonical CBOR: {0}")]
    Canonical(#[from] CanonicalError),
    #[error(transparent)]
    Parse(#[from] ParseError),
    #[error(transparent)]
    Validation(#[from] ValidationError),
    /// Protocol version `v` is higher than this crate understands.
    /// Callers should persist the raw bytes and re-parse after upgrade.
    #[error("unsupported protocol version {0} (max known is 1)")]
    UnsupportedVersion(u64),
}

/// Two-layer parser output for callers that need to safely persist
/// future-version events without dropping them.
#[derive(Debug)]
pub enum ParsedPayload {
    /// Fully parsed v0 or v1 event.
    Known(ParsedKommsEvent),
    /// `v > MAX_KNOWN_VERSION`. Raw CBOR bytes (post-prefix-strip) are
    /// included so the caller can re-parse after upgrading.
    Future { v: u64, raw_cbor: Vec<u8> },
}

/// Strips the 4-byte KOMMS prefix and returns the CBOR slice.
pub fn strip_komms_envelope(raw: &[u8]) -> Option<&[u8]> {
    raw.strip_prefix(&KOMMS_PAYLOAD_PREFIX)
}

/// Decode CBOR map into [`ParsedKommsEvent`] (does not enforce
/// canonicality or v1 §10 validation; use [`parse_komms_payload`] for
/// on-chain entry points).
pub fn parse_cbor_map(cbor: &[u8]) -> Result<ParsedKommsEvent, ParseError> {
    let value: Value =
        ciborium::de::from_reader(cbor).map_err(|e| ParseError::Cbor(e.to_string()))?;
    let Value::Map(entries) = value else {
        return Err(ParseError::NotAMap);
    };

    let mut fields: BTreeMap<u8, Value> = BTreeMap::new();
    for (k, v) in entries {
        let key_int = key_to_u8(&k)?;
        if fields.insert(key_int, v).is_some() {
            return Err(ParseError::DuplicateKey(key_int));
        }
    }

    let v = pop_uint(&mut fields, 0, "v")?;
    let t_raw = pop_uint(&mut fields, 1, "t")?;
    let t_u8 = u8::try_from(t_raw).map_err(|_| ParseError::EventTypeOverflow(t_raw))?;
    let t = EventType::from_u8(t_u8);

    let enc_val = fields.remove(&8).ok_or(ParseError::MissingField("enc"))?;
    let enc = enc_val.as_bool().ok_or(ParseError::ExpectedBool("enc"))?;

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

    // ----- v1 core (keys 12..=20) -----
    let parent_mid = pop_bytes32(&mut fields, 12, "parent_mid")?;
    let mut enc_scheme = pop_uint_opt(&mut fields, 13, "enc_scheme")?;
    let kind = pop_uint_opt(&mut fields, 14, "kind")?;
    let mime = pop_text_opt(&mut fields, 15, "mime")?;
    let ref_type = pop_uint_opt(&mut fields, 16, "ref_type")?;
    let device_pk = pop_bytes32(&mut fields, 17, "device_pk")?;
    let sig_scheme = pop_uint_opt(&mut fields, 18, "sig_scheme")?;
    let reaction_key = pop_bytes(&mut fields, 19, "reaction_key")?;
    let payment_hint = pop_bytes(&mut fields, 20, "payment_hint")?;

    // v0 inputs don't have key 13. Synthesise it from `enc` so downstream
    // consumers can rely on the field being populated.
    if v == 0 && enc_scheme.is_none() {
        enc_scheme = Some(if enc { 1 } else { 0 });
    }

    // v1-core reserved keys (21..=23). Reject loudly — they are not yet
    // allocated and accepting them would let future allocations break
    // hash parity once the meaning is decided.
    for &reserved in &[21u8, 22, 23] {
        if fields.contains_key(&reserved) {
            return Err(ParseError::ReservedCoreKey(reserved));
        }
    }

    // Extension / vendor keys (24..=255) — preserve verbatim.
    let mut extension_fields = BTreeMap::new();
    let extension_keys: Vec<u8> = fields
        .range(EXTENSION_KEY_MIN..=u8::MAX)
        .map(|(k, _)| *k)
        .collect();
    for key in extension_keys {
        if let Some(val) = fields.remove(&key) {
            extension_fields.insert(key, val);
        }
    }

    if !fields.is_empty() {
        // At this point only keys in the v1 core range (0..=23) could
        // remain, and we've consumed every defined one. Anything left is
        // a not-yet-allocated v1 core key.
        let remaining = *fields.keys().next().unwrap();
        return Err(ParseError::ReservedCoreKey(remaining));
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
        parent_mid,
        enc_scheme,
        kind,
        mime,
        ref_type,
        device_pk,
        sig_scheme,
        reaction_key,
        payment_hint,
        extension_fields,
    })
}

fn key_to_u8(k: &Value) -> Result<u8, ParseError> {
    let i = k.as_integer().ok_or(ParseError::InvalidKey)?;
    u8::try_from(i).map_err(|_| ParseError::InvalidKey)
}

fn pop_uint(
    fields: &mut BTreeMap<u8, Value>,
    key: u8,
    name: &'static str,
) -> Result<u64, ParseError> {
    let val = fields.remove(&key).ok_or(ParseError::MissingField(name))?;
    let i = val.as_integer().ok_or(ParseError::ExpectedUint(name))?;
    u64::try_from(i).map_err(|_| ParseError::ExpectedUint(name))
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

fn pop_text_opt(
    fields: &mut BTreeMap<u8, Value>,
    key: u8,
    name: &'static str,
) -> Result<Option<String>, ParseError> {
    let Some(val) = fields.remove(&key) else {
        return Ok(None);
    };
    val.into_text()
        .map(Some)
        .map_err(|_| ParseError::ExpectedText(name))
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
    u64::try_from(i)
        .map(Some)
        .map_err(|_| ParseError::ExpectedUint(name))
}

/// Validate `ref` layout (v0 A5 / v1 §6.2) when present.
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

/// Per-version structural validation (v0 A7/A8 + v1 §10).
///
/// Returns `Ok(())` for valid v0 / v1 known event types. Reserved /
/// vendor event types short-circuit with [`ValidationError::OpaqueEventType`]
/// so callers can persist-and-skip without misinterpreting the payload.
pub fn validate_event(ev: &ParsedKommsEvent) -> Result<(), ValidationError> {
    if ev.v > MAX_KNOWN_VERSION {
        return Err(ValidationError::BadVersion(ev.v));
    }

    // Reject WS-only ephemeral types on-chain. `validate_event` is
    // called from `parse_komms_payload` which only runs over on-chain
    // bytes, so this is the right place.
    if matches!(ev.t.as_u8(), 21 | 22) {
        return Err(ValidationError::EphemeralOnChain(ev.t));
    }

    // ref_type / ref_bytes inline tag must agree when both are present.
    if let Some(ref r) = ev.ref_bytes {
        validate_ref(r)?;
        if let Some(rt) = ev.ref_type {
            if rt > 0xFF || rt as u8 != r[0] {
                return Err(ValidationError::InvalidRef);
            }
        }
    }

    // mime: ASCII, length-bounded.
    if let Some(ref m) = ev.mime {
        if m.is_empty() || m.len() > 64 || !m.is_ascii() {
            return Err(ValidationError::InvalidMime);
        }
    }

    // reaction_key: non-empty, length-bounded (v1 §5.2 / §10).
    if let Some(ref rk) = ev.reaction_key {
        if rk.is_empty() || rk.len() > 32 {
            return Err(ValidationError::InvalidReactionKey);
        }
    }

    // enc_scheme ↔ enc agreement for v1.
    if ev.v >= 1 {
        let scheme = ev
            .enc_scheme
            .ok_or(ValidationError::V1MissingField("enc_scheme"))?;
        let scheme_says_encrypted = scheme != 0;
        if scheme_says_encrypted != ev.enc {
            return Err(ValidationError::EncSchemeMismatch {
                scheme,
                enc: ev.enc,
            });
        }
        // v1 §10: ts and n required for replay protection.
        if ev.ts.is_none() {
            return Err(ValidationError::V1MissingField("ts"));
        }
        if ev.n.is_none() {
            return Err(ValidationError::V1MissingField("n"));
        }
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
            if ev.enc {
                return Err(ValidationError::InvalidEnc);
            }
        }
        ChannelCreate | ChannelUpdate => {
            require(ev.sid.is_some(), "sid")?;
            require(ev.cid.is_some(), "cid")?;
            forbid(ev.did.is_some(), "did")?;
            if ev.enc {
                return Err(ValidationError::InvalidEnc);
            }
        }
        MessagePost => {
            require(ev.sid.is_some(), "sid")?;
            require(ev.cid.is_some(), "cid")?;
            require(ev.ref_bytes.is_some(), "ref")?;
            forbid(ev.enc, "enc")?;
        }
        MessageEdit => {
            require(ev.sid.is_some(), "sid")?;
            require(ev.cid.is_some(), "cid")?;
            require(ev.mid.is_some(), "mid")?;
            require(ev.ref_bytes.is_some(), "ref")?;
            forbid(ev.enc, "enc")?;
        }
        MessageDelete => {
            require(ev.sid.is_some(), "sid")?;
            require(ev.cid.is_some(), "cid")?;
            require(ev.mid.is_some(), "mid")?;
            forbid(ev.enc, "enc")?;
        }
        DmMessagePost => {
            require(ev.did.is_some(), "did")?;
            require(ev.ref_bytes.is_some(), "ref")?;
            require(ev.enc, "enc")?;
            forbid(ev.sid.is_some(), "sid")?;
            forbid(ev.cid.is_some(), "cid")?;
        }
        ReactionAdd | ReactionRemove => {
            require(ev.sid.is_some(), "sid")?;
            require(ev.cid.is_some(), "cid")?;
            require(ev.mid.is_some(), "mid")?;
            // v0 stuffed the reaction emoji into `ref` (UTF-8 inline). v1
            // adds the dedicated `reaction_key` field. Accept either, but
            // require at least one so reaction counts are computable.
            if ev.reaction_key.is_none() && ev.ref_bytes.is_none() {
                return Err(ValidationError::MissingForType(ev.t, "reaction_key|ref"));
            }
            forbid(ev.enc, "enc")?;
        }
        MemberJoin | MemberLeave => {
            require(ev.sid.is_some(), "sid")?;
            require(ev.pid.is_some(), "pid")?;
            forbid(ev.cid.is_some(), "cid")?;
            forbid(ev.did.is_some(), "did")?;
            if ev.enc {
                return Err(ValidationError::InvalidEnc);
            }
        }
        RoleAssign | RoleRevoke => {
            require(ev.sid.is_some(), "sid")?;
            if ev.enc {
                return Err(ValidationError::InvalidEnc);
            }
        }
        ModerationAction => {
            require(ev.sid.is_some(), "sid")?;
            forbid(ev.enc, "enc")?;
        }
        // ---- v1 core ----
        DeviceRegister => {
            require(ev.device_pk.is_some(), "device_pk")?;
            require(ev.sig.is_some(), "sig")?;
            require(ev.sig_scheme.is_some(), "sig_scheme")?;
            forbid(ev.enc, "enc")?;
        }
        DeviceRevoke => {
            require(ev.device_pk.is_some(), "device_pk")?;
            require(ev.sig.is_some(), "sig")?;
            forbid(ev.enc, "enc")?;
        }
        PinMessage | UnpinMessage => {
            require(ev.sid.is_some(), "sid")?;
            require(ev.cid.is_some(), "cid")?;
            require(ev.mid.is_some(), "mid")?;
            forbid(ev.enc, "enc")?;
        }
        BookmarkAdd | BookmarkRemove => {
            require(ev.mid.is_some(), "mid")?;
            forbid(ev.enc, "enc")?;
        }
        // Reserved range — caller chooses to persist & skip.
        Reserved(_) => return Err(ValidationError::OpaqueEventType(ev.t)),
    }

    Ok(())
}

/// Wire-entry parser: strip prefix → enforce canonical CBOR →
/// [`parse_cbor_map`] → [`validate_event`]. v0 and v1 events resolve to
/// `Ok(ParsedKommsEvent)`. `v > MAX_KNOWN_VERSION` resolves to
/// [`KommsPayloadError::UnsupportedVersion`]. Reserved event types
/// resolve to [`KommsPayloadError::Validation(OpaqueEventType)`] so the
/// caller can persist-and-skip.
pub fn parse_komms_payload(raw: &[u8]) -> Result<ParsedKommsEvent, KommsPayloadError> {
    let cbor = strip_komms_envelope(raw).ok_or(KommsPayloadError::MissingPrefix)?;
    canonical::validate_canonical(cbor)?;
    let ev = parse_cbor_map(cbor)?;
    if ev.v > MAX_KNOWN_VERSION {
        return Err(KommsPayloadError::UnsupportedVersion(ev.v));
    }
    validate_event(&ev)?;
    Ok(ev)
}

/// Same as [`parse_komms_payload`] but returns a [`ParsedPayload`] enum
/// so the caller can persist future-version events as raw CBOR instead
/// of treating them as a hard error. Use this in the indexer ingest
/// path; use [`parse_komms_payload`] everywhere else.
pub fn parse_komms_payload_with_future(raw: &[u8]) -> Result<ParsedPayload, KommsPayloadError> {
    let cbor = strip_komms_envelope(raw).ok_or(KommsPayloadError::MissingPrefix)?;
    canonical::validate_canonical(cbor)?;
    let ev = parse_cbor_map(cbor)?;
    if ev.v > MAX_KNOWN_VERSION {
        return Ok(ParsedPayload::Future {
            v: ev.v,
            raw_cbor: cbor.to_vec(),
        });
    }
    validate_event(&ev)?;
    Ok(ParsedPayload::Known(ev))
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

    fn v0_envelope(cbor: Vec<u8>) -> Vec<u8> {
        let mut raw = KOMMS_PAYLOAD_PREFIX.to_vec();
        raw.extend_from_slice(&cbor);
        raw
    }

    #[test]
    fn v0_server_create_roundtrip() {
        let raw = v0_envelope(encode_map(vec![
            (Value::Integer(0.into()), Value::Integer(0.into())),
            (Value::Integer(1.into()), Value::Integer(0.into())),
            (Value::Integer(2.into()), Value::Bytes(sid().to_vec())),
            (Value::Integer(8.into()), Value::Bool(false)),
        ]));
        let ev = parse_komms_payload(&raw).unwrap();
        assert_eq!(ev.t, EventType::ServerCreate);
        assert_eq!(ev.sid, Some(sid()));
        // enc_scheme synthesized for v0.
        assert_eq!(ev.enc_scheme, Some(0));
    }

    #[test]
    fn v0_message_post_requires_ref() {
        let raw = v0_envelope(encode_map(vec![
            (Value::Integer(0.into()), Value::Integer(0.into())),
            (Value::Integer(1.into()), Value::Integer(4.into())),
            (Value::Integer(2.into()), Value::Bytes(sid().to_vec())),
            (Value::Integer(3.into()), Value::Bytes([3u8; 32].to_vec())),
            (Value::Integer(8.into()), Value::Bool(false)),
        ]));
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
        let raw = v0_envelope(encode_map(vec![
            (Value::Integer(0.into()), Value::Integer(0.into())),
            (Value::Integer(1.into()), Value::Integer(7.into())),
            (Value::Integer(2.into()), Value::Bytes(sid().to_vec())),
            (Value::Integer(4.into()), Value::Bytes([9u8; 32].to_vec())),
            (Value::Integer(7.into()), Value::Bytes(ref_cid())),
            (Value::Integer(8.into()), Value::Bool(true)),
        ]));
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

    #[test]
    fn out_of_order_keys_rejected_at_wire() {
        // ciborium happens to emit Map entries in insertion order, so
        // we control the wire here.
        let raw = v0_envelope(encode_map(vec![
            (Value::Integer(1.into()), Value::Integer(0.into())),
            (Value::Integer(0.into()), Value::Integer(0.into())),
            (Value::Integer(8.into()), Value::Bool(false)),
        ]));
        let err = parse_komms_payload(&raw).unwrap_err();
        assert!(matches!(
            err,
            KommsPayloadError::Canonical(CanonicalError::KeysOutOfOrder(_))
        ));
    }

    #[test]
    fn v1_minimal_message_post() {
        // Build the v1 event programmatically via the encoder so the
        // canonical-CBOR enforcement path is exercised end-to-end.
        let ev = ParsedKommsEvent {
            v: 1,
            t: EventType::MessagePost,
            sid: Some(sid()),
            cid: Some([3u8; 32]),
            ref_bytes: Some(ref_cid()),
            enc: false,
            enc_scheme: Some(0),
            ts: Some(123),
            n: Some(1),
            sig_scheme: Some(0),
            ..Default::default()
        };
        let raw = encode::encode_komms_payload(&ev).unwrap();
        let parsed = parse_komms_payload(&raw).unwrap();
        assert_eq!(parsed, ev);
    }

    #[test]
    fn v1_requires_enc_scheme() {
        let ev = ParsedKommsEvent {
            v: 1,
            t: EventType::MessagePost,
            sid: Some(sid()),
            cid: Some([3u8; 32]),
            ref_bytes: Some(ref_cid()),
            enc: false,
            ts: Some(123),
            n: Some(1),
            ..Default::default()
        };
        // encode_komms_payload calls validate_event before writing.
        let err = encode::encode_komms_payload(&ev).unwrap_err();
        assert!(matches!(err, ValidationError::V1MissingField("enc_scheme")));
    }

    #[test]
    fn v1_enc_scheme_must_agree_with_enc() {
        let ev = ParsedKommsEvent {
            v: 1,
            t: EventType::DmMessagePost,
            did: Some([5u8; 32]),
            ref_bytes: Some(ref_cid()),
            enc: false,
            enc_scheme: Some(1), // says encrypted, but enc=false
            ts: Some(123),
            n: Some(1),
            ..Default::default()
        };
        let err = encode::encode_komms_payload(&ev).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::EncSchemeMismatch { scheme: 1, enc: false }
        ));
    }

    #[test]
    fn ephemeral_event_types_rejected_on_chain() {
        // t = 21 (TypingIndicator) MUST be rejected by validate_event.
        let raw = v0_envelope(encode_map(vec![
            (Value::Integer(0.into()), Value::Integer(0.into())),
            (Value::Integer(1.into()), Value::Integer(21.into())),
            (Value::Integer(8.into()), Value::Bool(false)),
        ]));
        let err = parse_komms_payload(&raw).unwrap_err();
        assert!(matches!(
            err,
            KommsPayloadError::Validation(ValidationError::EphemeralOnChain(EventType::Reserved(
                21
            )))
        ));
    }

    #[test]
    fn extension_keys_preserved_opaquely() {
        // Encode a v1 MessagePost plus an extension field at key 100.
        let mut ev = ParsedKommsEvent {
            v: 1,
            t: EventType::MessagePost,
            sid: Some(sid()),
            cid: Some([3u8; 32]),
            ref_bytes: Some(ref_cid()),
            enc: false,
            enc_scheme: Some(0),
            ts: Some(7),
            n: Some(1),
            ..Default::default()
        };
        ev.extension_fields
            .insert(100, Value::Integer(42i64.into()));
        let raw = encode::encode_komms_payload(&ev).unwrap();
        let parsed = parse_komms_payload(&raw).unwrap();
        assert_eq!(
            parsed.extension_fields.get(&100),
            Some(&Value::Integer(42i64.into()))
        );
    }

    #[test]
    fn reserved_core_key_rejected() {
        // Manually craft a v0 event with key 21 set (now in the
        // ephemeral / reserved-core range). parse_cbor_map should reject
        // before we even reach validate_event.
        let raw = v0_envelope(encode_map(vec![
            (Value::Integer(0.into()), Value::Integer(0.into())),
            (Value::Integer(1.into()), Value::Integer(0.into())),
            (Value::Integer(2.into()), Value::Bytes(sid().to_vec())),
            (Value::Integer(8.into()), Value::Bool(false)),
            (Value::Integer(21.into()), Value::Integer(0.into())),
        ]));
        let err = parse_komms_payload(&raw).unwrap_err();
        assert!(matches!(
            err,
            KommsPayloadError::Parse(ParseError::ReservedCoreKey(21))
        ));
    }

    #[test]
    fn future_version_returns_future_variant() {
        // v=2 envelope built via raw encoder bypassing validate_event.
        let cbor = encode_map(vec![
            (Value::Integer(0.into()), Value::Integer(2.into())),
            (Value::Integer(1.into()), Value::Integer(0.into())),
            (Value::Integer(2.into()), Value::Bytes(sid().to_vec())),
            (Value::Integer(8.into()), Value::Bool(false)),
        ]);
        let raw = v0_envelope(cbor.clone());
        match parse_komms_payload_with_future(&raw).unwrap() {
            ParsedPayload::Future { v, raw_cbor } => {
                assert_eq!(v, 2);
                assert_eq!(raw_cbor, cbor);
            }
            ParsedPayload::Known(_) => panic!("expected Future"),
        }
        // The strict variant errors out:
        let err = parse_komms_payload(&raw).unwrap_err();
        assert!(matches!(err, KommsPayloadError::UnsupportedVersion(2)));
    }
}
