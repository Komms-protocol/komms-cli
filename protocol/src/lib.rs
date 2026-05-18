//! KOMMS transaction-payload codec.
//!
//! This crate is the single source of truth for the KOMMS on-chain
//! payload format. It implements the historical v0 wire format, the v1
//! spec (`planning-docs/komms_protocol_v_1.md`), and the v1.1 additive
//! layer (`planning-docs/komms_protocol_v_1_1.md`). v1.1 indexers accept
//! v0 and v1.0 events verbatim and treat reserved / vendor event types
//! as opaque so the protocol can grow additively.
//!
//! ## Public API surface
//!
//! - [`parse_komms_payload`] — primary wire-entry parser. Enforces the
//!   `KOMM` prefix, canonical CBOR (`canonical::validate_canonical`), and
//!   v0/v1/v1.1 validation rules. Use this on every byte stream that
//!   arrives from chain.
//! - [`parse_cbor_map`] — low-level CBOR-only parser. Does NOT enforce
//!   canonicality and is intended for unit tests and round-trip helpers.
//! - [`validate_event`] — pure validation (A7/A8 of v0, §10 of v1, §12
//!   of v1.1).
//! - [`validate_ref`] — `ref_bytes` field layout check.
//! - [`encode::*`] — canonical CBOR encoder + identifier helpers.
//!
//! ## v1.1 additions (Toccata-era)
//!
//! v1.1 is a strict superset of v1.0 sharing the same `v = 1` envelope.
//! New CBOR keys 21–30 carry sealed-membership and encrypted-identifier
//! fields per `planning-docs/komms_protocol_v_1_1.md` §1.1; new event
//! types 23–26 (sealed member join/leave, key rotate, sealed event)
//! mirror the v1.0 public-server analogs but never reveal `sid`, `cid`,
//! or `pid` on chain. See [`EventType`] and [`ParsedKommsEvent`] field
//! comments for per-key semantics.

pub mod canonical;
pub mod encode;
pub mod verify;

use ciborium::Value;
use std::collections::BTreeMap;
use thiserror::Error;

pub use canonical::CanonicalError;
pub use encode::{
    RefBuildError, channel_id, dm_thread_id, encode_cbor_map, encode_komms_payload, message_id,
    participant_id, ref_from_cid_str, ref_from_content_hash, server_id, signing_payload_cbor,
};
pub use verify::{SignerPubkey, VerifyError, signer_pubkey_from_event, verify_event};

/// 4-byte ASCII envelope prefix: `KOMM` (ASCII `K`, `O`, `M`, `M`).
///
/// Wire format pre-Toccata used `KCOM` (`[0x4B, 0x43, 0x4F, 0x4D]`);
/// the prefix was renamed to `KOMM` in May 2026 as part of the
/// Toccata cut-over (no live mainnet existed at the time, and TN10's
/// Toccata hard-fork is a natural reset point — see
/// `komms-planning/ARCHITECTURE_DECISIONS.md` ADR-016 §"Wire-prefix
/// rename" + `MASTER_PLAN.md` Toccata-rename section).
pub const KOMMS_PAYLOAD_PREFIX: [u8; 4] = [0x4B, 0x4F, 0x4D, 0x4D];

/// Maximum protocol version this crate parses structurally. Higher `v`
/// values surface as [`KommsPayloadError::UnsupportedVersion`] so the
/// indexer can persist the raw bytes for a future deploy without
/// crashing.
pub const MAX_KNOWN_VERSION: u64 = 1;

/// Highest map key this crate parses at the v1 core level. Keys in
/// [`EXTENSION_KEY_MIN`]..=255 are preserved opaquely as
/// `extension_fields`. Bumped in v1.1 from 23 → 30 to cover the sealed
/// membership and encrypted-identifier allocations (`komms_protocol_v_1_1.md`
/// §1.1). Bumped in v1.2-pre to 32 for the role-management
/// fields (H6 of `komms-planning/AUDIT_2026-05-17.md`); pre-fix,
/// `ROLE_ASSIGN` and `ROLE_REVOKE` events were structurally
/// unusable because the canonical bytes carried no `target` or
/// `role` field — the validator accepted them but no consumer
/// could derive *who* gets *what* permission. Closes
/// `komms-protocol/04_PERMISSIONS.md §3.5`.
pub const V1_CORE_KEY_MAX: u8 = 32;
pub const EXTENSION_KEY_MIN: u8 = 33;

/// Canonical byte length for the `match_tag` (key 27) and `member_tag`
/// (key 21) fields. Per `komms_protocol_v_1_1.md` §12.6, both are
/// truncated HMAC outputs and MUST be exactly 16 bytes on the wire.
pub const V1_1_TAG_LEN: usize = 16;

/// Role enum values for `ROLE_ASSIGN` / `ROLE_REVOKE` (key 31 on
/// the wire). Mirrors `komms-protocol/04_PERMISSIONS.md §3.5`.
/// Validators MUST reject any value outside this set.
pub const ROLE_ADMIN: u8 = 0;
pub const ROLE_MODERATOR: u8 = 1;
pub const ROLE_MEMBER: u8 = 2;
pub const ROLE_VIEWER: u8 = 3;
pub const ROLE_BANNED: u8 = 4;

/// Highest allocated `role` enum value. Anything > this is
/// rejected at validate time.
pub const ROLE_MAX: u8 = ROLE_BANNED;

/// KOMMS event type. Known v0 (0..=14), v1.0 (15..=20), and v1.1
/// (23..=26) variants plus a catch-all [`EventType::Reserved`] for
/// forward-compatible event types. The ephemeral WS-only range
/// (21..=22) is still representable but rejected by [`validate_event`]
/// for on-chain use.
///
/// The discriminant of `Reserved(n)` is `n` itself, exposed via
/// [`EventType::as_u8`]. Pattern-match on `Reserved(_)` to treat any
/// unknown / future type as opaque; this catch-all already supplies
/// forward-compat for unknown event types, so the enum is intentionally
/// not `#[non_exhaustive]`.
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
    // v1.0 core
    DeviceRegister,
    DeviceRevoke,
    PinMessage,
    UnpinMessage,
    BookmarkAdd,
    BookmarkRemove,
    // v1.1 core (sealed membership + sealed event wrapper)
    /// `SEALED_MEMBER_JOIN` (t = 23). Sealed analog of [`MemberJoin`].
    /// Carries `member_tag` + `member_sealed` instead of `sid` + `pid`.
    /// Spec: `komms_protocol_v_1_1.md` §12.3.
    SealedMemberJoin,
    /// `SEALED_MEMBER_LEAVE` (t = 24). Sealed analog of [`MemberLeave`].
    /// Spec: `komms_protocol_v_1_1.md` §12.3.
    SealedMemberLeave,
    /// `KEY_ROTATE` (t = 25). Rotates the per-server master viewing
    /// key after a kick or membership change to obtain post-kick
    /// forward secrecy. Spec: `komms_protocol_v_1_1.md` §12.4.
    KeyRotate,
    /// `SEALED_EVENT` (t = 26). Generic envelope for any v1.0 event
    /// where the entire payload (including the inner event type) is
    /// encrypted under `enc_scheme = 4`. The inner type is recovered
    /// from `enc_t` (key 28) after group decryption.
    /// Spec: `komms_protocol_v_1_1.md` §12.2.
    SealedEvent,
    /// Any event type not enumerated above. Includes the WS-only
    /// ephemeral range (21..=22) and all reserved / vendor ranges
    /// (27..=255). Always stored opaquely; never validated structurally.
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
            EventType::SealedMemberJoin => 23,
            EventType::SealedMemberLeave => 24,
            EventType::KeyRotate => 25,
            EventType::SealedEvent => 26,
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
            23 => EventType::SealedMemberJoin,
            24 => EventType::SealedMemberLeave,
            25 => EventType::KeyRotate,
            26 => EventType::SealedEvent,
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
/// alongside v1.0 additive fields (keys 12..=20) and v1.1 additive
/// fields (keys 21..=30); higher keys are preserved in
/// [`ParsedKommsEvent::extension_fields`] for forward compatibility.
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
///
/// External consumers SHOULD construct via struct-update from
/// `Default::default()` so future v1.x field additions remain
/// non-breaking at the call site.
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

    // --- v1.0 core (keys 12..=20) ---
    /// Parent message id for threading (v1 key 12).
    pub parent_mid: Option<[u8; 32]>,
    /// Encryption scheme: 0=plain, 1=wallet-x25519, 2=DEPRECATED
    /// (former MLS reservation; rejected from v1.1 onward),
    /// 3=stealth-reserved (v1.2 Horizon C), 4=group envelope
    /// (v1.1, ADR-012). v1 key 13. Implicit (`Some(enc as u64)`) for
    /// v0 inputs so downstream consumers can rely on this being
    /// populated.
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
    /// Signature scheme for `sig` (key 11). v1 key 18.
    ///
    /// - `0` (default) = **Ed25519 over the canonical CBOR signing
    ///   payload** ([`crate::encode::signing_payload_cbor`]). This is
    ///   the canonical Komms-identity signature scheme per ADR-013 +
    ///   `komms-protocol/05_ENCRYPTION_POSTURE.md` §"Wire crypto
    ///   stack" + `komms-protocol/02_MESSAGING_CONTENT.md` §"Key 11".
    ///   The pre-Toccata draft erroneously labelled this slot
    ///   "BIP-340 Schnorr/secp256k1" — that was the Kasia-compat
    ///   migration path Komms abandoned in ADR-013 (Komms specifies
    ///   Ed25519 to stay compatible with the v1 MLS ciphersuite
    ///   `MLS_256_MLKEM768_X25519_AES256GCM_SHA256_Ed25519`). Closed
    ///   by B2 of `AUDIT_2026-05-17.md`.
    /// - `1` = bLSAG sealed sender (v1.1 reserved, Phase 3 only —
    ///   current builds reject; see [`ValidationError::SealedSenderNotImplemented`]).
    pub sig_scheme: Option<u64>,
    /// Reaction emoji / id (UTF-8 bytes, max 32). v1 key 19.
    /// Replaces the v0 convention of stuffing the reaction into `ref`.
    pub reaction_key: Option<Vec<u8>>,
    /// Receipt / payment hint for paid features. v1 key 20.
    pub payment_hint: Option<Vec<u8>>,

    // --- v1.1 core (keys 21..=30) ---
    /// Stealth-derived linkable tag for sealed membership events
    /// (`SEALED_MEMBER_JOIN`, `SEALED_MEMBER_LEAVE`). 16 bytes truncated
    /// HMAC. v1.1 key 21. Spec: `komms_protocol_v_1_1.md` §12.3.
    pub member_tag: Option<[u8; 16]>,
    /// AES-256-GCM ciphertext carrying the member's per-server stealth
    /// pubkey + identity claim. v1.1 key 22. Spec: §12.3 + ADR-012 §3.2.
    pub member_sealed: Option<Vec<u8>>,
    /// Encrypted counterpart to `sid` under `enc_scheme = 4`. v1.1
    /// key 23. Spec: §1.1 + §12.2.
    pub enc_sid: Option<Vec<u8>>,
    /// Encrypted counterpart to `cid`. v1.1 key 24.
    pub enc_cid: Option<Vec<u8>>,
    /// Encrypted counterpart to `ref_bytes` (message body / attachment
    /// pointer). v1.1 key 25.
    pub enc_body_ref: Option<Vec<u8>>,
    /// Encrypted counterpart to `parent_mid` (thread parent). v1.1 key 26.
    pub enc_parent_mid: Option<Vec<u8>>,
    /// HMAC-derived match tag the indexer uses to fan out an event into
    /// the correct (server, channel, key-epoch) bucket without learning
    /// the plaintext id. 16 bytes. v1.1 key 27. Spec: §12.6 + ADR-012 §3.1.
    pub match_tag: Option<[u8; 16]>,
    /// Encrypted counterpart to the inner event type when the wrapper
    /// is `SEALED_EVENT` (t = 26). Carries the true `t` byte plus any
    /// associated typed-field counterparts in a single AES-GCM payload.
    /// v1.1 key 28.
    pub enc_t: Option<Vec<u8>>,
    /// Key epoch the encrypted fields were sealed under. Monotonic
    /// per-server counter that increments on `KEY_ROTATE`. v1.1 key 29.
    pub key_epoch: Option<u64>,
    /// Sealed-sender signature payload (Phase 3, bLSAG). v1.1 key 30
    /// reserved; current builds reject any event carrying this field.
    /// Spec: ADR-013 + §12.5.
    pub sealed_signer: Option<Vec<u8>>,

    // --- v1.2-pre role-management (keys 31..=32) ---
    /// Role-management `role` enum. v1.2-pre key 31. Required on
    /// `ROLE_ASSIGN`; optional on `ROLE_REVOKE` (omitting means
    /// "revoke every role this target currently holds in this
    /// scope" per `komms-protocol/04_PERMISSIONS.md §3.5`).
    /// Validators MUST reject values > [`ROLE_MAX`]. H6 of
    /// `komms-planning/AUDIT_2026-05-17.md`.
    pub role: Option<u8>,
    /// Role-management target address. v1.2-pre key 32. Variable-
    /// length byte string carrying the canonical creator-address
    /// body (`version || payload`, e.g. 33 bytes for Schnorr
    /// addresses). Required on both `ROLE_ASSIGN` and
    /// `ROLE_REVOKE`. Validators MUST refuse a `target` shorter
    /// than 2 bytes (1-byte version + ≥ 1-byte payload). H6 of
    /// `komms-planning/AUDIT_2026-05-17.md`.
    pub target: Option<Vec<u8>>,

    // --- extension / vendor / future (keys 33..=255) ---
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
    #[error("field {0}: expected byte string of length 16")]
    ExpectedBytes16(&'static str),
    #[error("field {0}: expected byte string")]
    ExpectedBytes(&'static str),
    #[error("field {0}: expected text string")]
    ExpectedText(&'static str),
    #[error("field sig: expected 64 bytes")]
    InvalidSigLength,
    #[error("missing required field {0}")]
    MissingField(&'static str),
    /// Key in v1 core range (0..=30) is reserved and not yet defined.
    /// Retained for forward compatibility with future v1.x core
    /// allocations above 30.
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
    /// v1.1 §12: `enc_scheme = 2` (former MLS reservation) is deprecated
    /// and rejected by v1.1+ parsers per ADR-012.
    #[error("enc_scheme = 2 (MLS) was rejected in v1.1 per ADR-012")]
    DeprecatedEncSchemeMls,
    /// v1.1 §12.2: `enc_scheme = 4` events MUST carry `match_tag`,
    /// `key_epoch`, and at least one of the encrypted-counterpart
    /// fields (`enc_sid`, `enc_cid`, `enc_body_ref`, `enc_parent_mid`,
    /// `enc_t`).
    #[error("v1.1 enc_scheme=4 event missing required field {0}")]
    V1_1MissingField(&'static str),
    /// v1.1 §12.5: `sig_scheme = 1` (bLSAG sealed sender) is reserved
    /// for Phase 3 and rejected by current builds.
    #[error("sig_scheme = 1 (bLSAG) is reserved for Phase 3 (ADR-013); not yet implemented")]
    SealedSenderNotImplemented,
    /// v1.1 §12.6: `match_tag` and `member_tag` MUST be exactly 16
    /// bytes on the wire.
    #[error("v1.1 tag field {0} must be exactly 16 bytes")]
    InvalidTagLength(&'static str),
    /// v1.1 §12.7: rejects unrecognised `enc_scheme` values above the
    /// current allocation. v1.0 indexers SHOULD persist-and-skip
    /// instead; this surface is for v1.1+ structural validation.
    #[error("enc_scheme {0} is not defined in this protocol version")]
    UnknownEncScheme(u64),
    /// H6 of `komms-planning/AUDIT_2026-05-17.md`: the `role`
    /// byte on `ROLE_ASSIGN` / `ROLE_REVOKE` (key 31) must be
    /// one of the values in `04_PERMISSIONS.md §3.5`
    /// (0=Admin, 1=Moderator, 2=Member, 3=Viewer, 4=Banned).
    #[error("role enum value {0} is not defined (0..={max})", max = crate::ROLE_MAX)]
    UnknownRole(u8),
    /// H6 of `komms-planning/AUDIT_2026-05-17.md`: the `target`
    /// byte string on `ROLE_ASSIGN` / `ROLE_REVOKE` (key 32)
    /// must carry at least a 1-byte address version + ≥ 1-byte
    /// payload. Anything shorter is a malformed grant.
    #[error("target address bytes must be ≥ 2 bytes (got {0})")]
    InvalidTargetLength(usize),
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

/// Three-way parser output for callers that need to safely persist
/// future-version or reserved-event-type events without dropping them.
#[derive(Debug)]
pub enum ParsedPayload {
    /// Fully parsed v0 or v1 event. Passed [`validate_event`].
    Known(ParsedKommsEvent),
    /// Reserved or vendor event type (`event.t == EventType::Reserved(_)`).
    /// Envelope, version, and any v0/v1 core fields the wire happened to
    /// carry are parsed; structural validation is skipped because the
    /// type's semantics are unknown to this build. Persist the raw bytes
    /// so a future build can re-parse.
    Opaque {
        event: ParsedKommsEvent,
        raw_cbor: Vec<u8>,
    },
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

    // ----- v1.0 core (keys 12..=20) -----
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

    // ----- v1.1 core (keys 21..=30) -----
    let member_tag = pop_bytes16(&mut fields, 21, "member_tag")?;
    let member_sealed = pop_bytes(&mut fields, 22, "member_sealed")?;
    let enc_sid = pop_bytes(&mut fields, 23, "enc_sid")?;
    let enc_cid = pop_bytes(&mut fields, 24, "enc_cid")?;
    let enc_body_ref = pop_bytes(&mut fields, 25, "enc_body_ref")?;
    let enc_parent_mid = pop_bytes(&mut fields, 26, "enc_parent_mid")?;
    let match_tag = pop_bytes16(&mut fields, 27, "match_tag")?;
    let enc_t = pop_bytes(&mut fields, 28, "enc_t")?;
    let key_epoch = pop_uint_opt(&mut fields, 29, "key_epoch")?;
    let sealed_signer = pop_bytes(&mut fields, 30, "sealed_signer")?;

    // ----- v1.2-pre role-management (keys 31..=32) -----
    // H6 of `komms-planning/AUDIT_2026-05-17.md`. CBOR sees
    // `role` as a uint; we clamp to u8 here so downstream
    // validators work on the typed-byte form. Values outside
    // 0..=255 saturate at u8::MAX, which then surfaces as
    // `ValidationError::UnknownRole` at validate time —
    // chosen over a parse-time hard error so an out-of-range
    // role doesn't escalate to a parse failure that would
    // drop the whole event.
    let role = pop_uint_opt(&mut fields, 31, "role")?
        .map(|v| if v > u8::MAX as u64 { u8::MAX } else { v as u8 });
    let target = pop_bytes(&mut fields, 32, "target")?;

    // Extension / vendor keys (33..=255) — preserve verbatim.
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
        // At this point only keys in the v1 core range (0..=30) could
        // remain, and we've consumed every defined one. Anything left is
        // a not-yet-allocated v1.x core key.
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
        member_tag,
        member_sealed,
        enc_sid,
        enc_cid,
        enc_body_ref,
        enc_parent_mid,
        match_tag,
        enc_t,
        key_epoch,
        sealed_signer,
        role,
        target,
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

fn pop_bytes16(
    fields: &mut BTreeMap<u8, Value>,
    key: u8,
    name: &'static str,
) -> Result<Option<[u8; 16]>, ParseError> {
    let Some(val) = fields.remove(&key) else {
        return Ok(None);
    };
    let bytes = val
        .into_bytes()
        .map_err(|_| ParseError::ExpectedBytes16(name))?;
    if bytes.len() != V1_1_TAG_LEN {
        return Err(ParseError::ExpectedBytes16(name));
    }
    let mut out = [0u8; 16];
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

/// H6 of `komms-planning/AUDIT_2026-05-17.md`: reject any
/// `role` byte that is not one of the values defined in
/// `04_PERMISSIONS.md §3.5`. Acts on the parsed [`u8`] form
/// AFTER the CBOR layer has decoded the uint, so it doesn't
/// see the unclamped u64 — that's the parser's job.
fn validate_role_byte(role: Option<u8>) -> Result<(), ValidationError> {
    let Some(r) = role else { return Ok(()) };
    if r > ROLE_MAX {
        return Err(ValidationError::UnknownRole(r));
    }
    Ok(())
}

/// H6: a `target` byte string MUST be the canonical
/// creator-address body — `version || payload`. The protocol
/// does not pin the address version, so we accept any non-
/// trivial length (1-byte version + ≥ 1-byte payload). The
/// indexer is free to apply per-network shape checks on top
/// (e.g. "33 bytes on Mainnet Schnorr"), but the protocol
/// layer's job is only to refuse a definitionally-malformed
/// grant.
fn validate_target_bytes(target: Option<&[u8]>) -> Result<(), ValidationError> {
    let Some(bytes) = target else { return Ok(()) };
    if bytes.len() < 2 {
        return Err(ValidationError::InvalidTargetLength(bytes.len()));
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
        if let Some(rt) = ev.ref_type
            && (rt > 0xFF || rt as u8 != r[0])
        {
            return Err(ValidationError::InvalidRef);
        }
    }

    // mime: ASCII, length-bounded.
    if let Some(ref m) = ev.mime
        && (m.is_empty() || m.len() > 64 || !m.is_ascii())
    {
        return Err(ValidationError::InvalidMime);
    }

    // reaction_key: non-empty, length-bounded (v1 §5.2 / §10).
    if let Some(ref rk) = ev.reaction_key
        && (rk.is_empty() || rk.len() > 32)
    {
        return Err(ValidationError::InvalidReactionKey);
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
        // v1.1 §12.7: gate the enc_scheme allocation. 0 plain, 1
        // wallet-x25519 (DM lane), 3 stealth (v1.2 reserved, accepted
        // structurally), 4 group envelope (v1.1). 2 is the deprecated
        // MLS reservation per ADR-012 and is a hard reject.
        match scheme {
            0 | 1 | 3 | 4 => {}
            2 => return Err(ValidationError::DeprecatedEncSchemeMls),
            _ => return Err(ValidationError::UnknownEncScheme(scheme)),
        }
        // v1 §10: ts and n required for replay protection.
        if ev.ts.is_none() {
            return Err(ValidationError::V1MissingField("ts"));
        }
        if ev.n.is_none() {
            return Err(ValidationError::V1MissingField("n"));
        }
    }

    // v1.1 §12.5 + ADR-013: sealed sender is Phase 3. Any current
    // build that sees `sig_scheme = 1` or a populated `sealed_signer`
    // (key 30) MUST reject from projection — the spending witness
    // verification path is not implemented yet.
    if matches!(ev.sig_scheme, Some(1)) || ev.sealed_signer.is_some() {
        return Err(ValidationError::SealedSenderNotImplemented);
    }

    // v1.1 §12.6 (`member_tag`, `match_tag` = exactly 16 B) is enforced
    // at parse time by [`pop_bytes16`]. The typed `[u8; 16]` fields on
    // `ParsedKommsEvent` make the invariant a compile-time guarantee
    // for in-Rust construction, so no runtime re-check is needed here.

    // v1.1 §12.2: under enc_scheme = 4, every event MUST carry
    // match_tag + key_epoch and at least one encrypted-counterpart
    // field. Sealed membership events (t = 23/24/25) carry their
    // payload in `member_sealed` instead and are exempt from the
    // "at least one enc_* counterpart" rule here; their per-type
    // arms below enforce the equivalent requirement.
    let group_encrypted = ev.enc_scheme == Some(4);
    if group_encrypted {
        if ev.match_tag.is_none() {
            return Err(ValidationError::V1_1MissingField("match_tag"));
        }
        if ev.key_epoch.is_none() {
            return Err(ValidationError::V1_1MissingField("key_epoch"));
        }
        let has_enc_counterpart = ev.enc_sid.is_some()
            || ev.enc_cid.is_some()
            || ev.enc_body_ref.is_some()
            || ev.enc_parent_mid.is_some()
            || ev.enc_t.is_some();
        let is_sealed_member_event = matches!(
            ev.t,
            EventType::SealedMemberJoin | EventType::SealedMemberLeave | EventType::KeyRotate
        );
        if !has_enc_counterpart && !is_sealed_member_event {
            return Err(ValidationError::V1_1MissingField("enc_* counterpart"));
        }
    }

    use EventType::*;

    // "Effective presence" of v1.0 typed fields under v1.1 enc_scheme=4:
    // a typed event may carry sid OR enc_sid (etc.) but not neither.
    // For non-group-encrypted events these reduce to the v1.0 checks.
    let has_sid = ev.sid.is_some() || (group_encrypted && ev.enc_sid.is_some());
    let has_cid = ev.cid.is_some() || (group_encrypted && ev.enc_cid.is_some());
    let has_ref = ev.ref_bytes.is_some() || (group_encrypted && ev.enc_body_ref.is_some());

    // Plain-text `enc=true` bug (i.e. `enc=true` without enc_scheme=4
    // for events that don't otherwise allow encryption). v1.1 relaxes
    // typed-event encryption ONLY when enc_scheme=4.
    let plaintext_enc_misuse = ev.enc && !group_encrypted;

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
            require(has_sid, "sid|enc_sid")?;
            forbid(ev.cid.is_some() || ev.enc_cid.is_some(), "cid")?;
            forbid(ev.did.is_some(), "did")?;
            if plaintext_enc_misuse {
                return Err(ValidationError::InvalidEnc);
            }
        }
        ChannelCreate | ChannelUpdate => {
            require(has_sid, "sid|enc_sid")?;
            require(has_cid, "cid|enc_cid")?;
            forbid(ev.did.is_some(), "did")?;
            if plaintext_enc_misuse {
                return Err(ValidationError::InvalidEnc);
            }
        }
        MessagePost => {
            require(has_sid, "sid|enc_sid")?;
            require(has_cid, "cid|enc_cid")?;
            require(has_ref, "ref|enc_body_ref")?;
            forbid(plaintext_enc_misuse, "enc")?;
        }
        MessageEdit => {
            require(has_sid, "sid|enc_sid")?;
            require(has_cid, "cid|enc_cid")?;
            // mid is the txid of the parent MESSAGE_POST and is
            // therefore unavoidably public on chain (it IS the tx hash).
            // No enc_mid counterpart exists in v1.1.
            require(ev.mid.is_some(), "mid")?;
            require(has_ref, "ref|enc_body_ref")?;
            forbid(plaintext_enc_misuse, "enc")?;
        }
        MessageDelete => {
            require(has_sid, "sid|enc_sid")?;
            require(has_cid, "cid|enc_cid")?;
            require(ev.mid.is_some(), "mid")?;
            forbid(plaintext_enc_misuse, "enc")?;
        }
        DmMessagePost => {
            // DMs stay on enc_scheme=1 in v1.1; v1.2 Horizon-C will add
            // enc_scheme=3 stealth lane. No encrypted-counterpart
            // relaxation applies.
            require(ev.did.is_some(), "did")?;
            require(ev.ref_bytes.is_some(), "ref")?;
            require(ev.enc, "enc")?;
            forbid(ev.sid.is_some() || ev.enc_sid.is_some(), "sid")?;
            forbid(ev.cid.is_some() || ev.enc_cid.is_some(), "cid")?;
        }
        ReactionAdd | ReactionRemove => {
            require(has_sid, "sid|enc_sid")?;
            require(has_cid, "cid|enc_cid")?;
            require(ev.mid.is_some(), "mid")?;
            // v0 stuffed the reaction emoji into `ref` (UTF-8 inline). v1
            // adds the dedicated `reaction_key` field. Accept either, but
            // require at least one so reaction counts are computable.
            if ev.reaction_key.is_none() && ev.ref_bytes.is_none() {
                return Err(ValidationError::MissingForType(ev.t, "reaction_key|ref"));
            }
            forbid(plaintext_enc_misuse, "enc")?;
        }
        MemberJoin | MemberLeave => {
            // Public-server MEMBER_JOIN/LEAVE. v1.1 sealed analogs are
            // t = 23/24 — those are validated separately below.
            require(ev.sid.is_some(), "sid")?;
            require(ev.pid.is_some(), "pid")?;
            forbid(ev.cid.is_some(), "cid")?;
            forbid(ev.did.is_some(), "did")?;
            if plaintext_enc_misuse {
                return Err(ValidationError::InvalidEnc);
            }
        }
        RoleAssign => {
            // H6 of `komms-planning/AUDIT_2026-05-17.md` +
            // `komms-protocol/04_PERMISSIONS.md §3.5`:
            //   ROLE_ASSIGN MUST carry { sid, target, role },
            //   MAY carry cid (channel-scoped grant).
            require(has_sid, "sid|enc_sid")?;
            require(ev.target.is_some(), "target")?;
            require(ev.role.is_some(), "role")?;
            validate_role_byte(ev.role)?;
            validate_target_bytes(ev.target.as_deref())?;
            if plaintext_enc_misuse {
                return Err(ValidationError::InvalidEnc);
            }
        }
        RoleRevoke => {
            // ROLE_REVOKE MUST carry { sid, target }. `role` is
            // OPTIONAL: omitting means "revoke every role this
            // target currently holds in this scope" per
            // `04_PERMISSIONS.md §3.5`. When present it MUST be
            // a valid role enum value.
            require(has_sid, "sid|enc_sid")?;
            require(ev.target.is_some(), "target")?;
            if ev.role.is_some() {
                validate_role_byte(ev.role)?;
            }
            validate_target_bytes(ev.target.as_deref())?;
            if plaintext_enc_misuse {
                return Err(ValidationError::InvalidEnc);
            }
        }
        ModerationAction => {
            require(has_sid, "sid|enc_sid")?;
            forbid(plaintext_enc_misuse, "enc")?;
        }
        // ---- v1.0 core ----
        DeviceRegister => {
            require(ev.device_pk.is_some(), "device_pk")?;
            require(ev.sig.is_some(), "sig")?;
            require(ev.sig_scheme.is_some(), "sig_scheme")?;
            forbid(plaintext_enc_misuse, "enc")?;
        }
        DeviceRevoke => {
            require(ev.device_pk.is_some(), "device_pk")?;
            require(ev.sig.is_some(), "sig")?;
            forbid(plaintext_enc_misuse, "enc")?;
        }
        PinMessage | UnpinMessage => {
            require(has_sid, "sid|enc_sid")?;
            require(has_cid, "cid|enc_cid")?;
            require(ev.mid.is_some(), "mid")?;
            forbid(plaintext_enc_misuse, "enc")?;
        }
        BookmarkAdd | BookmarkRemove => {
            require(ev.mid.is_some(), "mid")?;
            forbid(plaintext_enc_misuse, "enc")?;
        }
        // ---- v1.1 core (sealed membership + sealed event wrapper) ----
        SealedMemberJoin => {
            // §12.3: member_tag (16B), member_sealed, match_tag (16B),
            // key_epoch all required. enc_scheme MUST be 4 (already
            // implied by match_tag/key_epoch presence + group_encrypted
            // checks above, but re-asserted for self-documenting rules).
            require(group_encrypted, "enc_scheme=4")?;
            require(ev.member_tag.is_some(), "member_tag")?;
            require(ev.member_sealed.is_some(), "member_sealed")?;
            require(ev.match_tag.is_some(), "match_tag")?;
            require(ev.key_epoch.is_some(), "key_epoch")?;
            // Sealed events never carry plaintext server / member /
            // channel identifiers: that would defeat the entire point.
            forbid(ev.sid.is_some(), "sid")?;
            forbid(ev.cid.is_some(), "cid")?;
            forbid(ev.did.is_some(), "did")?;
            forbid(ev.pid.is_some(), "pid")?;
        }
        SealedMemberLeave => {
            // §12.3: member_tag + sig required. The sig is the member's
            // self-signed leave assertion, verified at projection time
            // against the member's identity covenant pubkey.
            require(ev.member_tag.is_some(), "member_tag")?;
            require(ev.sig.is_some(), "sig")?;
            forbid(ev.sid.is_some(), "sid")?;
            forbid(ev.cid.is_some(), "cid")?;
            forbid(ev.did.is_some(), "did")?;
            forbid(ev.pid.is_some(), "pid")?;
        }
        KeyRotate => {
            // §12.4: member_sealed (wrapped new keys), match_tag,
            // key_epoch required. Tx-level admin signature verification
            // happens in the indexer covenant-projection layer.
            require(group_encrypted, "enc_scheme=4")?;
            require(ev.member_sealed.is_some(), "member_sealed")?;
            require(ev.match_tag.is_some(), "match_tag")?;
            require(ev.key_epoch.is_some(), "key_epoch")?;
            forbid(ev.sid.is_some(), "sid")?;
            forbid(ev.cid.is_some(), "cid")?;
        }
        SealedEvent => {
            // §12.2: t=26 is the fully-sealed wrapper. enc_t carries
            // the true event type plus its typed fields under AEAD.
            require(group_encrypted, "enc_scheme=4")?;
            require(ev.enc_t.is_some(), "enc_t")?;
            forbid(ev.sid.is_some(), "sid")?;
            forbid(ev.cid.is_some(), "cid")?;
            forbid(ev.did.is_some(), "did")?;
            forbid(ev.pid.is_some(), "pid")?;
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
/// so the caller can persist future-version and reserved-event-type
/// events as raw CBOR instead of treating them as hard errors. Use
/// this in the indexer ingest path; use [`parse_komms_payload`]
/// everywhere else.
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
    match validate_event(&ev) {
        Ok(()) => Ok(ParsedPayload::Known(ev)),
        Err(ValidationError::OpaqueEventType(_)) => Ok(ParsedPayload::Opaque {
            event: ev,
            raw_cbor: cbor.to_vec(),
        }),
        Err(other) => Err(other.into()),
    }
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
        // v1.1 §12.2 widened the per-type field-name reported by
        // `MissingForType` for MessagePost from "ref" to
        // "ref|enc_body_ref" so the error message reflects the
        // accept-either relaxation. v0 payloads (no enc_scheme=4)
        // surface the same error variant under the new name.
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
                "ref|enc_body_ref"
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
            ValidationError::EncSchemeMismatch {
                scheme: 1,
                enc: false
            }
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

    // The original `reserved_core_key_rejected` test guarded against
    // silent acceptance of v1.0-era reserved keys 21–23. v1.1 allocated
    // 21–30 (sealed-membership + encrypted counterparts), so that
    // defensive path is unreachable today. The `ReservedCoreKey` variant
    // is retained for forward compatibility (future v1.2 core key
    // allocations above 30), and the test was replaced by the v1.1
    // round-trip and validation suite below.

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
            other => panic!("expected Future, got {other:?}"),
        }
        // The strict variant errors out:
        let err = parse_komms_payload(&raw).unwrap_err();
        assert!(matches!(err, KommsPayloadError::UnsupportedVersion(2)));
    }

    #[test]
    fn opaque_event_type_returns_opaque_variant() {
        // t=64 (KMETA reserved range) — well-formed, semantically unknown.
        // Canonical CBOR uses 1-byte uint for keys <=23 and 2-byte uint
        // (`0x18 0x40`) for value 64.
        let cbor = encode_map(vec![
            (Value::Integer(0.into()), Value::Integer(0.into())),
            (Value::Integer(1.into()), Value::Integer(64.into())),
            (Value::Integer(8.into()), Value::Bool(false)),
        ]);
        let raw = v0_envelope(cbor.clone());
        match parse_komms_payload_with_future(&raw).unwrap() {
            ParsedPayload::Opaque { event, raw_cbor } => {
                assert_eq!(event.t, EventType::Reserved(64));
                assert_eq!(raw_cbor, cbor);
            }
            other => panic!("expected Opaque, got {other:?}"),
        }
        // The strict variant errors out:
        let err = parse_komms_payload(&raw).unwrap_err();
        assert!(matches!(
            err,
            KommsPayloadError::Validation(ValidationError::OpaqueEventType(_))
        ));
    }

    // ---------------------------------------------------------------
    // v1.1 (Toccata-era) wire-format additions.
    // Spec: planning-docs/komms_protocol_v_1_1.md §§1, 12.
    // ---------------------------------------------------------------

    fn match_tag() -> [u8; 16] {
        [0xAAu8; 16]
    }

    fn member_tag() -> [u8; 16] {
        [0xBBu8; 16]
    }

    /// Minimal v1.1 `SEALED_MEMBER_JOIN` round-trip through the canonical
    /// CBOR encoder + parser. Verifies every v1.1 key emitted is parsed
    /// back identically and that the per-type validator accepts the
    /// event.
    #[test]
    fn v1_1_sealed_member_join_roundtrip() {
        let ev = ParsedKommsEvent {
            v: 1,
            t: EventType::SealedMemberJoin,
            enc: true,
            enc_scheme: Some(4),
            ts: Some(1700000000),
            n: Some(1),
            member_tag: Some(member_tag()),
            member_sealed: Some(b"sealed-member-blob".to_vec()),
            match_tag: Some(match_tag()),
            key_epoch: Some(7),
            ..Default::default()
        };
        let raw = encode::encode_komms_payload(&ev).unwrap();
        let parsed = parse_komms_payload(&raw).unwrap();
        assert_eq!(parsed, ev);
    }

    #[test]
    fn v1_1_sealed_member_leave_roundtrip() {
        let ev = ParsedKommsEvent {
            v: 1,
            t: EventType::SealedMemberLeave,
            enc: false,
            enc_scheme: Some(0),
            ts: Some(1700000001),
            n: Some(2),
            sig: Some([0xCCu8; 64]),
            member_tag: Some(member_tag()),
            ..Default::default()
        };
        let raw = encode::encode_komms_payload(&ev).unwrap();
        let parsed = parse_komms_payload(&raw).unwrap();
        assert_eq!(parsed, ev);
    }

    #[test]
    fn v1_1_key_rotate_roundtrip() {
        let ev = ParsedKommsEvent {
            v: 1,
            t: EventType::KeyRotate,
            enc: true,
            enc_scheme: Some(4),
            ts: Some(1700000002),
            n: Some(3),
            member_sealed: Some(b"wrapped-new-key".to_vec()),
            match_tag: Some(match_tag()),
            key_epoch: Some(8),
            ..Default::default()
        };
        let raw = encode::encode_komms_payload(&ev).unwrap();
        let parsed = parse_komms_payload(&raw).unwrap();
        assert_eq!(parsed, ev);
    }

    #[test]
    fn v1_1_sealed_event_roundtrip() {
        let ev = ParsedKommsEvent {
            v: 1,
            t: EventType::SealedEvent,
            enc: true,
            enc_scheme: Some(4),
            ts: Some(1700000003),
            n: Some(4),
            enc_t: Some(b"aead-enc-inner-type-payload".to_vec()),
            match_tag: Some(match_tag()),
            key_epoch: Some(9),
            ..Default::default()
        };
        let raw = encode::encode_komms_payload(&ev).unwrap();
        let parsed = parse_komms_payload(&raw).unwrap();
        assert_eq!(parsed, ev);
    }

    /// v1.1 §12.2: a public-server typed event (e.g. MessagePost) MAY
    /// run under enc_scheme=4 by carrying enc_sid + enc_cid + enc_body_ref
    /// in place of the plaintext counterparts. Validates the per-type
    /// relaxation in `validate_event`.
    #[test]
    fn v1_1_enc_scheme_4_typed_message_post_roundtrip() {
        let ev = ParsedKommsEvent {
            v: 1,
            t: EventType::MessagePost,
            enc: true,
            enc_scheme: Some(4),
            ts: Some(1700000004),
            n: Some(5),
            enc_sid: Some(b"aead-sid-blob".to_vec()),
            enc_cid: Some(b"aead-cid-blob".to_vec()),
            enc_body_ref: Some(b"aead-body-ref-blob".to_vec()),
            match_tag: Some(match_tag()),
            key_epoch: Some(10),
            ..Default::default()
        };
        let raw = encode::encode_komms_payload(&ev).unwrap();
        let parsed = parse_komms_payload(&raw).unwrap();
        assert_eq!(parsed, ev);
    }

    /// v1.1 §12.2: enc_scheme=4 events without match_tag MUST be
    /// rejected. The encoder calls validate before emitting bytes.
    #[test]
    fn v1_1_enc_scheme_4_missing_match_tag_rejected() {
        let ev = ParsedKommsEvent {
            v: 1,
            t: EventType::MessagePost,
            enc: true,
            enc_scheme: Some(4),
            ts: Some(1700000005),
            n: Some(6),
            enc_sid: Some(b"x".to_vec()),
            enc_cid: Some(b"y".to_vec()),
            enc_body_ref: Some(b"z".to_vec()),
            key_epoch: Some(11),
            ..Default::default()
        };
        let err = encode::encode_komms_payload(&ev).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::V1_1MissingField("match_tag")
        ));
    }

    /// v1.1 §12.2: enc_scheme=4 events without ANY encrypted-counterpart
    /// field (and not a sealed-membership event type) MUST be rejected.
    #[test]
    fn v1_1_enc_scheme_4_missing_enc_counterpart_rejected() {
        let ev = ParsedKommsEvent {
            v: 1,
            t: EventType::MessagePost,
            enc: true,
            enc_scheme: Some(4),
            ts: Some(1700000006),
            n: Some(7),
            match_tag: Some(match_tag()),
            key_epoch: Some(12),
            ..Default::default()
        };
        let err = encode::encode_komms_payload(&ev).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::V1_1MissingField("enc_* counterpart")
        ));
    }

    /// v1.1 §12.5 + ADR-013: sig_scheme=1 is reserved for the Phase 3
    /// sealed-sender rollout. Phase 1/2 builds MUST reject.
    #[test]
    fn v1_1_sig_scheme_1_rejected_as_phase_3_reserved() {
        let ev = ParsedKommsEvent {
            v: 1,
            t: EventType::MessagePost,
            sid: Some([1u8; 32]),
            cid: Some([2u8; 32]),
            ref_bytes: Some({
                let mut v = vec![0x01u8];
                v.extend_from_slice(b"bagaaa");
                v
            }),
            enc: false,
            enc_scheme: Some(0),
            ts: Some(1700000007),
            n: Some(8),
            sig_scheme: Some(1),
            ..Default::default()
        };
        let err = encode::encode_komms_payload(&ev).unwrap_err();
        assert!(matches!(err, ValidationError::SealedSenderNotImplemented));
    }

    /// v1.1 §12.5 (mirror of above): sealed_signer (key 30) populated
    /// triggers the same Phase 3 reservation guard regardless of
    /// sig_scheme.
    #[test]
    fn v1_1_sealed_signer_field_rejected_as_phase_3_reserved() {
        let ev = ParsedKommsEvent {
            v: 1,
            t: EventType::SealedEvent,
            enc: true,
            enc_scheme: Some(4),
            ts: Some(1700000008),
            n: Some(9),
            enc_t: Some(b"x".to_vec()),
            match_tag: Some(match_tag()),
            key_epoch: Some(13),
            sealed_signer: Some(b"blsag-ring-sig".to_vec()),
            ..Default::default()
        };
        let err = encode::encode_komms_payload(&ev).unwrap_err();
        assert!(matches!(err, ValidationError::SealedSenderNotImplemented));
    }

    /// v1.1 §12.7 + ADR-012: enc_scheme=2 (former MLS reservation) is
    /// deprecated and MUST be rejected.
    #[test]
    fn v1_1_deprecated_mls_enc_scheme_rejected() {
        // Manually craft the wire because the encoder pre-validates.
        let raw = v0_envelope(encode_map(vec![
            (Value::Integer(0.into()), Value::Integer(1.into())),
            (Value::Integer(1.into()), Value::Integer(4.into())),
            (Value::Integer(2.into()), Value::Bytes(sid().to_vec())),
            (Value::Integer(3.into()), Value::Bytes([2u8; 32].to_vec())),
            (Value::Integer(7.into()), Value::Bytes(ref_cid())),
            (Value::Integer(8.into()), Value::Bool(true)),
            (
                Value::Integer(9.into()),
                Value::Integer(1700000009u64.into()),
            ),
            (Value::Integer(10.into()), Value::Integer(10u64.into())),
            (Value::Integer(13.into()), Value::Integer(2u64.into())),
        ]));
        let err = parse_komms_payload(&raw).unwrap_err();
        assert!(matches!(
            err,
            KommsPayloadError::Validation(ValidationError::DeprecatedEncSchemeMls)
        ));
    }

    /// v1.1 §12.7: unknown enc_scheme values (>= 5) MUST be rejected by
    /// the v1.1 validator. v1.0 indexers that don't know about
    /// enc_scheme=4 will follow a separate persist-and-skip path; that
    /// is not the surface tested here.
    #[test]
    fn v1_1_unknown_enc_scheme_rejected() {
        let raw = v0_envelope(encode_map(vec![
            (Value::Integer(0.into()), Value::Integer(1.into())),
            (Value::Integer(1.into()), Value::Integer(4.into())),
            (Value::Integer(2.into()), Value::Bytes(sid().to_vec())),
            (Value::Integer(3.into()), Value::Bytes([2u8; 32].to_vec())),
            (Value::Integer(7.into()), Value::Bytes(ref_cid())),
            (Value::Integer(8.into()), Value::Bool(true)),
            (
                Value::Integer(9.into()),
                Value::Integer(1700000010u64.into()),
            ),
            (Value::Integer(10.into()), Value::Integer(11u64.into())),
            (Value::Integer(13.into()), Value::Integer(42u64.into())),
        ]));
        let err = parse_komms_payload(&raw).unwrap_err();
        assert!(matches!(
            err,
            KommsPayloadError::Validation(ValidationError::UnknownEncScheme(42))
        ));
    }

    /// v1.1 §12.6: member_tag (key 21) wrong length is rejected at
    /// parse time before validation runs.
    #[test]
    fn v1_1_member_tag_wrong_length_rejected() {
        // 15 bytes (one short).
        let raw = v0_envelope(encode_map(vec![
            (Value::Integer(0.into()), Value::Integer(1.into())),
            (Value::Integer(1.into()), Value::Integer(23.into())),
            (Value::Integer(8.into()), Value::Bool(true)),
            (
                Value::Integer(9.into()),
                Value::Integer(1700000011u64.into()),
            ),
            (Value::Integer(10.into()), Value::Integer(12u64.into())),
            (Value::Integer(13.into()), Value::Integer(4u64.into())),
            (Value::Integer(21.into()), Value::Bytes(vec![0xBBu8; 15])),
        ]));
        let err = parse_komms_payload(&raw).unwrap_err();
        assert!(matches!(
            err,
            KommsPayloadError::Parse(ParseError::ExpectedBytes16("member_tag"))
        ));
    }

    /// v1.1 §12.3: SEALED_MEMBER_JOIN with enc_scheme != 4 is malformed.
    /// Caught by the per-type validator before bytes hit the wire.
    #[test]
    fn v1_1_sealed_member_join_without_group_enc_rejected() {
        let ev = ParsedKommsEvent {
            v: 1,
            t: EventType::SealedMemberJoin,
            enc: false,
            enc_scheme: Some(0),
            ts: Some(1700000012),
            n: Some(13),
            member_tag: Some(member_tag()),
            member_sealed: Some(b"x".to_vec()),
            match_tag: Some(match_tag()),
            key_epoch: Some(14),
            ..Default::default()
        };
        let err = encode::encode_komms_payload(&ev).unwrap_err();
        // group_encrypted check fires before per-type because match_tag
        // is set without enc_scheme=4 → no, actually match_tag is allowed
        // structurally; the per-type `require(group_encrypted, ...)`
        // catches it.
        assert!(matches!(
            err,
            ValidationError::MissingForType(EventType::SealedMemberJoin, "enc_scheme=4")
        ));
    }

    /// Regression: a v1.0 event (no v1.1 fields) parses on the v1.1
    /// crate exactly as before. This protects the strict-superset
    /// claim — `komms_protocol_v_1_1.md` §0.
    #[test]
    fn v1_1_parser_accepts_pure_v1_0_event_unchanged() {
        let ev = ParsedKommsEvent {
            v: 1,
            t: EventType::MessagePost,
            sid: Some([1u8; 32]),
            cid: Some([2u8; 32]),
            ref_bytes: Some(ref_cid()),
            enc: false,
            enc_scheme: Some(0),
            ts: Some(1700000013),
            n: Some(14),
            ..Default::default()
        };
        let raw = encode::encode_komms_payload(&ev).unwrap();
        let parsed = parse_komms_payload(&raw).unwrap();
        assert_eq!(parsed, ev);
        // Confirm no v1.1 fields leak in:
        assert!(parsed.member_tag.is_none());
        assert!(parsed.match_tag.is_none());
        assert!(parsed.key_epoch.is_none());
        assert!(parsed.enc_sid.is_none());
        assert!(parsed.enc_t.is_none());
    }

    // ----- v1.2-pre role-management (H6 of
    //       komms-planning/AUDIT_2026-05-17.md) -----

    fn h6_target_bytes() -> Vec<u8> {
        // 1-byte version (0 = PubKey) || 32-byte all-0x42
        // Schnorr payload. Same shape the indexer reduces
        // creator addresses to (`version || payload`).
        let mut v = Vec::with_capacity(33);
        v.push(0u8);
        v.extend_from_slice(&[0x42u8; 32]);
        v
    }

    /// H6 fixture: v1 ROLE_ASSIGN with `enc_scheme = 0`
    /// (plaintext). All H6 tests start from this baseline; the
    /// specific tests then mutate exactly one field.
    fn h6_baseline_role_assign() -> ParsedKommsEvent {
        ParsedKommsEvent {
            v: 1,
            t: EventType::RoleAssign,
            sid: Some([0xAA; 32]),
            enc: false,
            enc_scheme: Some(0),
            ts: Some(1_700_000_020),
            n: Some(21),
            role: Some(ROLE_MODERATOR),
            target: Some(h6_target_bytes()),
            ..Default::default()
        }
    }

    fn h6_baseline_role_revoke() -> ParsedKommsEvent {
        ParsedKommsEvent {
            v: 1,
            t: EventType::RoleRevoke,
            sid: Some([0xAA; 32]),
            enc: false,
            enc_scheme: Some(0),
            ts: Some(1_700_000_022),
            n: Some(23),
            role: None,
            target: Some(h6_target_bytes()),
            ..Default::default()
        }
    }

    #[test]
    fn h6_role_assign_round_trip_carries_target_and_role() {
        let ev = h6_baseline_role_assign();
        let raw = encode::encode_komms_payload(&ev).unwrap();
        let parsed = parse_komms_payload(&raw).unwrap();
        assert_eq!(parsed.role, Some(ROLE_MODERATOR));
        assert_eq!(parsed.target.as_deref(), Some(h6_target_bytes().as_slice()));
        assert_eq!(parsed.sid, Some([0xAA; 32]));
    }

    #[test]
    fn h6_role_assign_missing_target_rejected_at_validate() {
        let ev = ParsedKommsEvent {
            target: None,
            ..h6_baseline_role_assign()
        };
        let err = encode::encode_komms_payload(&ev).unwrap_err();
        assert_eq!(
            err,
            ValidationError::MissingForType(EventType::RoleAssign, "target")
        );
    }

    #[test]
    fn h6_role_assign_missing_role_rejected_at_validate() {
        let ev = ParsedKommsEvent {
            role: None,
            ..h6_baseline_role_assign()
        };
        let err = encode::encode_komms_payload(&ev).unwrap_err();
        assert_eq!(
            err,
            ValidationError::MissingForType(EventType::RoleAssign, "role")
        );
    }

    #[test]
    fn h6_role_assign_out_of_range_role_rejected() {
        let ev = ParsedKommsEvent {
            role: Some(99),
            ..h6_baseline_role_assign()
        };
        let err = encode::encode_komms_payload(&ev).unwrap_err();
        assert_eq!(err, ValidationError::UnknownRole(99));
    }

    #[test]
    fn h6_role_assign_short_target_rejected() {
        let ev = ParsedKommsEvent {
            // Single byte — only an address-version tag, no
            // payload at all. Must be rejected.
            target: Some(vec![0x00]),
            ..h6_baseline_role_assign()
        };
        let err = encode::encode_komms_payload(&ev).unwrap_err();
        assert_eq!(err, ValidationError::InvalidTargetLength(1));
    }

    #[test]
    fn h6_role_revoke_accepts_omitted_role() {
        // ROLE_REVOKE without a role enum means "revoke
        // everything this target currently holds in this
        // scope" per 04_PERMISSIONS.md §3.5.
        let ev = h6_baseline_role_revoke();
        let raw = encode::encode_komms_payload(&ev).unwrap();
        let parsed = parse_komms_payload(&raw).unwrap();
        assert_eq!(parsed.role, None);
        assert_eq!(parsed.target.as_deref(), Some(h6_target_bytes().as_slice()));
    }

    #[test]
    fn h6_role_revoke_requires_target() {
        let ev = ParsedKommsEvent {
            target: None,
            ..h6_baseline_role_revoke()
        };
        let err = encode::encode_komms_payload(&ev).unwrap_err();
        assert_eq!(
            err,
            ValidationError::MissingForType(EventType::RoleRevoke, "target")
        );
    }

    #[test]
    fn h6_role_assign_channel_scoped_round_trip() {
        // 04_PERMISSIONS.md §3.2 allows ROLE_ASSIGN to carry
        // an optional `cid` for channel-scoped grants. We
        // already require `sid`; `cid` MUST round-trip when
        // present.
        let ev = ParsedKommsEvent {
            cid: Some([0xCC; 32]),
            role: Some(ROLE_VIEWER),
            ts: Some(1_700_000_021),
            n: Some(22),
            ..h6_baseline_role_assign()
        };
        let raw = encode::encode_komms_payload(&ev).unwrap();
        let parsed = parse_komms_payload(&raw).unwrap();
        assert_eq!(parsed.cid, Some([0xCC; 32]));
        assert_eq!(parsed.role, Some(ROLE_VIEWER));
    }

    #[test]
    fn h6_key_31_and_32_no_longer_extension_fields() {
        // Before H6, keys 31+32 were preserved as opaque
        // extension_fields. After H6, they are core and must
        // populate the structured fields. This protects
        // against a regression that silently leaks role data
        // into the extension bucket where downstream code
        // would never see it.
        let ev = ParsedKommsEvent {
            role: Some(ROLE_ADMIN),
            ..h6_baseline_role_assign()
        };
        let raw = encode::encode_komms_payload(&ev).unwrap();
        let parsed = parse_komms_payload(&raw).unwrap();
        assert!(
            !parsed.extension_fields.contains_key(&31),
            "key 31 (role) MUST surface as parsed.role, not extension_fields"
        );
        assert!(
            !parsed.extension_fields.contains_key(&32),
            "key 32 (target) MUST surface as parsed.target, not extension_fields"
        );
    }
}
