//! Cross-language parity fixtures.
//!
//! Each test below builds a `ParsedKommsEvent`, encodes it via
//! `encode_komms_payload`, and prints the canonical wire bytes in hex.
//! These hex strings are baked into
//! `komms-client/src/lib/komms/payload/__tests__/parity.fixtures.ts`
//! and verified byte-for-byte by the Vitest suite.
//!
//! Run with `cargo test --release --test parity_fixtures -- --nocapture`
//! whenever you change the encoder or update the spec, then copy each
//! `FIXTURE name=... hex=...` line into the TypeScript fixture file.

use protocol::{EventType, ParsedKommsEvent, encode::encode_komms_payload};

fn dump(name: &str, ev: &ParsedKommsEvent) {
    let bytes = encode_komms_payload(ev).expect("encode");
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    println!("FIXTURE name={name} hex={hex}");
}

fn ref_hippius_cid() -> Vec<u8> {
    let mut v = vec![0x01u8];
    v.extend_from_slice(b"bagaaiera1234567");
    v
}

fn ref_content_hash() -> Vec<u8> {
    let mut v = vec![0x02u8];
    v.extend_from_slice(&[0xAB; 32]);
    v
}

#[test]
fn dump_v0_server_create() {
    let ev = ParsedKommsEvent {
        v: 0,
        t: EventType::ServerCreate,
        sid: Some([0x11; 32]),
        enc: false,
        ..Default::default()
    };
    dump("v0_server_create", &ev);
}

#[test]
fn dump_v0_message_post() {
    let ev = ParsedKommsEvent {
        v: 0,
        t: EventType::MessagePost,
        sid: Some([0x22; 32]),
        cid: Some([0x33; 32]),
        ref_bytes: Some(ref_hippius_cid()),
        enc: false,
        ..Default::default()
    };
    dump("v0_message_post", &ev);
}

#[test]
fn dump_v0_dm_message_post() {
    let ev = ParsedKommsEvent {
        v: 0,
        t: EventType::DmMessagePost,
        did: Some([0x44; 32]),
        ref_bytes: Some(ref_content_hash()),
        enc: true,
        ts: Some(0x0100_0000_0000_0000),
        n: Some(7),
        ..Default::default()
    };
    dump("v0_dm_message_post", &ev);
}

#[test]
fn dump_v0_member_join() {
    let ev = ParsedKommsEvent {
        v: 0,
        t: EventType::MemberJoin,
        sid: Some([0x55; 32]),
        pid: Some([0x66; 32]),
        enc: false,
        ..Default::default()
    };
    dump("v0_member_join", &ev);
}

#[test]
fn dump_v1_message_post() {
    let ev = ParsedKommsEvent {
        v: 1,
        t: EventType::MessagePost,
        sid: Some([0x77; 32]),
        cid: Some([0x88; 32]),
        ref_bytes: Some(ref_hippius_cid()),
        enc: false,
        ts: Some(1_700_000_000),
        n: Some(1),
        enc_scheme: Some(0),
        kind: Some(0),
        sig_scheme: Some(0),
        ..Default::default()
    };
    dump("v1_message_post", &ev);
}

#[test]
fn dump_v1_reaction_with_reaction_key() {
    let ev = ParsedKommsEvent {
        v: 1,
        t: EventType::ReactionAdd,
        sid: Some([0x99; 32]),
        cid: Some([0xAA; 32]),
        mid: Some([0xBB; 32]),
        reaction_key: Some(b"\xf0\x9f\x91\x8d".to_vec()), // 👍 thumbs-up
        enc: false,
        ts: Some(1_700_000_001),
        n: Some(2),
        enc_scheme: Some(0),
        ..Default::default()
    };
    dump("v1_reaction_add", &ev);
}

#[test]
fn dump_v1_pin_message() {
    let ev = ParsedKommsEvent {
        v: 1,
        t: EventType::PinMessage,
        sid: Some([0xCC; 32]),
        cid: Some([0xDD; 32]),
        mid: Some([0xEE; 32]),
        enc: false,
        ts: Some(1_700_000_002),
        n: Some(3),
        enc_scheme: Some(0),
        ..Default::default()
    };
    dump("v1_pin_message", &ev);
}

#[test]
fn dump_v1_dm_with_kind_mime() {
    let ev = ParsedKommsEvent {
        v: 1,
        t: EventType::DmMessagePost,
        did: Some([0xFF; 32]),
        ref_bytes: Some(ref_content_hash()),
        enc: true,
        ts: Some(1_700_000_003),
        n: Some(4),
        enc_scheme: Some(1),
        kind: Some(1), // image
        mime: Some("image/png".to_string()),
        ref_type: Some(0x02),
        ..Default::default()
    };
    dump("v1_dm_image", &ev);
}

// ============================================================================
// v1.1 fixtures (komms_protocol_v_1_1.md §12). B4 of AUDIT_2026-05-17.md
// closed the cross-language parity gap for the four new event kinds.
// ============================================================================

/// 16-byte stealth-derived linkable tag (key 21 / key 27).
const TAG_MEMBER: [u8; 16] = [0x71; 16];
const TAG_MATCH: [u8; 16] = [0x72; 16];

/// Stable sealed-payload bytes for the AEAD ciphertext fields. These
/// fixtures are deterministic — we are testing the wire encoder, not
/// the AEAD primitive — so a constant byte sequence is sufficient and
/// keeps the parity fixture file reproducible.
fn member_sealed_bytes() -> Vec<u8> {
    vec![0xC0; 64]
}

fn enc_sid_bytes() -> Vec<u8> {
    vec![0xC1; 48]
}

fn enc_t_bytes() -> Vec<u8> {
    vec![0xC2; 8]
}

#[test]
fn dump_v1_1_sealed_member_join() {
    // §12.3: sealed-membership events never carry plaintext identifiers
    // — the entire point is to hide the (server, member) pair from the
    // chain. `enc_sid` provides the encrypted counterpart for indexer
    // fan-out, but it's optional because `match_tag` already routes the
    // event to its server bucket.
    let ev = ParsedKommsEvent {
        v: 1,
        t: EventType::SealedMemberJoin,
        enc: true,
        ts: Some(1_700_000_010),
        n: Some(11),
        enc_scheme: Some(4),
        member_tag: Some(TAG_MEMBER),
        member_sealed: Some(member_sealed_bytes()),
        match_tag: Some(TAG_MATCH),
        key_epoch: Some(1),
        ..Default::default()
    };
    dump("v1_1_sealed_member_join", &ev);
}

#[test]
fn dump_v1_1_key_rotate() {
    let ev = ParsedKommsEvent {
        v: 1,
        t: EventType::KeyRotate,
        enc: true,
        ts: Some(1_700_000_011),
        n: Some(12),
        enc_scheme: Some(4),
        member_sealed: Some(member_sealed_bytes()),
        match_tag: Some(TAG_MATCH),
        key_epoch: Some(2),
        ..Default::default()
    };
    dump("v1_1_key_rotate", &ev);
}

#[test]
fn dump_v1_1_sealed_event() {
    let ev = ParsedKommsEvent {
        v: 1,
        t: EventType::SealedEvent,
        enc: true,
        ts: Some(1_700_000_012),
        n: Some(13),
        enc_scheme: Some(4),
        enc_sid: Some(enc_sid_bytes()),
        enc_t: Some(enc_t_bytes()),
        match_tag: Some(TAG_MATCH),
        key_epoch: Some(3),
        ..Default::default()
    };
    dump("v1_1_sealed_event", &ev);
}

// --- v1.2-pre role-management fixtures (H6 of
// `komms-planning/AUDIT_2026-05-17.md`) ---
//
// Pre-fix, ROLE_ASSIGN and ROLE_REVOKE events only carried `sid`
// — neither the target principal nor the role enum survived
// encode/decode. The fixtures below pin the canonical CBOR
// layout for the two new core keys (31 = role, 32 = target)
// so the TS mirror in `komms-client/src/lib/komms/payload/
// __tests__/parity.test.ts` can assert byte-equality.
fn target_address_bytes() -> Vec<u8> {
    // 1-byte address-version tag (PubKey = 0) || 32-byte
    // Schnorr payload of all 0x42. Matches the
    // `creator_address_bytes` shape the indexer stores.
    let mut v = Vec::with_capacity(33);
    v.push(0u8);
    v.extend_from_slice(&[0x42u8; 32]);
    v
}

#[test]
fn dump_v1_2_role_assign() {
    let ev = ParsedKommsEvent {
        v: 1,
        t: EventType::RoleAssign,
        sid: Some([0xAA; 32]),
        enc: false,
        enc_scheme: Some(0),
        ts: Some(1_700_000_020),
        n: Some(21),
        role: Some(::protocol::ROLE_MODERATOR),
        target: Some(target_address_bytes()),
        ..Default::default()
    };
    dump("v1_2_role_assign", &ev);
}

#[test]
fn dump_v1_2_role_assign_channel_scoped() {
    // Channel-scoped ROLE_ASSIGN — same shape as server-wide
    // but with `cid` populated (overrides server-wide for that
    // channel per `04_PERMISSIONS.md §3.2`).
    let ev = ParsedKommsEvent {
        v: 1,
        t: EventType::RoleAssign,
        sid: Some([0xAA; 32]),
        cid: Some([0xCC; 32]),
        enc: false,
        enc_scheme: Some(0),
        ts: Some(1_700_000_021),
        n: Some(22),
        role: Some(::protocol::ROLE_VIEWER),
        target: Some(target_address_bytes()),
        ..Default::default()
    };
    dump("v1_2_role_assign_channel_scoped", &ev);
}

#[test]
fn dump_v1_2_role_revoke_all() {
    // ROLE_REVOKE with `role` OMITTED — revokes every role the
    // target currently holds in the (sid)-scope per
    // `04_PERMISSIONS.md §3.5`.
    let ev = ParsedKommsEvent {
        v: 1,
        t: EventType::RoleRevoke,
        sid: Some([0xAA; 32]),
        enc: false,
        enc_scheme: Some(0),
        ts: Some(1_700_000_022),
        n: Some(23),
        role: None,
        target: Some(target_address_bytes()),
        ..Default::default()
    };
    dump("v1_2_role_revoke_all", &ev);
}

#[test]
fn dump_v1_2_role_revoke_specific() {
    // ROLE_REVOKE with a specific `role` — revokes just that
    // role for the target.
    let ev = ParsedKommsEvent {
        v: 1,
        t: EventType::RoleRevoke,
        sid: Some([0xAA; 32]),
        enc: false,
        enc_scheme: Some(0),
        ts: Some(1_700_000_023),
        n: Some(24),
        role: Some(::protocol::ROLE_BANNED),
        target: Some(target_address_bytes()),
        ..Default::default()
    };
    dump("v1_2_role_revoke_specific", &ev);
}
