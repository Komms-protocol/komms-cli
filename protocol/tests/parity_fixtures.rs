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
