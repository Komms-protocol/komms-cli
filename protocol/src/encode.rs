//! Canonical CBOR encoder and identifier helpers.
//!
//! ## Identifier model (v1 §9)
//!
//! v1 fixes a semantic mismatch in the v0 spec: `sid`, `cid`, and `mid`
//! are ALL **direct Kaspa transaction ids** — the 32-byte txid of the
//! transaction that created the entity. The v0 spec text described
//! SHA-256 derivations for these fields that the v0 binary never
//! implemented; v1 codifies the binary behaviour as the canonical rule.
//!
//! `pid` (Participant ID) and `did` (DM Thread ID) keep their v0
//! semantics because the v0 binary already implemented them correctly.

use crate::{
    KOMMS_PAYLOAD_PREFIX, ParsedKommsEvent, ValidationError, validate_event, validate_ref,
};
use ciborium::Value;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RefBuildError {
    #[error("CID string must be non-empty UTF-8")]
    EmptyCid,
}

/// `ref_type` 0x01: Hippius / UTF-8 CID.
pub fn ref_from_cid_str(cid: &str) -> Result<Vec<u8>, RefBuildError> {
    if cid.is_empty() {
        return Err(RefBuildError::EmptyCid);
    }
    let mut v = vec![0x01u8];
    v.extend_from_slice(cid.as_bytes());
    Ok(v)
}

/// `ref_type` 0x02: raw SHA-256 content hash (32 bytes after prefix).
pub fn ref_from_content_hash(hash: [u8; 32]) -> Vec<u8> {
    let mut v = vec![0x02u8];
    v.extend_from_slice(&hash);
    v
}

fn sha256_domain(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for p in parts {
        hasher.update(p);
    }
    hasher.finalize().into()
}

/// v1 §9.1 — Komms server id is the 32-byte txid of the
/// `ServerCreate` transaction.
#[inline]
pub fn server_id(creation_txid: &[u8; 32]) -> [u8; 32] {
    *creation_txid
}

/// v1 §9.2 — Channel id is the 32-byte txid of the `ChannelCreate`
/// transaction.
#[inline]
pub fn channel_id(creation_txid: &[u8; 32]) -> [u8; 32] {
    *creation_txid
}

/// v1 §9.3 — Message id is the 32-byte txid of the `MessagePost`
/// (or other message-creating) transaction.
#[inline]
pub fn message_id(creation_txid: &[u8; 32]) -> [u8; 32] {
    *creation_txid
}

/// v1 §9.4 — Participant ID for ACL identity:
/// `SHA-256("KOMMS_PARTICIPANT_V0" || creator_address_bytes)`. v0-compat.
pub fn participant_id(creator_address_bytes: &[u8]) -> [u8; 32] {
    sha256_domain(b"KOMMS_PARTICIPANT_V0", &[creator_address_bytes])
}

/// v1 §9.5 — DM thread id:
/// `SHA-256("KOMMS_DM_V0" || min(addrA,addrB) || max(addrA,addrB))`. v0-compat.
pub fn dm_thread_id(addr_a: &[u8], addr_b: &[u8]) -> [u8; 32] {
    let (min_a, max_a) = match addr_a.cmp(addr_b) {
        Ordering::Greater => (addr_b, addr_a),
        _ => (addr_a, addr_b),
    };
    sha256_domain(b"KOMMS_DM_V0", &[min_a, max_a])
}

/// Encode the event map as canonical CBOR. Does NOT include the `KOMM`
/// envelope prefix; use [`encode_komms_payload`] for the full wire
/// representation.
///
/// Runs [`validate_event`] before encoding so it is impossible to emit
/// a payload that this crate would later refuse to parse.
pub fn encode_cbor_map(ev: &ParsedKommsEvent) -> Result<Vec<u8>, ValidationError> {
    validate_event(ev)?;
    if let Some(ref r) = ev.ref_bytes {
        validate_ref(r)?;
    }

    // Build (key, value) pairs in strict ascending key order. ciborium's
    // `Value::Map` preserves insertion order on the wire, so this is
    // sufficient as long as we never push out of order.
    let mut pairs: Vec<(Value, Value)> = Vec::new();

    // v0 core
    pairs.push((bk(0), Value::Integer(ev.v.into())));
    pairs.push((bk(1), Value::Integer((ev.t.as_u8() as u64).into())));
    if let Some(sid) = ev.sid {
        pairs.push((bk(2), Value::Bytes(sid.to_vec())));
    }
    if let Some(cid) = ev.cid {
        pairs.push((bk(3), Value::Bytes(cid.to_vec())));
    }
    if let Some(did) = ev.did {
        pairs.push((bk(4), Value::Bytes(did.to_vec())));
    }
    if let Some(pid) = ev.pid {
        pairs.push((bk(5), Value::Bytes(pid.to_vec())));
    }
    if let Some(mid) = ev.mid {
        pairs.push((bk(6), Value::Bytes(mid.to_vec())));
    }
    if let Some(ref r) = ev.ref_bytes {
        pairs.push((bk(7), Value::Bytes(r.clone())));
    }
    pairs.push((bk(8), Value::Bool(ev.enc)));
    if let Some(ts) = ev.ts {
        pairs.push((bk(9), Value::Integer(ts.into())));
    }
    if let Some(n) = ev.n {
        pairs.push((bk(10), Value::Integer(n.into())));
    }
    if let Some(sig) = ev.sig {
        pairs.push((bk(11), Value::Bytes(sig.to_vec())));
    }

    // v1 core
    if let Some(parent_mid) = ev.parent_mid {
        pairs.push((bk(12), Value::Bytes(parent_mid.to_vec())));
    }
    if let Some(scheme) = ev.enc_scheme {
        pairs.push((bk(13), Value::Integer(scheme.into())));
    }
    if let Some(kind) = ev.kind {
        pairs.push((bk(14), Value::Integer(kind.into())));
    }
    if let Some(ref mime) = ev.mime {
        pairs.push((bk(15), Value::Text(mime.clone())));
    }
    if let Some(rt) = ev.ref_type {
        pairs.push((bk(16), Value::Integer(rt.into())));
    }
    if let Some(dpk) = ev.device_pk {
        pairs.push((bk(17), Value::Bytes(dpk.to_vec())));
    }
    if let Some(ss) = ev.sig_scheme {
        pairs.push((bk(18), Value::Integer(ss.into())));
    }
    if let Some(ref rk) = ev.reaction_key {
        pairs.push((bk(19), Value::Bytes(rk.clone())));
    }
    if let Some(ref ph) = ev.payment_hint {
        pairs.push((bk(20), Value::Bytes(ph.clone())));
    }

    // v1.1 core (keys 21..=30). Emitted in strict ascending key order so
    // the canonical-CBOR contract holds. Field semantics live on the
    // `ParsedKommsEvent` doc comments.
    if let Some(member_tag) = ev.member_tag {
        pairs.push((bk(21), Value::Bytes(member_tag.to_vec())));
    }
    if let Some(ref member_sealed) = ev.member_sealed {
        pairs.push((bk(22), Value::Bytes(member_sealed.clone())));
    }
    if let Some(ref enc_sid) = ev.enc_sid {
        pairs.push((bk(23), Value::Bytes(enc_sid.clone())));
    }
    if let Some(ref enc_cid) = ev.enc_cid {
        pairs.push((bk(24), Value::Bytes(enc_cid.clone())));
    }
    if let Some(ref enc_body_ref) = ev.enc_body_ref {
        pairs.push((bk(25), Value::Bytes(enc_body_ref.clone())));
    }
    if let Some(ref enc_parent_mid) = ev.enc_parent_mid {
        pairs.push((bk(26), Value::Bytes(enc_parent_mid.clone())));
    }
    if let Some(match_tag) = ev.match_tag {
        pairs.push((bk(27), Value::Bytes(match_tag.to_vec())));
    }
    if let Some(ref enc_t) = ev.enc_t {
        pairs.push((bk(28), Value::Bytes(enc_t.clone())));
    }
    if let Some(key_epoch) = ev.key_epoch {
        pairs.push((bk(29), Value::Integer(key_epoch.into())));
    }
    if let Some(ref sealed_signer) = ev.sealed_signer {
        pairs.push((bk(30), Value::Bytes(sealed_signer.clone())));
    }

    // v1.2-pre role-management (keys 31..=32). H6 of
    // `komms-planning/AUDIT_2026-05-17.md`. Emit in strict
    // ascending key order so the canonical-bytes invariant
    // (KOMMS_PRINCIPLES §6) holds across cross-language
    // mirrors.
    if let Some(role) = ev.role {
        pairs.push((bk(31), Value::Integer((role as u64).into())));
    }
    if let Some(ref target) = ev.target {
        pairs.push((bk(32), Value::Bytes(target.clone())));
    }

    // Extension / vendor (keys 33..=255). BTreeMap iteration is already
    // in ascending key order so we can append directly.
    for (key, val) in ev.extension_fields.iter() {
        pairs.push((bk(*key), val.clone()));
    }

    let v = Value::Map(pairs);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&v, &mut buf).expect("CBOR map encode to Vec");
    Ok(buf)
}

#[inline]
fn bk(key: u8) -> Value {
    Value::Integer((key as u64).into())
}

/// v1 §11.2: the canonical CBOR bytes covered by `sig` (the full map
/// minus key 11). Equal-to-byte against [`encode_cbor_map`] of a
/// `sig = None` clone.
pub fn signing_payload_cbor(ev: &ParsedKommsEvent) -> Result<Vec<u8>, ValidationError> {
    let mut ev = ev.clone();
    ev.sig = None;
    encode_cbor_map(&ev)
}

/// `KOMM` prefix + canonical CBOR for a full transaction payload.
pub fn encode_komms_payload(ev: &ParsedKommsEvent) -> Result<Vec<u8>, ValidationError> {
    let cbor = encode_cbor_map(ev)?;
    let mut out = KOMMS_PAYLOAD_PREFIX.to_vec();
    out.extend_from_slice(&cbor);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EventType;

    fn ref_cid() -> Vec<u8> {
        ref_from_cid_str("bagaaaa").unwrap()
    }

    #[test]
    fn encode_then_parse_v1_roundtrip() {
        let ev = ParsedKommsEvent {
            v: 1,
            t: EventType::MessagePost,
            sid: Some([1u8; 32]),
            cid: Some([2u8; 32]),
            ref_bytes: Some(ref_cid()),
            enc: false,
            enc_scheme: Some(0),
            ts: Some(123),
            n: Some(1),
            ..Default::default()
        };
        let raw = encode_komms_payload(&ev).unwrap();
        let parsed = crate::parse_komms_payload(&raw).unwrap();
        assert_eq!(parsed, ev);
    }

    #[test]
    fn signing_payload_excludes_sig() {
        let ev = ParsedKommsEvent {
            v: 1,
            t: EventType::MessagePost,
            sid: Some([1u8; 32]),
            cid: Some([2u8; 32]),
            ref_bytes: Some(ref_cid()),
            enc: false,
            enc_scheme: Some(0),
            ts: Some(42),
            n: Some(2),
            sig: Some([9u8; 64]),
            ..Default::default()
        };
        let signing = signing_payload_cbor(&ev).unwrap();
        let mut without_sig = ev.clone();
        without_sig.sig = None;
        let direct = encode_cbor_map(&without_sig).unwrap();
        assert_eq!(signing, direct);
    }
}
