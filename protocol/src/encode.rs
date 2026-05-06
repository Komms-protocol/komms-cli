//! Canonical CBOR encoding (Appendix A) and identifier derivations (A4).

use crate::{
    ParsedKommsEvent, ValidationError, validate_event, validate_ref, KOMMS_PAYLOAD_PREFIX,
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

/// A4.1 Komms server id: canonical `sid` equals the `ServerCreate` transaction id (32-byte Kaspa tx id).
pub fn server_id(creation_txid: &[u8; 32]) -> [u8; 32] {
    *creation_txid
}

/// Member identity for `MEMBER_JOIN` / `MEMBER_LEAVE` (map key `pid`).
/// `SHA-256("KOMMS_PARTICIPANT_V0" || creator_address_bytes)` — same `version || payload` as indexer APIs.
pub fn participant_id(creator_address_bytes: &[u8]) -> [u8; 32] {
    sha256_domain(b"KOMMS_PARTICIPANT_V0", &[creator_address_bytes])
}

/// A4.2 `cid = SHA-256("KOMMS_CHANNEL_V0" || sid || creator_address_bytes || creation_txid_bytes)`
pub fn channel_id(
    sid: &[u8; 32],
    creator_address_bytes: &[u8],
    creation_txid: &[u8; 32],
) -> [u8; 32] {
    sha256_domain(
        b"KOMMS_CHANNEL_V0",
        &[sid.as_ref(), creator_address_bytes, creation_txid.as_ref()],
    )
}

/// A4.3 `did = SHA-256("KOMMS_DM_V0" || min(addrA,addrB) || max(addrA,addrB))`
pub fn dm_thread_id(addr_a: &[u8], addr_b: &[u8]) -> [u8; 32] {
    let (min_a, max_a) = match addr_a.cmp(addr_b) {
        Ordering::Greater => (addr_b, addr_a),
        _ => (addr_a, addr_b),
    };
    sha256_domain(b"KOMMS_DM_V0", &[min_a, max_a])
}

/// A4.4 `mid = SHA-256("KOMMS_MSG_V0" || txid_bytes || event_index)` with `event_index` as big-endian u64.
pub fn message_id(txid: &[u8; 32], event_index: u64) -> [u8; 32] {
    let ix = event_index.to_be_bytes();
    sha256_domain(b"KOMMS_MSG_V0", &[txid.as_ref(), ix.as_ref()])
}

/// Encode the event map as deterministic CBOR (keys in ascending order). Does not include the `KOMM` prefix.
pub fn encode_cbor_map(ev: &ParsedKommsEvent) -> Result<Vec<u8>, ValidationError> {
    validate_event(ev)?;
    if let Some(ref r) = ev.ref_bytes {
        validate_ref(r)?;
    }
    let mut pairs: Vec<(Value, Value)> = Vec::new();

    pairs.push((Value::Integer(0.into()), Value::Integer(ev.v.into())));
    pairs.push((
        Value::Integer(1.into()),
        Value::Integer((ev.t as u8).into()),
    ));

    if let Some(sid) = ev.sid {
        pairs.push((Value::Integer(2.into()), Value::Bytes(sid.to_vec())));
    }
    if let Some(cid) = ev.cid {
        pairs.push((Value::Integer(3.into()), Value::Bytes(cid.to_vec())));
    }
    if let Some(did) = ev.did {
        pairs.push((Value::Integer(4.into()), Value::Bytes(did.to_vec())));
    }
    if let Some(pid) = ev.pid {
        pairs.push((Value::Integer(5.into()), Value::Bytes(pid.to_vec())));
    }
    if let Some(mid) = ev.mid {
        pairs.push((Value::Integer(6.into()), Value::Bytes(mid.to_vec())));
    }
    if let Some(ref r) = ev.ref_bytes {
        pairs.push((Value::Integer(7.into()), Value::Bytes(r.clone())));
    }
    pairs.push((Value::Integer(8.into()), Value::Bool(ev.enc)));
    if let Some(ts) = ev.ts {
        pairs.push((Value::Integer(9.into()), Value::Integer(ts.into())));
    }
    if let Some(n) = ev.n {
        pairs.push((Value::Integer(10.into()), Value::Integer(n.into())));
    }
    if let Some(sig) = ev.sig {
        pairs.push((Value::Integer(11.into()), Value::Bytes(sig.to_vec())));
    }

    let v = Value::Map(pairs);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&v, &mut buf).expect("CBOR map encode to Vec");
    Ok(buf)
}

/// A6: CBOR map bytes covered by `sig` (deterministic map **without** key 11).
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
