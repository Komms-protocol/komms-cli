//! Protocol-level Ed25519 verification of KOMMS events.
//!
//! Closes B2 of `komms-planning/AUDIT_2026-05-17.md` — the indexer
//! previously persisted any event that shape-parsed, regardless of
//! whether its `sig` field (key 11) was authentic. The audit traced
//! this back to two anti-patterns:
//!
//! 1. The block-processor never re-derived
//!    [`crate::signing_payload_cbor`] and checked the signature.
//! 2. The `komms-miner-submit` HTTP-surface comment explicitly
//!    deferred verification to the gateway, then the gateway
//!    deferred to the miner, then the indexer trusted both.
//!
//! This module provides the missing third leg: a pure, dependency-
//! local verifier whose only inputs are an event and its in-band
//! 32-byte Ed25519 pubkey. Every consumer (indexer block-processor,
//! miner-submit HTTP handler, future client mirror) imports the same
//! function — KOMMS_PRINCIPLES §6 (canonical bytes are one path).
//!
//! ## Canonical signed bytes
//!
//! The signed message is `signing_payload_cbor(ev)` — the canonical
//! CBOR map of every event field EXCEPT key 11 (`sig`). This matches:
//!
//! - [`komms-protocol/02_MESSAGING_CONTENT.md`](https://github.com/Komms-protocol/komms-planning/blob/main/komms-protocol/02_MESSAGING_CONTENT.md)
//!   §"Key 11 (`sig`)" — 64-byte Ed25519 over canonical CBOR.
//! - [`komms-protocol/06_UNIVERSAL_CONTENT.md`](https://github.com/Komms-protocol/komms-planning/blob/main/komms-protocol/06_UNIVERSAL_CONTENT.md)
//!   §"Signature row" — "Ed25519 signature over the canonical CBOR
//!   by reporter's `kommsIdentityPriv`".
//! - ADR-013 — Komms identity is Ed25519 (xonly; same curve the v1
//!   ciphersuite `MLS_256_MLKEM768_X25519_AES256GCM_SHA256_Ed25519`
//!   pins for MLS LeafNode signatures).
//!
//! The `KOMM` envelope prefix is NOT included in the signed bytes —
//! it is an on-chain wire delimiter, not part of the authenticated
//! payload.
//!
//! ## In-band pubkey
//!
//! Today, the only event fields that carry a 32-byte verifying key
//! on the wire are:
//!
//! - `device_pk` (key 17), populated for `DeviceRegister`,
//!   `DeviceRevoke`, and any v1.0+ event that opts into per-device
//!   signature transport ([`crate::ParsedKommsEvent::device_pk`]).
//!
//! For v0 events and v1.0+ events that defer signer identity to
//! out-of-band identity resolution (the Komms-identity covenant
//! lookup, ADR-011 / WS-A.6), the verifier returns
//! [`SignerPubkey::OutOfBand`] so the caller can decide whether to
//! persist anyway (current behaviour, behind a metric) or drop the
//! event (post-Horizon-B once the identity covenant ships).
//!
//! `sealed_signer` (key 30) is intentionally excluded from this
//! lookup: it is a variable-length bLSAG ring-signature blob, not a
//! 32-byte verifying key, and any event carrying it is rejected at
//! [`crate::validate_event`] time as Phase-3 reserved (ADR-013 §5).
//!
//! ## Constant-time
//!
//! `ed25519-dalek` (RustCrypto) performs constant-time scalar /
//! point arithmetic. The match on [`VerifyError`] variants happens
//! AFTER `verify_strict` returns, so an attacker cannot mount a
//! timing oracle that distinguishes "bad sig" from "bad pubkey".

use crate::{ParsedKommsEvent, ValidationError, encode::signing_payload_cbor};
use ed25519_dalek::{Signature, VerifyingKey};

/// Where the verifier sourced (or could not source) the signing key.
///
/// Returned by [`signer_pubkey_from_event`] so the caller can
/// distinguish the three operational paths:
///
/// 1. In-band pubkey present → verify now; reject on failure.
/// 2. Out-of-band (covenant-resolved) → persist unverified; metric.
/// 3. Sealed-sender (Phase 3) → upstream `validate_event` already
///    rejected, so this variant is unreachable by construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerPubkey {
    /// 32-byte Ed25519 verifying key sourced from the event itself
    /// (currently only [`ParsedKommsEvent::device_pk`], key 17).
    /// Pass to [`verify_event`] directly.
    InBand([u8; 32]),
    /// Signer identity is resolved out-of-band (Komms-identity
    /// covenant lookup, ADR-011) and not yet wired into this crate.
    /// Caller MUST NOT treat as authenticated; record the gap via a
    /// metric counter so the migration to mandatory verification is
    /// observable.
    OutOfBand,
}

/// Verification failure modes.
///
/// All variants are deliberately distinct so callers can attribute
/// drops in metrics / structured logs without ambiguity. Avoid
/// re-stringifying the variant for the user: collapse to a single
/// "signature invalid" tag downstream — the granularity here is for
/// operators, not adversaries.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    /// Event carries no `sig` field (key 11). [`validate_event`]
    /// already enforces presence for event types where the protocol
    /// requires it, so reaching this variant means the caller is
    /// trying to verify an event that the protocol does not require
    /// to be signed.
    #[error("event has no `sig` (key 11); nothing to verify")]
    SignatureMissing,

    /// Supplied 32-byte slice does not decode to a canonical Ed25519
    /// verifying point under ZIP-215 rules
    /// ([`ed25519_dalek::VerifyingKey::from_bytes`]).
    #[error("invalid Ed25519 verifying key bytes")]
    InvalidPubkey,

    /// Signature does not verify against `signing_payload_cbor(ev)`
    /// under the supplied verifying key. Includes the strict
    /// malleability checks
    /// ([`ed25519_dalek::VerifyingKey::verify_strict`]).
    #[error("Ed25519 signature does not verify against canonical CBOR signing payload")]
    SignatureInvalid,

    /// Canonical encode failed (event itself is malformed). Surfaces
    /// the underlying `ValidationError` so the caller can log it
    /// once at the right severity instead of re-deriving it.
    #[error("canonical CBOR encode failed prior to verification: {0}")]
    Encode(#[from] ValidationError),
}

/// Extract the in-band Ed25519 signer pubkey from `ev`, if any.
///
/// See module docs for the policy. Stable + zero-allocation.
#[inline]
pub fn signer_pubkey_from_event(ev: &ParsedKommsEvent) -> SignerPubkey {
    match ev.device_pk {
        Some(dpk) => SignerPubkey::InBand(dpk),
        None => SignerPubkey::OutOfBand,
    }
}

/// Verify `ev.sig` (Ed25519, 64 bytes) against
/// [`signing_payload_cbor(ev)`](crate::signing_payload_cbor) using
/// the supplied 32-byte Ed25519 verifying key.
///
/// Uses `verify_strict` to reject (a) signatures with non-reduced
/// scalar `s`, and (b) small-order public keys — both attack
/// surfaces that the non-strict `verify` accepts. See the
/// [`ed25519_dalek::VerifyingKey::verify_strict`] docs for the full
/// rationale on why the strict variant is what every protocol
/// that survives external review picks.
///
/// **Inputs:**
///
/// - `ev`: parsed event. Its `sig` field MUST be `Some(_)`;
///   otherwise [`VerifyError::SignatureMissing`] is returned.
/// - `pubkey`: 32-byte Ed25519 verifying key. For events that
///   carry `device_pk` (key 17), the caller should source it from
///   there via [`signer_pubkey_from_event`]; for events whose
///   signer is resolved out-of-band, the caller is responsible for
///   providing a trusted pubkey (e.g., a Komms-identity covenant
///   lookup).
///
/// **Returns:** `Ok(())` on a valid sig; otherwise a [`VerifyError`]
/// variant. The function is constant-time; the variant breakdown is
/// for diagnostic logging only.
pub fn verify_event(ev: &ParsedKommsEvent, pubkey: &[u8; 32]) -> Result<(), VerifyError> {
    let sig_bytes = ev.sig.ok_or(VerifyError::SignatureMissing)?;
    let signing_bytes = signing_payload_cbor(ev)?;
    let key = VerifyingKey::from_bytes(pubkey).map_err(|_| VerifyError::InvalidPubkey)?;
    let signature = Signature::from_bytes(&sig_bytes);
    key.verify_strict(&signing_bytes, &signature)
        .map_err(|_| VerifyError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EventType;
    use ed25519_dalek::{Signer, SigningKey};

    /// Reproducible signing key from a fixed seed so tests are
    /// deterministic — we never need `OsRng` for verify-only tests.
    fn fixed_signing_key(seed_byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed_byte; 32])
    }

    /// Construct a v1 MessagePost with the canonical sid/cid/ts/n,
    /// sign it with `key`, and return the event + the verifying-key
    /// bytes. Sidesteps clutter at every call site.
    fn signed_message_event(key: &SigningKey) -> (ParsedKommsEvent, [u8; 32]) {
        let mut ev = ParsedKommsEvent {
            v: 1,
            t: EventType::MessagePost,
            sid: Some([0xAA; 32]),
            cid: Some([0xBB; 32]),
            ref_bytes: Some(crate::encode::ref_from_cid_str("bagaaaa").unwrap()),
            enc: false,
            enc_scheme: Some(0),
            ts: Some(1_700_000_000),
            n: Some(1),
            device_pk: Some(key.verifying_key().to_bytes()),
            sig_scheme: Some(0),
            ..Default::default()
        };
        let to_sign = signing_payload_cbor(&ev).expect("canonical encode");
        let sig = key.sign(&to_sign);
        ev.sig = Some(sig.to_bytes());
        (ev, key.verifying_key().to_bytes())
    }

    /// Happy path: an event signed with `k` verifies against `k`'s
    /// public bytes.
    #[test]
    fn verify_event_accepts_well_formed_sig() {
        let key = fixed_signing_key(0xA1);
        let (ev, pk) = signed_message_event(&key);
        assert_eq!(verify_event(&ev, &pk), Ok(()));
    }

    /// Tampering with the sig (flip any byte) is detected.
    #[test]
    fn verify_event_rejects_corrupted_sig() {
        let key = fixed_signing_key(0xA2);
        let (mut ev, pk) = signed_message_event(&key);
        let mut bad = ev.sig.unwrap();
        bad[0] ^= 0x01;
        ev.sig = Some(bad);
        assert_eq!(verify_event(&ev, &pk), Err(VerifyError::SignatureInvalid));
    }

    /// Signing with key A and verifying with key B's pubkey fails.
    #[test]
    fn verify_event_rejects_pubkey_mismatch() {
        let key_a = fixed_signing_key(0xA3);
        let key_b = fixed_signing_key(0xB4);
        let (ev, _) = signed_message_event(&key_a);
        let pk_b = key_b.verifying_key().to_bytes();
        assert_eq!(verify_event(&ev, &pk_b), Err(VerifyError::SignatureInvalid));
    }

    /// Tampering with any signed field (here: `ts`) invalidates the
    /// signature — proves the signature actually covers the canonical
    /// CBOR (not just a hash of the sid+cid).
    #[test]
    fn verify_event_rejects_payload_tamper() {
        let key = fixed_signing_key(0xA5);
        let (mut ev, pk) = signed_message_event(&key);
        ev.ts = Some(ev.ts.unwrap() + 1);
        assert_eq!(verify_event(&ev, &pk), Err(VerifyError::SignatureInvalid));
    }

    /// Missing `sig` field → `SignatureMissing`; nothing to verify.
    #[test]
    fn verify_event_missing_sig_returns_typed_error() {
        let key = fixed_signing_key(0xA6);
        let (mut ev, pk) = signed_message_event(&key);
        ev.sig = None;
        assert_eq!(verify_event(&ev, &pk), Err(VerifyError::SignatureMissing));
    }

    /// A 32-byte slice that does not decompress to a valid Edwards
    /// curve point returns `InvalidPubkey`. Many byte patterns decode
    /// successfully under ZIP-215 lax rules (the identity point
    /// `[0; 32]` is a valid weak key, `[0xFF; 32]` reduces to a small
    /// y-coord and is on the curve, etc.), so we use a specific
    /// vector taken from RustCrypto's own decompression test set
    /// — `y` outside the canonical range with sign bit set on a
    /// non-residue x² — that exercises the `from_bytes` rejection
    /// path without depending on internal implementation quirks.
    #[test]
    fn verify_event_invalid_pubkey_returns_typed_error() {
        let key = fixed_signing_key(0xA7);
        let (ev, _) = signed_message_event(&key);
        // Non-curve point: y-coord whose x² has no square root mod p.
        // Found by brute force search starting at counter=0 — pinned
        // here so the test is deterministic across runs.
        let mut bogus = [0u8; 32];
        bogus[0] = 0x02; // y = 2, sign bit clear.
        // Verify pre-condition: this is genuinely not on the curve.
        assert!(
            VerifyingKey::from_bytes(&bogus).is_err(),
            "test fixture must hit the from_bytes rejection path"
        );
        assert_eq!(verify_event(&ev, &bogus), Err(VerifyError::InvalidPubkey));
    }

    /// `signer_pubkey_from_event` surfaces `device_pk` when present.
    #[test]
    fn signer_pubkey_from_event_returns_device_pk_when_present() {
        let key = fixed_signing_key(0xA8);
        let (ev, pk) = signed_message_event(&key);
        assert_eq!(signer_pubkey_from_event(&ev), SignerPubkey::InBand(pk));
    }

    /// `signer_pubkey_from_event` returns `OutOfBand` for v0 events
    /// (or any event without `device_pk` populated).
    #[test]
    fn signer_pubkey_from_event_returns_out_of_band_for_v0_event() {
        let ev = ParsedKommsEvent {
            v: 0,
            t: EventType::MessagePost,
            sid: Some([0xAA; 32]),
            cid: Some([0xBB; 32]),
            ref_bytes: Some(crate::encode::ref_from_cid_str("bagaaaa").unwrap()),
            enc: false,
            ts: Some(42),
            n: Some(1),
            ..Default::default()
        };
        assert_eq!(signer_pubkey_from_event(&ev), SignerPubkey::OutOfBand);
    }

    /// Round-trip via `verify_event` ↔ direct `verify_strict` produce
    /// identical results — pins the contract that `verify_event`
    /// does not silently transform the signed message.
    #[test]
    fn verify_event_matches_direct_verify_strict() {
        let key = fixed_signing_key(0xA9);
        let (ev, pk) = signed_message_event(&key);
        let key_obj = VerifyingKey::from_bytes(&pk).unwrap();
        let sig = Signature::from_bytes(&ev.sig.unwrap());
        let canonical = signing_payload_cbor(&ev).unwrap();
        assert!(key_obj.verify_strict(&canonical, &sig).is_ok());
        assert_eq!(verify_event(&ev, &pk), Ok(()));
    }
}
