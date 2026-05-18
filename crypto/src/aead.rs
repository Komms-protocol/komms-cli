//! AES-256-GCM seal / open with explicit AAD binding.
//!
//! Every v1.1 encrypted-counterpart field (`enc_sid`, `enc_cid`,
//! `enc_body_ref`, `enc_parent_mid`, `enc_t`, `member_sealed`) uses
//! AES-256-GCM as the underlying AEAD. This module exposes a single
//! pair of `seal_field` / `open_field` helpers that:
//!
//! 1. Draw a fresh 96-bit nonce from the platform CSPRNG on every
//!    seal. Random nonces are safe for the message volumes we care
//!    about (NIST SP 800-38D §8.3 — collision probability < 2⁻³² for
//!    < 2³² messages per key, which we never approach because we
//!    rotate keys far more often).
//! 2. Bind every ciphertext to an explicit AAD chosen by the caller
//!    so that a `member_sealed` blob cannot be spliced into an
//!    `enc_body_ref` slot, etc. See [`AadContext`] for the canonical
//!    construction.
//! 3. Return the open variant only on successful AEAD-tag verification
//!    and surface failure as an opaque [`AeadError::Tag`] — callers
//!    MUST NOT distinguish "wrong key" from "wrong AAD" from "tampered
//!    ciphertext" because doing so leaks information to attackers.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use thiserror::Error;

use crate::sealed::SealedField;

/// 96-bit nonce length used by AES-256-GCM (NIST SP 800-38D §8.2.1).
pub const NONCE_LEN: usize = 12;
/// 128-bit authentication tag appended after every AES-GCM ciphertext.
pub const AEAD_TAG_LEN: usize = 16;

/// Errors returned by [`open_field`]. Constant-time-safe: variant
/// discrimination MUST NOT leak the failure cause to the network peer.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AeadError {
    /// Authentication tag mismatch. Returned by AES-GCM on any of:
    /// wrong key, wrong AAD, wrong nonce, or tampered ciphertext.
    /// Callers SHOULD treat this as a single opaque "decrypt failed"
    /// signal.
    #[error("AEAD authentication failed (wrong key, AAD, nonce, or ciphertext)")]
    Tag,
    /// Ciphertext was shorter than the minimum AEAD tag length. Always
    /// a wire-format violation rather than a key / AAD mismatch.
    #[error("ciphertext too short to contain AEAD tag")]
    TooShort,
}

/// Canonical AAD construction for v1.1 field-level AEAD.
///
/// The on-wire `enc_*` blob is bound to:
///
/// - the protocol version + domain tag (prevents downgrade / cross-
///   protocol replay),
/// - the destination CBOR key byte (prevents an `enc_sid` blob from
///   being spliced into the `enc_cid` slot),
/// - the server id and key epoch (prevents cross-server / cross-
///   rotation replay),
/// - optionally a per-event nonce-binding field (e.g. the `n` replay
///   counter or `ts`) when the caller wants per-message uniqueness
///   beyond what the random nonce already provides.
///
/// The encoding is unambiguous: each component is preceded by a
/// single-byte length tag, so a malicious peer cannot construct two
/// distinct (component₁, component₂) tuples that serialise to the
/// same AAD byte string.
#[derive(Clone, Debug)]
pub struct AadContext<'a> {
    /// CBOR key byte of the destination field (e.g. 23 for `enc_sid`,
    /// 25 for `enc_body_ref`, 28 for `enc_t`). Prevents cross-field
    /// ciphertext splicing.
    pub cbor_key: u8,
    /// Server id the event is bound to.
    pub server_id: &'a [u8; 32],
    /// Key epoch the encryption was performed under.
    pub key_epoch: u64,
    /// Optional extra binding (e.g. event `n`, parent `mid`).
    /// Append-only; if you change the layout, mint a new domain tag.
    pub extra: &'a [u8],
}

const AAD_DOMAIN: &[u8] = b"komms/v1.1/aead";

impl AadContext<'_> {
    /// Materialise the canonical AAD byte string. Length-prefixed
    /// components prevent ambiguity between different field orderings.
    fn encode(&self) -> Vec<u8> {
        // Layout: domain || 0x01 || cbor_key (1B)
        //                || 0x20 || server_id (32B)
        //                || 0x08 || key_epoch_be (8B)
        //                || varint(extra.len()) || extra
        //
        // The single-byte length tags double as type tags so a peer
        // cannot make the AAD ambiguous by varying lengths.
        let mut out =
            Vec::with_capacity(AAD_DOMAIN.len() + 1 + 1 + 1 + 32 + 1 + 8 + 4 + self.extra.len());
        out.extend_from_slice(AAD_DOMAIN);
        out.push(0x01);
        out.push(self.cbor_key);
        out.push(0x20);
        out.extend_from_slice(self.server_id);
        out.push(0x08);
        out.extend_from_slice(&self.key_epoch.to_be_bytes());
        // `extra` length encoded as 4-byte big-endian (max field is
        // 2³² - 1 bytes, far above any sane on-chain payload).
        let extra_len = u32::try_from(self.extra.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&extra_len.to_be_bytes());
        out.extend_from_slice(self.extra);
        out
    }
}

/// Encrypt `plaintext` under `key` (32 B AES-256 key) with AAD
/// derived from `aad`. Returns a [`SealedField`] containing the
/// fresh nonce, the ciphertext, and the 16-byte AEAD tag.
///
/// The nonce is drawn from `OsRng`. The same plaintext MUST NOT be
/// sealed twice under the same key; doing so is safe because each
/// call draws a fresh nonce, but callers should still avoid emitting
/// redundant transactions for cost reasons.
pub fn seal_field(key: &[u8; 32], aad: &AadContext<'_>, plaintext: &[u8]) -> SealedField {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);
    let aad_bytes = aad.encode();
    let mut ct = cipher
        .encrypt(
            &nonce_bytes,
            Payload {
                msg: plaintext,
                aad: &aad_bytes,
            },
        )
        .expect("AES-GCM seal never fails for in-spec inputs");
    let tag_offset = ct.len() - AEAD_TAG_LEN;
    let tag: [u8; AEAD_TAG_LEN] = ct[tag_offset..]
        .try_into()
        .expect("ciphertext suffix is exactly AEAD_TAG_LEN bytes");
    ct.truncate(tag_offset);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(nonce_bytes.as_slice());
    SealedField {
        nonce,
        ciphertext: ct,
        aead_tag: tag,
    }
}

/// Verify and decrypt `sealed` under `key` with the same AAD used at
/// seal time. Returns the plaintext on success or [`AeadError::Tag`]
/// on any failure mode.
pub fn open_field(
    key: &[u8; 32],
    aad: &AadContext<'_>,
    sealed: &SealedField,
) -> Result<Vec<u8>, AeadError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&sealed.nonce);
    let aad_bytes = aad.encode();
    // AES-GCM expects ciphertext || tag concatenated. We carry them
    // separately on the wire (matches the CBOR layout where bytes are
    // a single typed run) so reassemble here.
    let mut combined = Vec::with_capacity(sealed.ciphertext.len() + AEAD_TAG_LEN);
    combined.extend_from_slice(&sealed.ciphertext);
    combined.extend_from_slice(&sealed.aead_tag);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &combined,
                aad: &aad_bytes,
            },
        )
        .map_err(|_| AeadError::Tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        [0x11u8; 32]
    }
    fn sid() -> [u8; 32] {
        [0x01u8; 32]
    }

    fn aad<'a>(extra: &'a [u8]) -> AadContext<'a> {
        AadContext {
            cbor_key: 23,
            server_id: const { &[0x01u8; 32] },
            key_epoch: 7,
            extra,
        }
    }

    /// Happy-path round-trip — the core property the rest of the
    /// pipeline relies on.
    #[test]
    fn seal_open_roundtrip() {
        let aad = aad(b"");
        let sealed = seal_field(&key(), &aad, b"hello world");
        let opened = open_field(&key(), &aad, &sealed).unwrap();
        assert_eq!(opened, b"hello world");
    }

    /// Empty plaintext is valid AEAD input (carrier for AAD-only
    /// authenticity). v1.1 doesn't currently use this surface but
    /// the primitive should support it for forward compatibility.
    #[test]
    fn empty_plaintext_roundtrips() {
        let aad = aad(b"");
        let sealed = seal_field(&key(), &aad, b"");
        assert!(sealed.ciphertext.is_empty());
        let opened = open_field(&key(), &aad, &sealed).unwrap();
        assert!(opened.is_empty());
    }

    /// Two consecutive seals of the same plaintext under the same key
    /// MUST produce different ciphertexts because the nonce is fresh.
    /// This is what makes a passive observer unable to detect message
    /// repetition.
    #[test]
    fn nonce_freshness_yields_distinct_ciphertexts() {
        let aad = aad(b"");
        let a = seal_field(&key(), &aad, b"hello world");
        let b = seal_field(&key(), &aad, b"hello world");
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    /// Wrong key → opaque `Tag` failure.
    #[test]
    fn wrong_key_rejected() {
        let aad = aad(b"");
        let sealed = seal_field(&key(), &aad, b"secret");
        let wrong = [0xFFu8; 32];
        let err = open_field(&wrong, &aad, &sealed).unwrap_err();
        assert_eq!(err, AeadError::Tag);
    }

    /// Wrong AAD → opaque `Tag` failure (same error variant as wrong
    /// key by design; callers MUST NOT branch on the cause).
    #[test]
    fn wrong_aad_field_byte_rejected() {
        let seal_aad = aad(b"");
        let sealed = seal_field(&key(), &seal_aad, b"secret");
        let mut wrong_aad = aad(b"");
        wrong_aad.cbor_key = 24; // pretend it was enc_cid, not enc_sid
        let err = open_field(&key(), &wrong_aad, &sealed).unwrap_err();
        assert_eq!(err, AeadError::Tag);
    }

    /// Wrong key epoch → opaque `Tag` failure. Defends against
    /// replaying a ciphertext from a prior epoch into a fresh one.
    #[test]
    fn wrong_aad_epoch_rejected() {
        let seal_aad = aad(b"");
        let sealed = seal_field(&key(), &seal_aad, b"secret");
        let mut wrong_aad = aad(b"");
        wrong_aad.key_epoch = 8;
        let err = open_field(&key(), &wrong_aad, &sealed).unwrap_err();
        assert_eq!(err, AeadError::Tag);
    }

    /// Tampered ciphertext (single bit flip) → opaque `Tag` failure.
    /// This is the AEAD integrity property as advertised.
    #[test]
    fn tampered_ciphertext_rejected() {
        let aad = aad(b"");
        let mut sealed = seal_field(&key(), &aad, b"secret message body");
        if let Some(first) = sealed.ciphertext.first_mut() {
            *first ^= 0x01;
        }
        let err = open_field(&key(), &aad, &sealed).unwrap_err();
        assert_eq!(err, AeadError::Tag);
    }

    /// Tampered AEAD tag → opaque `Tag` failure.
    #[test]
    fn tampered_aead_tag_rejected() {
        let aad = aad(b"");
        let mut sealed = seal_field(&key(), &aad, b"secret message body");
        sealed.aead_tag[0] ^= 0x01;
        let err = open_field(&key(), &aad, &sealed).unwrap_err();
        assert_eq!(err, AeadError::Tag);
    }

    /// The `extra` AAD binding actually binds. Sealing with
    /// `extra = b"v=1,n=2"` cannot be opened with `extra = b"v=1,n=3"`.
    #[test]
    fn extra_aad_binding_is_authenticated() {
        let seal_aad = aad(b"v=1,n=2");
        let sealed = seal_field(&key(), &seal_aad, b"ok");
        let open_aad = aad(b"v=1,n=3");
        let err = open_field(&key(), &open_aad, &sealed).unwrap_err();
        assert_eq!(err, AeadError::Tag);
    }

    /// Smoke-check the AAD encoding doesn't accidentally produce
    /// the same bytes for two distinct contexts. This is a coarse
    /// property test that the explicit length-prefix layout works.
    #[test]
    fn aad_encoding_separates_field_bytes() {
        let mut a = aad(b"");
        a.cbor_key = 23;
        let mut b = aad(b"");
        b.cbor_key = 24;
        assert_ne!(a.encode(), b.encode());
    }

    #[test]
    fn aad_encoding_separates_servers() {
        let server_a = [0x01u8; 32];
        let server_b = [0x02u8; 32];
        let a = AadContext {
            cbor_key: 23,
            server_id: &server_a,
            key_epoch: 7,
            extra: b"",
        };
        let b = AadContext {
            cbor_key: 23,
            server_id: &server_b,
            key_epoch: 7,
            extra: b"",
        };
        assert_ne!(a.encode(), b.encode());
    }

    /// AAD is also exercised across the full seal/open cycle when the
    /// server id changes — sealing with one and opening with another
    /// MUST fail.
    #[test]
    fn cross_server_replay_rejected() {
        let server_a = [0x01u8; 32];
        let server_b = [0x02u8; 32];
        let seal_aad = AadContext {
            cbor_key: 23,
            server_id: &server_a,
            key_epoch: 7,
            extra: b"",
        };
        let sealed = seal_field(&key(), &seal_aad, b"private payload");
        let open_aad = AadContext {
            cbor_key: 23,
            server_id: &server_b,
            key_epoch: 7,
            extra: b"",
        };
        let err = open_field(&key(), &open_aad, &sealed).unwrap_err();
        assert_eq!(err, AeadError::Tag);
        // sid() helper kept for symmetry with the other test files;
        // silence the unused-import warning when this is the only use
        // in scope.
        let _ = sid();
    }
}
