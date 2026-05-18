//! Wire-format for v1.1 sealed-field payloads.
//!
//! Every v1.1 encrypted-counterpart field (`enc_sid`, `enc_cid`,
//! `enc_body_ref`, `enc_parent_mid`, `enc_t`, `member_sealed`) carries
//! the same three-part byte string on the chain:
//!
//! ```text
//! 0       12              N            N+16
//! +-------+----------------+------------+
//! | nonce |  ciphertext    | aead_tag   |
//! +-------+----------------+------------+
//!   12 B       variable        16 B
//! ```
//!
//! Layout chosen so a single fixed-offset parser can recover the three
//! components without reading any length tag: `nonce` is the first 12
//! bytes, `aead_tag` is the last 16, and the ciphertext is everything
//! in between. Any byte string shorter than 28 (= 12 + 16) is rejected
//! at parse time because it cannot contain both the nonce and the tag.

use thiserror::Error;

use crate::aead::{AEAD_TAG_LEN, NONCE_LEN};

/// Minimum on-wire length: nonce (12 B) + AEAD tag (16 B).
pub const MIN_SEALED_LEN: usize = NONCE_LEN + AEAD_TAG_LEN;

/// In-memory representation of a sealed field, split into its three
/// canonical components.
///
/// `nonce` and `aead_tag` are fixed-size by AES-256-GCM's contract;
/// `ciphertext` carries the same number of bytes as the plaintext
/// (AES-GCM is a streaming cipher).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedField {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
    pub aead_tag: [u8; AEAD_TAG_LEN],
}

/// Parse errors surfaced by [`SealedField::from_wire`]. All errors
/// here are wire-shape violations and SHOULD result in the indexer
/// rejecting the event from typed projection.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SealedFieldError {
    /// Byte string was shorter than `nonce_len + tag_len = 28` bytes.
    #[error("sealed field too short: need at least {MIN_SEALED_LEN} bytes, got {0}")]
    TooShort(usize),
}

impl SealedField {
    /// Canonical wire encoding: `nonce || ciphertext || aead_tag`.
    /// Returns a freshly allocated `Vec<u8>` ready to drop into a
    /// `ciborium::Value::Bytes`.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(NONCE_LEN + self.ciphertext.len() + AEAD_TAG_LEN);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.aead_tag);
        out
    }

    /// Parse the canonical wire encoding back into the three
    /// components. The input MUST be at least 28 bytes long.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, SealedFieldError> {
        if bytes.len() < MIN_SEALED_LEN {
            return Err(SealedFieldError::TooShort(bytes.len()));
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[..NONCE_LEN]);
        let tag_offset = bytes.len() - AEAD_TAG_LEN;
        let mut aead_tag = [0u8; AEAD_TAG_LEN];
        aead_tag.copy_from_slice(&bytes[tag_offset..]);
        let ciphertext = bytes[NONCE_LEN..tag_offset].to_vec();
        Ok(Self {
            nonce,
            ciphertext,
            aead_tag,
        })
    }

    /// On-wire length of this sealed field. Equal to the `bytes`
    /// length seen by [`Self::from_wire`].
    pub fn wire_len(&self) -> usize {
        NONCE_LEN + self.ciphertext.len() + AEAD_TAG_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> SealedField {
        SealedField {
            nonce: [0xAAu8; NONCE_LEN],
            ciphertext: vec![1, 2, 3, 4, 5],
            aead_tag: [0xCCu8; AEAD_TAG_LEN],
        }
    }

    #[test]
    fn wire_roundtrip() {
        let sf = fixture();
        let bytes = sf.to_wire();
        assert_eq!(bytes.len(), sf.wire_len());
        let back = SealedField::from_wire(&bytes).unwrap();
        assert_eq!(sf, back);
    }

    #[test]
    fn empty_ciphertext_roundtrips() {
        let sf = SealedField {
            nonce: [0u8; NONCE_LEN],
            ciphertext: vec![],
            aead_tag: [0u8; AEAD_TAG_LEN],
        };
        let bytes = sf.to_wire();
        assert_eq!(bytes.len(), MIN_SEALED_LEN);
        let back = SealedField::from_wire(&bytes).unwrap();
        assert_eq!(sf, back);
    }

    #[test]
    fn too_short_rejected() {
        for len in 0..MIN_SEALED_LEN {
            let bytes = vec![0u8; len];
            let err = SealedField::from_wire(&bytes).unwrap_err();
            assert_eq!(err, SealedFieldError::TooShort(len));
        }
    }

    /// Wire layout is fixed: bytes 0..12 are the nonce, the last 16
    /// are the AEAD tag, and everything in between is the
    /// ciphertext. Pin this with a byte-level assertion so a future
    /// refactor cannot silently change the field order.
    #[test]
    fn wire_layout_is_stable() {
        let sf = SealedField {
            nonce: [0x11u8; NONCE_LEN],
            ciphertext: vec![0x22u8; 4],
            aead_tag: [0x33u8; AEAD_TAG_LEN],
        };
        let bytes = sf.to_wire();
        assert_eq!(&bytes[..NONCE_LEN], &[0x11u8; NONCE_LEN]);
        assert_eq!(&bytes[NONCE_LEN..NONCE_LEN + 4], &[0x22u8; 4]);
        assert_eq!(&bytes[NONCE_LEN + 4..], &[0x33u8; AEAD_TAG_LEN]);
    }
}
