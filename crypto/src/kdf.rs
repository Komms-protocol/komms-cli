//! HKDF-SHA-256 helpers with explicit domain separation.
//!
//! Every derived key in v1.1 passes through a typed entry point here so
//! that:
//!
//! 1. No call site can accidentally reuse a key across contexts (e.g.
//!    use a match-tag HMAC key to also AEAD-encrypt a field).
//! 2. Domain strings are centralised, ASCII, version-stamped, and easy
//!    to audit. See [`KdfDomain::as_bytes`] for the canonical list.
//! 3. The `info` field bound into HKDF carries the contextual binding
//!    (server id, channel id, epoch counter) that distinguishes one
//!    derivation from another within the same domain.
//!
//! ## Construction
//!
//! ```text
//! okm = HKDF-SHA-256(
//!     ikm  = master_viewing_key,           // 32 bytes
//!     salt = b"",                          // empty salt; mvk is already high-entropy
//!     info = domain_tag || 0x00 || binding // domain prefix + structured binding
//! )[..32]
//! ```
//!
//! Per RFC 5869 §3.1 the salt is optional and recommended when the IKM
//! is not already uniformly random. The master viewing key is generated
//! by a CSPRNG (`KEY_ROTATE` emits one freshly drawn per rotation) so
//! the salt-less form is safe; the security reduction relies on the
//! HMAC-SHA-256 PRF assumption.
//!
//! The single `0x00` separator byte between the domain string and the
//! variable-length binding guarantees that domains with distinct
//! intended bindings cannot collide (e.g. a 32-byte channel id starting
//! with the bytes of another domain string).

use hkdf::Hkdf;
use sha2::Sha256;

use crate::{DataEncryptionKey, MasterViewingKey};

/// HKDF domain separators. Each variant binds a specific call-site
/// intent (key purpose × format). Adding a new domain is an additive
/// change; **never** reuse or rename an existing one — a v1.1
/// participant somewhere else has the same string baked in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KdfDomain {
    /// Per-channel data encryption key. Used as the AES-256-GCM key
    /// for `enc_sid`, `enc_cid`, `enc_body_ref`, `enc_parent_mid`,
    /// `enc_t`. Binding: `server_id || channel_id || key_epoch_be8`.
    ChannelDek,
    /// Match-tag HMAC key. Used by [`crate::tags::compute_match_tag`]
    /// to produce the 16-byte fan-out tag the indexer reads from
    /// `match_tag` (CBOR key 27). Binding: `server_id || key_epoch_be8`.
    MatchTagKey,
    /// Member-tag HMAC key. Used by [`crate::tags::compute_member_tag`]
    /// to produce the linkable 16-byte sealed-membership tag
    /// (`member_tag`, CBOR key 21). Binding: `server_id || key_epoch_be8`.
    MemberTagKey,
    /// Member-sealed AEAD key. Encrypts the per-server stealth pubkey
    /// and identity blob carried in `member_sealed` (CBOR key 22).
    /// Binding: `server_id || key_epoch_be8`.
    MemberSealedKey,
}

impl KdfDomain {
    /// Canonical ASCII domain tag baked into the HKDF `info` parameter.
    /// Version-stamped (`v1.1`) and slash-separated so a future v1.2
    /// or `KdfDomain` rev cannot silently collide.
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            KdfDomain::ChannelDek => b"komms/v1.1/channel-dek",
            KdfDomain::MatchTagKey => b"komms/v1.1/match-tag-key",
            KdfDomain::MemberTagKey => b"komms/v1.1/member-tag-key",
            KdfDomain::MemberSealedKey => b"komms/v1.1/member-sealed-key",
        }
    }
}

/// Run HKDF-SHA-256 with `info = domain.as_bytes() || 0x00 || binding`
/// and extract 32 bytes. Internal — call sites should use the typed
/// helpers below.
fn hkdf_32(mvk: &MasterViewingKey, domain: KdfDomain, binding: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, mvk.as_slice());
    let mut info = Vec::with_capacity(domain.as_bytes().len() + 1 + binding.len());
    info.extend_from_slice(domain.as_bytes());
    info.push(0x00);
    info.extend_from_slice(binding);
    let mut out = [0u8; 32];
    // hkdf::expand cannot fail for an OKM length of 32 bytes
    // (max OKM is 255 * 32 = 8160 bytes for HKDF-SHA-256), so this
    // unwrap is infallible.
    hk.expand(&info, &mut out)
        .expect("HKDF-SHA-256 expand to 32 bytes never fails");
    out
}

/// Derive the per-channel DEK from the server's master viewing key,
/// the channel id, and the current key epoch.
///
/// Identical inputs produce identical outputs; this is the property
/// that lets every member of a server (re)derive the channel key
/// without an interactive handshake.
pub fn derive_channel_dek(
    mvk: &MasterViewingKey,
    server_id: &[u8; 32],
    channel_id: &[u8; 32],
    key_epoch: u64,
) -> DataEncryptionKey {
    let mut binding = [0u8; 32 + 32 + 8];
    binding[..32].copy_from_slice(server_id);
    binding[32..64].copy_from_slice(channel_id);
    binding[64..].copy_from_slice(&key_epoch.to_be_bytes());
    hkdf_32(mvk, KdfDomain::ChannelDek, &binding)
}

/// Derive the match-tag HMAC key (per server, per epoch).
pub fn derive_match_tag_key(
    mvk: &MasterViewingKey,
    server_id: &[u8; 32],
    key_epoch: u64,
) -> [u8; 32] {
    let mut binding = [0u8; 32 + 8];
    binding[..32].copy_from_slice(server_id);
    binding[32..].copy_from_slice(&key_epoch.to_be_bytes());
    hkdf_32(mvk, KdfDomain::MatchTagKey, &binding)
}

/// Derive the member-tag HMAC key (per server, per epoch).
pub fn derive_member_tag_key(
    mvk: &MasterViewingKey,
    server_id: &[u8; 32],
    key_epoch: u64,
) -> [u8; 32] {
    let mut binding = [0u8; 32 + 8];
    binding[..32].copy_from_slice(server_id);
    binding[32..].copy_from_slice(&key_epoch.to_be_bytes());
    hkdf_32(mvk, KdfDomain::MemberTagKey, &binding)
}

/// Derive the member-sealed AEAD key (per server, per epoch).
pub fn derive_member_sealed_key(
    mvk: &MasterViewingKey,
    server_id: &[u8; 32],
    key_epoch: u64,
) -> [u8; 32] {
    let mut binding = [0u8; 32 + 8];
    binding[..32].copy_from_slice(server_id);
    binding[32..].copy_from_slice(&key_epoch.to_be_bytes());
    hkdf_32(mvk, KdfDomain::MemberSealedKey, &binding)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mvk() -> MasterViewingKey {
        [0x42u8; 32]
    }

    fn sid() -> [u8; 32] {
        [0x01u8; 32]
    }

    fn cid() -> [u8; 32] {
        [0x02u8; 32]
    }

    /// HKDF is deterministic: identical inputs MUST yield identical
    /// keys. Every member of a server relies on this for handshake-free
    /// reconvergence on the per-channel DEK.
    #[test]
    fn channel_dek_is_deterministic() {
        let a = derive_channel_dek(&mvk(), &sid(), &cid(), 7);
        let b = derive_channel_dek(&mvk(), &sid(), &cid(), 7);
        assert_eq!(a, b);
    }

    /// A different epoch under the same (mvk, sid, cid) MUST produce a
    /// different key. This is the property that gives KEY_ROTATE its
    /// forward-secrecy semantics.
    #[test]
    fn channel_dek_changes_per_epoch() {
        let e1 = derive_channel_dek(&mvk(), &sid(), &cid(), 1);
        let e2 = derive_channel_dek(&mvk(), &sid(), &cid(), 2);
        assert_ne!(e1, e2);
    }

    /// Domain separation: two different `KdfDomain` variants with the
    /// same binding bytes MUST produce different keys.
    #[test]
    fn domains_are_separated() {
        let match_key = derive_match_tag_key(&mvk(), &sid(), 0);
        let member_key = derive_member_tag_key(&mvk(), &sid(), 0);
        let sealed_key = derive_member_sealed_key(&mvk(), &sid(), 0);
        assert_ne!(match_key, member_key);
        assert_ne!(match_key, sealed_key);
        assert_ne!(member_key, sealed_key);
    }

    /// Different servers under the same epoch MUST yield different keys.
    #[test]
    fn server_id_binding_is_honored() {
        let server_a = [0xAAu8; 32];
        let server_b = [0xBBu8; 32];
        let a = derive_match_tag_key(&mvk(), &server_a, 5);
        let b = derive_match_tag_key(&mvk(), &server_b, 5);
        assert_ne!(a, b);
    }

    /// Different channels within the same server MUST yield different
    /// per-channel DEKs.
    #[test]
    fn channel_id_binding_is_honored() {
        let channel_a = [0x10u8; 32];
        let channel_b = [0x11u8; 32];
        let a = derive_channel_dek(&mvk(), &sid(), &channel_a, 0);
        let b = derive_channel_dek(&mvk(), &sid(), &channel_b, 0);
        assert_ne!(a, b);
    }

    /// Golden vector — pins the exact byte output for the documented
    /// inputs so any unintentional change to the HKDF construction
    /// (domain string, separator byte, binding layout) breaks the
    /// suite. Regenerate intentionally if you change the construction
    /// in a coordinated cross-runtime release; never silently.
    #[test]
    fn channel_dek_golden_vector() {
        let mvk = [0u8; 32];
        let sid = [0u8; 32];
        let cid = [0u8; 32];
        let dek = derive_channel_dek(&mvk, &sid, &cid, 0);
        let expected =
            hex_literal::hex!("5c29e4e0fa1426f1de0223e9908055529d70a96c5387f000e54f6b6ffd99d2a9");
        assert_eq!(dek, expected, "channel-dek golden vector drift");
    }
}
