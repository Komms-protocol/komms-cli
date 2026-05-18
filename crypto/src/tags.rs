//! Fixed-length HMAC tag helpers.
//!
//! v1.1 ships two flavours of 16-byte HMAC tags:
//!
//! - **`match_tag`** (CBOR key 27): the indexer's fan-out primitive.
//!   Computed by senders and subscribers identically, the indexer
//!   treats it as an opaque bucket id (`komms_protocol_v_1_1.md` §13.6).
//! - **`member_tag`** (CBOR key 21): the linkable sealed-membership
//!   tag emitted by `SEALED_MEMBER_JOIN` / `SEALED_MEMBER_LEAVE`.
//!   Lets the indexer reconcile a member's join + leave without
//!   learning their on-server identity.
//!
//! Both are HMAC-SHA-256 outputs truncated to 16 bytes (FIPS 198-1
//! permits truncation; SP 800-107 recommends ≥ 128 bits for the
//! collision-resistant regime, which is exactly our 16-byte choice).
//!
//! Truncation is taken from the *left*, matching every other HMAC
//! truncation convention in the IETF (TLS, SRTP, IPsec) so no
//! reader/writer disagrees on which half of the digest is the tag.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// On-wire length of every Komms v1.1 truncated HMAC tag, in bytes.
/// Matches `V1_1_TAG_LEN` in the `protocol` crate.
pub const TAG_LEN: usize = 16;

type HmacSha256 = Hmac<Sha256>;

/// Domain prefix for the `match_tag` HMAC input. Distinct from the
/// `member_tag` prefix so the same HMAC key (in case of accidental
/// reuse) cannot produce a tag valid for both domains.
const MATCH_TAG_DOMAIN: &[u8] = b"komms/v1.1/match-tag";

/// Domain prefix for the `member_tag` HMAC input.
const MEMBER_TAG_DOMAIN: &[u8] = b"komms/v1.1/member-tag";

/// Compute the 16-byte `match_tag` for an event addressed to
/// `(server_id, channel_id, key_epoch)`.
///
/// The HMAC key is derived by
/// [`crate::kdf::derive_match_tag_key`]; the message is the
/// canonical input
///
/// ```text
/// MATCH_TAG_DOMAIN || channel_id (32 B) || key_epoch_be (8 B)
/// ```
///
/// The server id is already bound into the key via HKDF, so it does
/// not need to appear here. Subscribers re-running this with the
/// same `(match_tag_key, channel_id, key_epoch)` obtain the same
/// tag and can match the indexer's fan-out without ever revealing
/// the channel id to the indexer.
pub fn compute_match_tag(
    match_tag_key: &[u8; 32],
    channel_id: &[u8; 32],
    key_epoch: u64,
) -> [u8; TAG_LEN] {
    // Hmac::new_from_slice on a 32-byte key cannot fail (Hmac<Sha256>
    // accepts any byte length); unwrap is infallible.
    let mut mac = HmacSha256::new_from_slice(match_tag_key)
        .expect("HMAC-SHA-256 accepts arbitrary key length");
    mac.update(MATCH_TAG_DOMAIN);
    mac.update(channel_id);
    mac.update(&key_epoch.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(&digest[..TAG_LEN]);
    out
}

/// Compute the 16-byte `member_tag` for a `(member_pubkey, key_epoch)`
/// pair under the server's member-tag HMAC key.
///
/// `member_pubkey` is the user's per-server stealth secp256k1 x-only
/// pubkey (32 bytes), derived per ADR-011 from the user's master
/// identity. Encoding the x-only key directly (no SEC1 prefix byte)
/// keeps the wire input fixed-width and matches the BIP-340
/// convention used elsewhere in the v1.1 stack.
pub fn compute_member_tag(
    member_tag_key: &[u8; 32],
    member_pubkey: &[u8; 32],
    key_epoch: u64,
) -> [u8; TAG_LEN] {
    let mut mac = HmacSha256::new_from_slice(member_tag_key)
        .expect("HMAC-SHA-256 accepts arbitrary key length");
    mac.update(MEMBER_TAG_DOMAIN);
    mac.update(member_pubkey);
    mac.update(&key_epoch.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(&digest[..TAG_LEN]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf;

    fn mvk() -> [u8; 32] {
        [0x42u8; 32]
    }
    fn sid() -> [u8; 32] {
        [0x01u8; 32]
    }
    fn cid() -> [u8; 32] {
        [0x02u8; 32]
    }

    /// Two computations with identical inputs MUST agree. Without this
    /// property, the indexer fan-out and subscriber-side matching
    /// fundamentally cannot work.
    #[test]
    fn match_tag_is_deterministic() {
        let k = kdf::derive_match_tag_key(&mvk(), &sid(), 0);
        let a = compute_match_tag(&k, &cid(), 0);
        let b = compute_match_tag(&k, &cid(), 0);
        assert_eq!(a, b);
        assert_eq!(a.len(), TAG_LEN);
    }

    /// Tags for the same `(server, channel)` under different epochs
    /// MUST diverge. This is what enables forward-secret fan-out
    /// after `KEY_ROTATE`.
    #[test]
    fn match_tag_changes_per_epoch() {
        let k1 = kdf::derive_match_tag_key(&mvk(), &sid(), 1);
        let k2 = kdf::derive_match_tag_key(&mvk(), &sid(), 2);
        let t1 = compute_match_tag(&k1, &cid(), 1);
        let t2 = compute_match_tag(&k2, &cid(), 2);
        assert_ne!(t1, t2);
    }

    /// Tags for two different channels under the same epoch MUST
    /// differ — otherwise the indexer would route events into the
    /// wrong bucket.
    #[test]
    fn match_tag_separates_channels() {
        let k = kdf::derive_match_tag_key(&mvk(), &sid(), 0);
        let t1 = compute_match_tag(&k, &[0x10; 32], 0);
        let t2 = compute_match_tag(&k, &[0x11; 32], 0);
        assert_ne!(t1, t2);
    }

    /// `match_tag` and `member_tag` MUST never collide for the same
    /// inputs — the domain prefix is what prevents this even if a
    /// caller (incorrectly) reuses an HMAC key across both call
    /// sites.
    #[test]
    fn match_and_member_domains_are_separated() {
        let shared_key = [0x99u8; 32];
        let cid32 = [0x02u8; 32];
        let match_tag_out = compute_match_tag(&shared_key, &cid32, 0);
        let member_tag_out = compute_member_tag(&shared_key, &cid32, 0);
        assert_ne!(match_tag_out, member_tag_out);
    }

    /// Different members in the same server / epoch MUST yield
    /// different `member_tag` values. Without this, the indexer
    /// cannot tell two members apart and the sealed-membership
    /// projection is broken.
    #[test]
    fn member_tag_separates_members() {
        let k = kdf::derive_member_tag_key(&mvk(), &sid(), 0);
        let t1 = compute_member_tag(&k, &[0x21u8; 32], 0);
        let t2 = compute_member_tag(&k, &[0x22u8; 32], 0);
        assert_ne!(t1, t2);
    }

    /// Golden vector — pins the exact byte output for the documented
    /// inputs. Regenerate intentionally on cross-runtime release.
    #[test]
    fn match_tag_golden_vector() {
        let key = [0u8; 32];
        let cid = [0u8; 32];
        let tag = compute_match_tag(&key, &cid, 0);
        let expected = hex_literal::hex!("bd8672353c3f211f263956c4a2c0f848");
        assert_eq!(tag, expected, "match-tag golden vector drift");
    }
}
