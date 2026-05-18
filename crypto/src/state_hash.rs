//! Cumulative state hash for the plurality indexer cross-check.
//!
//! Spec: `planning-docs/komms_protocol_v_1_1.md` §11.1 + ADR-015 §1.
//! Used by v1.1 indexers to produce a per-(accepting-block) hash that
//! N independently-run indexers MUST agree on, byte-for-byte, if they
//! have projected the same set of Komms events. Clients query several
//! indexers in parallel and treat the highest accepting-DAA where the
//! state hashes converge as their "confirmed tip" (§11.3).
//!
//! ## Algorithm
//!
//! ```text
//! state_hash_block_0 = BLAKE2b-256(
//!     "KOMMS_STATE_GENESIS_v1.1" || 0x00 * 32
//! )
//! state_hash_block_N = BLAKE2b-256(
//!     state_hash_block_{N-1} ||
//!     canonical_cbor(
//!         sorted_by_tx_id(
//!             projected_events_in_block_N
//!         )
//!     )
//! )
//! ```
//!
//! - `BLAKE2b-256` is BLAKE2b with the output length parameter set to
//!   32 bytes (RFC 7693 §3.2). Chosen over SHA-256 for its native
//!   support for variable output length and its higher
//!   software-throughput on common server CPUs (relevant for indexer
//!   replay).
//! - `canonical_cbor(sorted_by_tx_id(events))` is a CBOR array (major
//!   type 4) of the projected event maps in ascending `tx_id` byte
//!   order. The array header uses the canonical
//!   shortest-encoding-length form per RFC 8949 §4.2.1. Each element is
//!   the indexer's already-canonical CBOR projection, copied verbatim
//!   into the array body — this crate does not re-encode element bytes
//!   so a single bit drift in projection logic surfaces as a
//!   divergence rather than getting masked by canonicalisation.
//!
//! ## Caller contract
//!
//! The CALLER (the indexer) is responsible for:
//!
//! 1. Projecting each KOMMS event into the indexer's canonical CBOR map
//!    per v1.1 §13 / §14 (typed projections, with v1.1 fields included
//!    where present).
//! 2. Computing each event's `tx_id` as the on-chain 32-byte Kaspa
//!    transaction id (NOT a derived hash — direct txid, per
//!    `komms_protocol_v_1_1.md` §9).
//! 3. Passing only the events whose `accepting_block_hash` matches the
//!    block being summarised. Re-orgs invalidate the chain and require
//!    recomputation from the most recent stable ancestor.
//!
//! This crate's job is purely the hash chain — nothing about Kaspa
//! consensus, block boundaries, or storage. Those concerns live in
//! the `indexer-actors` crate.

use blake2::Blake2b;
use blake2::digest::{Digest, consts::U32};

/// On-wire length of every state hash: 32 bytes / 256 bits.
pub const STATE_HASH_LEN: usize = 32;

/// Domain-separation prefix for the genesis state hash. Locks the
/// hash chain to the v1.1 era so a future v1.2 algorithm bump cannot
/// silently replay the v1.1 history with a different downstream
/// algorithm. Exactly as specified in `komms_protocol_v_1_1.md` §11.1.
pub const GENESIS_DOMAIN: &[u8] = b"KOMMS_STATE_GENESIS_v1.1";

/// One projected KOMMS event contributing to a block's state hash.
///
/// `canonical_cbor` MUST be the byte-exact canonical CBOR encoding of
/// the event's indexer projection (RFC 8949 §4.2.1). Passing
/// non-canonical bytes here cannot produce an incorrect *individual*
/// state hash (the crate hashes whatever it is given), but it WILL
/// cause two indexers to disagree, which is the exact failure mode
/// the cross-check is meant to detect — so callers should validate
/// canonicality upstream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectedEvent {
    /// 32-byte Kaspa transaction id. Becomes the sort key.
    pub tx_id: [u8; 32],
    /// Indexer's canonical-CBOR projection of the event. Treated as
    /// opaque bytes by this crate.
    pub canonical_cbor: Vec<u8>,
}

type Blake2b256 = Blake2b<U32>;

/// Compute the genesis state hash. Always returns the same 32-byte
/// constant; provided as a function so the canonical input is
/// embedded in one place and visible to documentation.
///
/// Indexers MUST anchor their hash chain to this value.
pub fn state_hash_genesis() -> [u8; STATE_HASH_LEN] {
    let mut hasher = Blake2b256::new();
    hasher.update(GENESIS_DOMAIN);
    hasher.update([0u8; STATE_HASH_LEN]);
    hasher.finalize().into()
}

/// Compute the next state hash in the chain. `prior` is the previous
/// block's state hash (or [`state_hash_genesis`] for the first block
/// containing any Komms event). `events` is the set of projected
/// events accepted in this block, in any order — this function sorts
/// them by `tx_id` before hashing.
///
/// Returns a fresh 32-byte hash. Idempotent: identical `(prior,
/// events)` inputs MUST always produce identical output.
pub fn state_hash_next(
    prior: &[u8; STATE_HASH_LEN],
    events: &[ProjectedEvent],
) -> [u8; STATE_HASH_LEN] {
    let mut indices: Vec<usize> = (0..events.len()).collect();
    indices.sort_by(|&a, &b| events[a].tx_id.cmp(&events[b].tx_id));

    let mut hasher = Blake2b256::new();
    hasher.update(prior);
    // CBOR array header (major type 4) with the canonical
    // shortest-length encoding. Then the verbatim canonical-CBOR
    // bytes of each event in sorted order.
    let header = encode_cbor_uint_header(0x80, events.len() as u64);
    hasher.update(&header);
    for &i in &indices {
        hasher.update(&events[i].canonical_cbor);
    }
    hasher.finalize().into()
}

/// Encode a CBOR major-type uint head with the canonical
/// shortest-length form per RFC 8949 §4.2.1. `major_type_byte` is the
/// high 3 bits set (e.g. `0x80` for array, `0x40` for byte string).
///
/// Visible to tests via the wider crate.
fn encode_cbor_uint_header(major_type_byte: u8, value: u64) -> Vec<u8> {
    let initial = major_type_byte & 0xE0;
    if value < 24 {
        vec![initial | (value as u8)]
    } else if value < 0x100 {
        vec![initial | 24, value as u8]
    } else if value < 0x10000 {
        let mut out = vec![initial | 25];
        out.extend_from_slice(&(value as u16).to_be_bytes());
        out
    } else if value < 0x1_0000_0000 {
        let mut out = vec![initial | 26];
        out.extend_from_slice(&(value as u32).to_be_bytes());
        out
    } else {
        let mut out = vec![initial | 27];
        out.extend_from_slice(&value.to_be_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe(tx_id: [u8; 32], body: &[u8]) -> ProjectedEvent {
        ProjectedEvent {
            tx_id,
            canonical_cbor: body.to_vec(),
        }
    }

    /// Genesis is a fixed constant — pinned by golden vector to lock
    /// the algorithm. Regenerate intentionally only on coordinated
    /// cross-runtime release.
    #[test]
    fn genesis_golden_vector() {
        let g = state_hash_genesis();
        let expected =
            hex_literal::hex!("dd7ef76dd52e04ece3c50d238bca0946edee687ef7e3d2971f3390e47252404e");
        assert_eq!(g, expected, "state-hash genesis vector drift");
    }

    /// Two independent calls MUST agree. Without this, the entire
    /// plurality cross-check is meaningless.
    #[test]
    fn next_is_deterministic() {
        let prior = state_hash_genesis();
        let events = vec![pe([0x01; 32], b"event-a"), pe([0x02; 32], b"event-b")];
        let a = state_hash_next(&prior, &events);
        let b = state_hash_next(&prior, &events);
        assert_eq!(a, b);
    }

    /// Sort independence — events passed in any order MUST yield the
    /// same hash. This decouples the algorithm from each indexer's
    /// internal accept order.
    #[test]
    fn sort_order_is_normalised() {
        let prior = state_hash_genesis();
        let in_order = vec![
            pe([0x01; 32], b"a"),
            pe([0x02; 32], b"b"),
            pe([0x03; 32], b"c"),
        ];
        let scrambled = vec![
            pe([0x02; 32], b"b"),
            pe([0x03; 32], b"c"),
            pe([0x01; 32], b"a"),
        ];
        assert_eq!(
            state_hash_next(&prior, &in_order),
            state_hash_next(&prior, &scrambled)
        );
    }

    /// Changing the prior hash MUST change the output even with
    /// identical event sets. This is the chaining property; without
    /// it, an indexer could fork at block N and re-converge at N+1.
    #[test]
    fn prior_hash_propagates() {
        let p1 = [0xAAu8; 32];
        let p2 = [0xBBu8; 32];
        let events = vec![pe([0x01; 32], b"x")];
        assert_ne!(state_hash_next(&p1, &events), state_hash_next(&p2, &events));
    }

    /// Empty-block case (accepting block contained zero KOMMS events).
    /// The chain still advances by hashing `prior || 0x80` (CBOR array
    /// of length 0). Indexers MUST emit a state hash for every
    /// accepting block, even empty ones — otherwise the chain becomes
    /// ambiguous (which empty blocks were skipped?).
    #[test]
    fn empty_block_advances_chain() {
        let prior = state_hash_genesis();
        let h = state_hash_next(&prior, &[]);
        assert_ne!(h, prior);
        // Equivalent hand computation: BLAKE2b-256(genesis || 0x80)
        let mut hasher = Blake2b256::new();
        hasher.update(prior);
        hasher.update([0x80u8]);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(h, expected);
    }

    /// Changing a single event's payload (with the same tx_id) MUST
    /// flip the hash. Without this, the indexer could project two
    /// different shapes for one transaction and clients would never
    /// notice.
    #[test]
    fn projection_bit_flip_diverges() {
        let prior = state_hash_genesis();
        let a = state_hash_next(&prior, &[pe([0x01; 32], b"version_a_payload")]);
        let b = state_hash_next(&prior, &[pe([0x01; 32], b"version_b_payload")]);
        assert_ne!(a, b);
    }

    /// CBOR header canonicality: array length 0, 23, 24, 255, 256
    /// each yield the canonical shortest encoding per RFC 8949
    /// §4.2.1. This guards against a future contributor "optimising"
    /// the encoder into a non-canonical variant.
    #[test]
    fn cbor_array_header_canonical_lengths() {
        assert_eq!(encode_cbor_uint_header(0x80, 0), vec![0x80]);
        assert_eq!(encode_cbor_uint_header(0x80, 23), vec![0x97]);
        assert_eq!(encode_cbor_uint_header(0x80, 24), vec![0x98, 24]);
        assert_eq!(encode_cbor_uint_header(0x80, 255), vec![0x98, 255]);
        assert_eq!(encode_cbor_uint_header(0x80, 256), vec![0x99, 0x01, 0x00]);
        assert_eq!(
            encode_cbor_uint_header(0x80, 0xFFFF),
            vec![0x99, 0xFF, 0xFF]
        );
        assert_eq!(
            encode_cbor_uint_header(0x80, 0x10000),
            vec![0x9A, 0x00, 0x01, 0x00, 0x00]
        );
        assert_eq!(
            encode_cbor_uint_header(0x80, u64::MAX),
            vec![0x9B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
    }

    /// End-to-end golden vector pinning a multi-event block hash so
    /// any algorithm drift fails loudly. Regenerate intentionally only
    /// on coordinated cross-runtime release.
    #[test]
    fn next_block_golden_vector() {
        let prior = state_hash_genesis();
        let events = vec![
            pe([0x01u8; 32], b"\xa1\x00\x01"),
            pe([0x02u8; 32], b"\xa1\x00\x02"),
            pe([0x03u8; 32], b"\xa1\x00\x03"),
        ];
        let h = state_hash_next(&prior, &events);
        let expected =
            hex_literal::hex!("d55c7c5f4774bfa81aeb6870ad5e1d7a5398820510d096812dd5425a3de9ffbd");
        assert_eq!(h, expected, "state-hash next-block vector drift");
    }
}
