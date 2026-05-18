//! `komms-crypto` — v1.1 encryption primitives.
//!
//! This crate implements the cryptographic building blocks for the
//! Komms v1.1 wire format (Toccata-era) as specified in:
//!
//! - `planning-docs/komms_protocol_v_1_1.md` §§1, 12, 13
//! - `ARCHITECTURE_DECISIONS.md` ADR-012 (encrypted on-chain identifiers
//!   + sealed `MemberJoin`)
//! - `komms-protocol/05_ENCRYPTION_POSTURE.md` (threat model + non-goals)
//!
//! ## Cryptographic stack
//!
//! - HKDF-SHA-256 for key derivation (RFC 5869).
//! - HMAC-SHA-256 truncated to 16 bytes for indexer match tags and
//!   sealed-membership linkable tags (FIPS 198-1).
//! - AES-256-GCM for AEAD field encryption (NIST SP 800-38D), with
//!   96-bit nonces drawn from the platform CSPRNG via [`rand_core`].
//! - Constant-time comparisons via `subtle`; key clearing via
//!   `zeroize`.
//!
//! Algorithm choices are locked to one audited RustCrypto generation
//! (digest 0.10 / aead 0.5) so the dependency closure cannot pick up
//! pre-release alternatives accidentally. See workspace `Cargo.toml`
//! for the version pin policy.
//!
//! ## Domain separation
//!
//! Every HKDF expansion and HMAC computation is domain-separated using
//! a versioned ASCII tag prefix (`komms/v1.1/…`). This makes it
//! impossible to repurpose a derived key from one context as the key
//! for another. See [`kdf::KdfDomain`] for the canonical list and the
//! per-domain rationale.
//!
//! ## Public API
//!
//! - [`kdf`] — domain-separated HKDF-SHA-256 with typed call sites
//!   (per-channel DEK, match-tag key, member-tag key, member-sealed
//!   key).
//! - [`tags`] — fixed-length HMAC tag helpers (`compute_match_tag`,
//!   `compute_member_tag`).
//! - [`aead`] — AES-256-GCM seal / open with explicit AAD binding.
//! - [`sealed`] — `nonce || ciphertext || aead_tag` wire format used
//!   by every v1.1 encrypted-counterpart field on the chain.
//! - [`state_hash`] — BLAKE2b-256 cumulative state hash chain for the
//!   plurality indexer cross-check (`komms_protocol_v_1_1.md` §11.1).
//!
//! ## Non-goals
//!
//! - No bLSAG / ring signatures (Phase 3, ADR-013) — that lands in a
//!   separate `komms-sealed-sender` crate when Phase 3 ships.
//! - No covenant scripting (EP-028) — see `kaspa-txscript` builders.
//! - No DM lane crypto (`enc_scheme = 1` wallet-x25519) — that lives in
//!   the client wallet code path and uses a separate primitives set.

#![forbid(unsafe_code)]

pub mod aead;
pub mod kdf;
pub mod request_auth;
pub mod sealed;
pub mod state_hash;
pub mod tags;

pub use aead::{AEAD_TAG_LEN, AeadError, NONCE_LEN, open_field, seal_field};
pub use kdf::{
    KdfDomain, derive_channel_dek, derive_match_tag_key, derive_member_sealed_key,
    derive_member_tag_key,
};
pub use sealed::{SealedField, SealedFieldError};
pub use state_hash::{ProjectedEvent, STATE_HASH_LEN, state_hash_genesis, state_hash_next};
pub use tags::{TAG_LEN, compute_match_tag, compute_member_tag};

/// Convenience alias for the 32-byte per-server master viewing key.
///
/// Conceptually a symmetric secret rotated on `KEY_ROTATE` (event
/// type 25). All v1.1 server-scoped derivations start from this key
/// and a per-epoch counter, so passing it around as a typed alias
/// makes intent explicit at call sites.
pub type MasterViewingKey = [u8; 32];

/// 32-byte AES-256 key produced by [`derive_channel_dek`] and friends.
pub type DataEncryptionKey = [u8; 32];
