//! Per-caller HMAC-SHA-256 request authentication.
//!
//! S2 + S4 of
//! [`komms-planning/AUDIT_2026-05-17.md §6`](komms-planning/AUDIT_2026-05-17.md).
//!
//! ## Wire format
//!
//! HMAC input (newline-separated, no trailing newline):
//!
//! ```text
//! caller      || "\n"     // "gateway", "validator:5G..."
//! ts_decimal  || "\n"     // unix seconds (decimal)
//! method      || "\n"     // HTTP verb
//! path        || "\n"     // URL path (without scheme/host/query)
//! body_bytes              // request body (empty on WS upgrade)
//! ```
//!
//! Required HTTP headers on every authenticated request (HTTP POST
//! AND WebSocket upgrade GET):
//!
//! - `X-Komms-Caller` — caller id naming the entry in the receiver's
//!   secrets map (e.g. `"gateway"` or `"validator:5GabcDEF..."`).
//! - `X-Komms-Ts` — unix seconds, decimal.
//! - `X-Komms-Sig` — hex HMAC-SHA-256.
//!
//! ## Rationale
//!
//! The pre-v1.4 baseline shared one HMAC secret across every caller
//! (gateway, validator-S-probe, future indexer-read clients), so a
//! hostile party who learned the secret could forge envelopes for
//! the other. Splitting the secret per-caller closes the seam: a
//! leaked validator secret cannot forge a gateway-submit and vice
//! versa.
//!
//! ## Why this lives in the `crypto` crate
//!
//! Both `komms-miner-submit` (HTTP POST `/v1/submit`) and the
//! `indexer` binary (WebSocket upgrade `/komms/events/stream`) need
//! the same `verify` semantics; centralising the implementation
//! here means one source of truth and one set of tests instead of
//! two parallel copies that can silently drift.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Outcome of a successful verification. `caller` is the matched
/// entry from the secrets map (use it for attribution + audit logs).
#[derive(Debug, Clone)]
pub struct VerifiedCaller {
    pub caller: String,
}

/// Why a verification failed. Deliberately uninformative outside
/// the variant name so the wire-level error surface doesn't leak
/// which dimension failed (a probing attacker should not be able
/// to learn "wrong caller" vs "wrong signature" via response
/// strings).
#[derive(Debug, thiserror::Error)]
pub enum RequestAuthError {
    #[error("missing X-Komms-Caller header")]
    MissingCaller,
    #[error("missing X-Komms-Ts header")]
    MissingTimestamp,
    #[error("missing X-Komms-Sig header")]
    MissingSignature,
    #[error("malformed X-Komms-Ts header")]
    MalformedTimestamp,
    #[error("malformed X-Komms-Sig header")]
    MalformedSignature,
    #[error("clock skew")]
    ClockSkew,
    #[error("timestamp drift {drift_secs}s exceeds allowed {allowed_secs}s")]
    TimestampDrift { drift_secs: u64, allowed_secs: u64 },
    #[error("empty X-Komms-Caller")]
    EmptyCaller,
    #[error("unknown X-Komms-Caller")]
    UnknownCaller,
    #[error("HMAC mismatch")]
    HmacMismatch,
}

/// Compute the canonical HMAC-input bytes for a request. Exposed so
/// the gateway / validator signer-side implementations cannot
/// silently drift from the verifier-side input layout.
pub fn canonical_input(
    caller: &str,
    ts_decimal: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        caller.len() + ts_decimal.len() + method.len() + path.len() + body.len() + 4,
    );
    payload.extend_from_slice(caller.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(ts_decimal.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(method.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(path.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(body);
    payload
}

/// Sign a request under `secret` with the canonical input layout
/// (see [`canonical_input`]). Returns the hex-encoded signature
/// callers put into the `X-Komms-Sig` header.
pub fn sign(
    secret: &[u8],
    caller: &str,
    ts_decimal: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> String {
    let payload = canonical_input(caller, ts_decimal, method, path, body);
    let mut mac =
        HmacSha256::new_from_slice(secret).expect("HmacSha256 accepts arbitrary key length");
    mac.update(&payload);
    faster_hex::hex_string(&mac.finalize().into_bytes())
}

/// Verify the per-caller HMAC envelope of an incoming request. On
/// success returns the matched caller id; on failure returns a
/// typed [`RequestAuthError`].
//
// Eight parameters intentionally — splitting the verify surface into a
// `Request` builder struct buys no readability here and would force every
// caller in the gateway + miner-submit hot paths to allocate a temporary
// just to satisfy a lint. The signature is part of the public API; the
// allow is local to the function.
#[allow(clippy::too_many_arguments)]
pub fn verify(
    secrets: &BTreeMap<String, Vec<u8>>,
    method: &str,
    path: &str,
    body: &[u8],
    caller_header: Option<&str>,
    ts_header: Option<&str>,
    sig_header: Option<&str>,
    skew_secs: u64,
) -> Result<VerifiedCaller, RequestAuthError> {
    let caller = caller_header.ok_or(RequestAuthError::MissingCaller)?.trim();
    if caller.is_empty() {
        return Err(RequestAuthError::EmptyCaller);
    }
    let ts_str = ts_header.ok_or(RequestAuthError::MissingTimestamp)?;
    let sig_hex = sig_header.ok_or(RequestAuthError::MissingSignature)?;

    let ts: i64 = ts_str
        .parse()
        .map_err(|_| RequestAuthError::MalformedTimestamp)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RequestAuthError::ClockSkew)?
        .as_secs() as i64;
    let drift = (now - ts).unsigned_abs();
    if drift > skew_secs {
        return Err(RequestAuthError::TimestampDrift {
            drift_secs: drift,
            allowed_secs: skew_secs,
        });
    }

    let secret = secrets.get(caller).ok_or(RequestAuthError::UnknownCaller)?;

    let payload = canonical_input(caller, ts_str, method, path, body);
    let mut mac =
        HmacSha256::new_from_slice(secret).expect("HmacSha256 accepts arbitrary key length");
    mac.update(&payload);
    let expected = mac.finalize().into_bytes();

    let mut actual = vec![0u8; expected.len()];
    faster_hex::hex_decode(sig_hex.trim().as_bytes(), &mut actual)
        .map_err(|_| RequestAuthError::MalformedSignature)?;

    if expected.ct_eq(&actual).into() {
        Ok(VerifiedCaller {
            caller: caller.to_string(),
        })
    } else {
        Err(RequestAuthError::HmacMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets() -> BTreeMap<String, Vec<u8>> {
        let mut m = BTreeMap::new();
        m.insert("gateway".to_string(), vec![0x11u8; 32]);
        m.insert("validator:5G".to_string(), vec![0x22u8; 32]);
        m
    }

    fn now_ts() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    #[test]
    fn canonical_input_layout_is_documented() {
        let inp = canonical_input("gw", "100", "POST", "/v1/submit", b"body");
        // 5 fields separated by 4 newlines, body at the tail.
        let expected: Vec<u8> = b"gw\n100\nPOST\n/v1/submit\nbody".to_vec();
        assert_eq!(inp, expected);
    }

    #[test]
    fn sign_verify_roundtrip_under_gateway_secret() {
        let s = secrets();
        let ts = now_ts();
        let body = br#"{"hello":"world"}"#;
        let sig = sign(
            &s["gateway"],
            "gateway",
            &ts.to_string(),
            "POST",
            "/v1/submit",
            body,
        );
        let out = verify(
            &s,
            "POST",
            "/v1/submit",
            body,
            Some("gateway"),
            Some(&ts.to_string()),
            Some(&sig),
            300,
        )
        .unwrap();
        assert_eq!(out.caller, "gateway");
    }

    /// S2 invariant: validator's secret cannot forge a gateway
    /// envelope even though the wire format embeds the caller name.
    #[test]
    fn validator_secret_cannot_forge_gateway_caller() {
        let s = secrets();
        let ts = now_ts();
        let body = br#"{}"#;
        let sig = sign(
            &s["validator:5G"],
            "gateway",
            &ts.to_string(),
            "POST",
            "/v1/submit",
            body,
        );
        let err = verify(
            &s,
            "POST",
            "/v1/submit",
            body,
            Some("gateway"),
            Some(&ts.to_string()),
            Some(&sig),
            300,
        )
        .unwrap_err();
        assert!(matches!(err, RequestAuthError::HmacMismatch));
    }

    /// S4 wire surface: WS-upgrade requests are signed with method
    /// "GET" and the upgrade path. A signature for `/v1/submit`
    /// MUST NOT validate against `/komms/events/stream`.
    #[test]
    fn submit_signature_does_not_authenticate_ws_upgrade() {
        let s = secrets();
        let ts = now_ts();
        let sig = sign(
            &s["gateway"],
            "gateway",
            &ts.to_string(),
            "POST",
            "/v1/submit",
            b"",
        );
        let err = verify(
            &s,
            "GET",
            "/komms/events/stream",
            b"",
            Some("gateway"),
            Some(&ts.to_string()),
            Some(&sig),
            300,
        )
        .unwrap_err();
        assert!(matches!(err, RequestAuthError::HmacMismatch));
    }

    #[test]
    fn rejects_unknown_caller() {
        let s = secrets();
        let ts = now_ts();
        let sig = "00".repeat(32);
        let err = verify(
            &s,
            "POST",
            "/v1/submit",
            b"",
            Some("attacker"),
            Some(&ts.to_string()),
            Some(&sig),
            300,
        )
        .unwrap_err();
        assert!(matches!(err, RequestAuthError::UnknownCaller));
    }

    #[test]
    fn rejects_skewed_timestamp() {
        let s = secrets();
        let ts = now_ts() - 10_000;
        let body = b"";
        let sig = sign(
            &s["gateway"],
            "gateway",
            &ts.to_string(),
            "POST",
            "/x",
            body,
        );
        let err = verify(
            &s,
            "POST",
            "/x",
            body,
            Some("gateway"),
            Some(&ts.to_string()),
            Some(&sig),
            300,
        )
        .unwrap_err();
        assert!(matches!(err, RequestAuthError::TimestampDrift { .. }));
    }
}
