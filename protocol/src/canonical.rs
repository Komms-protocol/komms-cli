//! Canonical CBOR enforcement (RFC 8949 §4.2, Komms profile).
//!
//! This module walks the raw CBOR bytes of a KOMMS payload and rejects
//! anything that is not in canonical form. Canonicality matters here for
//! three reasons:
//!
//!   1. **Signature stability.** Key 11 `sig` covers the canonical CBOR
//!      bytes of the map without key 11. If a parser accepts non-canonical
//!      input, a different re-encoder produces different bytes and the
//!      signature won't reverify.
//!   2. **Content-hash parity.** `content_hash` and `mid` derivations
//!      depend on byte-stable inputs across Rust, TypeScript, and any
//!      future implementer.
//!   3. **Indexer fairness.** Two encoders producing slightly different
//!      bytes for the same logical event would resolve to different
//!      records in the indexer, breaking dedupe.
//!
//! ## Komms canonical profile (stricter than RFC 8949 §4.2.1)
//!
//! - Map keys MUST be unsigned integers (major type 0).
//! - Keys MUST appear in strictly ascending numeric order.
//! - Duplicate keys are rejected.
//! - Lengths MUST use the shortest possible encoding.
//! - Indefinite-length items are forbidden.
//! - Tagged items (major type 6) are forbidden.
//! - Floating-point values are forbidden.
//! - Simple values are restricted to `false`(20), `true`(21), `null`(22),
//!   `undefined`(23).
//! - Recursion depth is bounded.

use thiserror::Error;

/// Maximum CBOR nesting depth allowed in a single KOMMS event. Generous
/// enough for the spec but tight enough to bound parser memory.
const MAX_NESTING_DEPTH: u32 = 8;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CanonicalError {
    #[error("CBOR truncated at offset {0}")]
    Truncated(usize),
    #[error("CBOR depth exceeded MAX_NESTING_DEPTH({MAX_NESTING_DEPTH}) at offset {0}")]
    NestingTooDeep(usize),
    #[error("indefinite-length items are forbidden (offset {0})")]
    IndefiniteLength(usize),
    #[error("non-shortest-form length/argument encoding at offset {0}")]
    NonShortestForm(usize),
    #[error("map keys must be unsigned integers (offset {0})")]
    NonUintKey(usize),
    #[error("map keys must be in strictly ascending order (offset {0})")]
    KeysOutOfOrder(usize),
    #[error("duplicate map key {key} (offset {offset})")]
    DuplicateKey { key: u64, offset: usize },
    #[error("tagged items are forbidden (tag {tag} at offset {offset})")]
    TaggedItem { tag: u64, offset: usize },
    #[error("floating-point values are forbidden (offset {0})")]
    FloatForbidden(usize),
    #[error("invalid CBOR simple value 0x{value:02x} at offset {offset}")]
    InvalidSimpleValue { value: u8, offset: usize },
    #[error("trailing bytes after CBOR root item (offset {0})")]
    TrailingBytes(usize),
    #[error("reserved CBOR additional-info argument 28/29/30 at offset {0}")]
    ReservedArgument(usize),
}

/// Validate that `cbor` is a single canonical CBOR item, exhausting the
/// slice. Returns `Ok(())` on success.
pub fn validate_canonical(cbor: &[u8]) -> Result<(), CanonicalError> {
    let mut pos: usize = 0;
    walk_item(cbor, &mut pos, 0)?;
    if pos != cbor.len() {
        return Err(CanonicalError::TrailingBytes(pos));
    }
    Ok(())
}

fn walk_item(cbor: &[u8], pos: &mut usize, depth: u32) -> Result<(), CanonicalError> {
    if depth > MAX_NESTING_DEPTH {
        return Err(CanonicalError::NestingTooDeep(*pos));
    }
    let initial_off = *pos;
    let initial = read_u8(cbor, pos)?;
    let major = initial >> 5;
    let arg = initial & 0x1F;

    // Indefinite-length is encoded as additional-info = 31 (0x1F).
    if arg == 0x1F {
        return Err(CanonicalError::IndefiniteLength(initial_off));
    }
    if (28..=30).contains(&arg) {
        return Err(CanonicalError::ReservedArgument(initial_off));
    }

    match major {
        0 | 1 => {
            // unsigned int / negative int — argument is the value
            let _value = read_argument(cbor, pos, arg, initial_off)?;
            Ok(())
        }
        2 | 3 => {
            // byte string / text string — argument is the length
            let len = read_argument(cbor, pos, arg, initial_off)? as usize;
            skip_bytes(cbor, pos, len)?;
            Ok(())
        }
        4 => {
            // array
            let count = read_argument(cbor, pos, arg, initial_off)?;
            for _ in 0..count {
                walk_item(cbor, pos, depth + 1)?;
            }
            Ok(())
        }
        5 => {
            // map
            let count = read_argument(cbor, pos, arg, initial_off)?;
            let mut prev_key: Option<u64> = None;
            for _ in 0..count {
                let key_off = *pos;
                let key = read_uint_key(cbor, pos)?;
                if let Some(p) = prev_key {
                    if key <= p {
                        if key == p {
                            return Err(CanonicalError::DuplicateKey {
                                key,
                                offset: key_off,
                            });
                        }
                        return Err(CanonicalError::KeysOutOfOrder(key_off));
                    }
                }
                prev_key = Some(key);
                walk_item(cbor, pos, depth + 1)?;
            }
            Ok(())
        }
        6 => {
            // tag — forbidden in Komms profile
            let tag = read_argument(cbor, pos, arg, initial_off)?;
            Err(CanonicalError::TaggedItem {
                tag,
                offset: initial_off,
            })
        }
        7 => match initial {
            0xF4 | 0xF5 | 0xF6 | 0xF7 => Ok(()),
            0xF9 | 0xFA | 0xFB => Err(CanonicalError::FloatForbidden(initial_off)),
            _ => Err(CanonicalError::InvalidSimpleValue {
                value: initial,
                offset: initial_off,
            }),
        },
        _ => unreachable!("major is 3 bits"),
    }
}

/// Read an unsigned-int map key. Inlined version of `walk_item` for the
/// major-type-0 path — returns the decoded numeric value so map ordering
/// can be enforced.
fn read_uint_key(cbor: &[u8], pos: &mut usize) -> Result<u64, CanonicalError> {
    let initial_off = *pos;
    let initial = read_u8(cbor, pos)?;
    let major = initial >> 5;
    let arg = initial & 0x1F;
    if major != 0 {
        return Err(CanonicalError::NonUintKey(initial_off));
    }
    if arg == 0x1F {
        return Err(CanonicalError::IndefiniteLength(initial_off));
    }
    if (28..=30).contains(&arg) {
        return Err(CanonicalError::ReservedArgument(initial_off));
    }
    read_argument(cbor, pos, arg, initial_off)
}

/// Read the additional-info "argument" with shortest-form enforcement.
fn read_argument(
    cbor: &[u8],
    pos: &mut usize,
    arg: u8,
    initial_off: usize,
) -> Result<u64, CanonicalError> {
    let value: u64 = match arg {
        0..=23 => arg as u64,
        24 => {
            let v = read_u8(cbor, pos)? as u64;
            if v < 24 {
                return Err(CanonicalError::NonShortestForm(initial_off));
            }
            v
        }
        25 => {
            let v = read_u16_be(cbor, pos)? as u64;
            if v <= 0xFF {
                return Err(CanonicalError::NonShortestForm(initial_off));
            }
            v
        }
        26 => {
            let v = read_u32_be(cbor, pos)? as u64;
            if v <= 0xFFFF {
                return Err(CanonicalError::NonShortestForm(initial_off));
            }
            v
        }
        27 => {
            let v = read_u64_be(cbor, pos)?;
            if v <= 0xFFFF_FFFF {
                return Err(CanonicalError::NonShortestForm(initial_off));
            }
            v
        }
        _ => return Err(CanonicalError::ReservedArgument(initial_off)),
    };
    Ok(value)
}

#[inline]
fn read_u8(cbor: &[u8], pos: &mut usize) -> Result<u8, CanonicalError> {
    let p = *pos;
    if p >= cbor.len() {
        return Err(CanonicalError::Truncated(p));
    }
    let v = cbor[p];
    *pos = p + 1;
    Ok(v)
}

#[inline]
fn read_u16_be(cbor: &[u8], pos: &mut usize) -> Result<u16, CanonicalError> {
    let p = *pos;
    if p + 2 > cbor.len() {
        return Err(CanonicalError::Truncated(p));
    }
    let v = u16::from_be_bytes([cbor[p], cbor[p + 1]]);
    *pos = p + 2;
    Ok(v)
}

#[inline]
fn read_u32_be(cbor: &[u8], pos: &mut usize) -> Result<u32, CanonicalError> {
    let p = *pos;
    if p + 4 > cbor.len() {
        return Err(CanonicalError::Truncated(p));
    }
    let v = u32::from_be_bytes([cbor[p], cbor[p + 1], cbor[p + 2], cbor[p + 3]]);
    *pos = p + 4;
    Ok(v)
}

#[inline]
fn read_u64_be(cbor: &[u8], pos: &mut usize) -> Result<u64, CanonicalError> {
    let p = *pos;
    if p + 8 > cbor.len() {
        return Err(CanonicalError::Truncated(p));
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&cbor[p..p + 8]);
    let v = u64::from_be_bytes(buf);
    *pos = p + 8;
    Ok(v)
}

#[inline]
fn skip_bytes(cbor: &[u8], pos: &mut usize, n: usize) -> Result<(), CanonicalError> {
    let p = *pos;
    let end = p.checked_add(n).ok_or(CanonicalError::Truncated(p))?;
    if end > cbor.len() {
        return Err(CanonicalError::Truncated(p));
    }
    *pos = end;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(v: ciborium::Value) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&v, &mut buf).unwrap();
        buf
    }

    #[test]
    fn canonical_simple_map_ok() {
        // { 0:0, 1:4, 8:false }
        let bytes = enc(ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(0.into()),
                ciborium::Value::Integer(0.into()),
            ),
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Integer(4.into()),
            ),
            (
                ciborium::Value::Integer(8.into()),
                ciborium::Value::Bool(false),
            ),
        ]));
        assert_eq!(validate_canonical(&bytes), Ok(()));
    }

    #[test]
    fn out_of_order_keys_rejected() {
        // { 1:0, 0:0 } — descending
        let bytes = enc(ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Integer(0.into()),
            ),
            (
                ciborium::Value::Integer(0.into()),
                ciborium::Value::Integer(0.into()),
            ),
        ]));
        assert!(matches!(
            validate_canonical(&bytes),
            Err(CanonicalError::KeysOutOfOrder(_))
        ));
    }

    #[test]
    fn duplicate_keys_rejected() {
        let bytes = enc(ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(0.into()),
                ciborium::Value::Integer(0.into()),
            ),
            (
                ciborium::Value::Integer(0.into()),
                ciborium::Value::Integer(0.into()),
            ),
        ]));
        assert!(matches!(
            validate_canonical(&bytes),
            Err(CanonicalError::DuplicateKey { .. })
        ));
    }

    #[test]
    fn non_uint_key_rejected() {
        // { "x": 0 }
        let bytes = enc(ciborium::Value::Map(vec![(
            ciborium::Value::Text("x".into()),
            ciborium::Value::Integer(0.into()),
        )]));
        assert!(matches!(
            validate_canonical(&bytes),
            Err(CanonicalError::NonUintKey(_))
        ));
    }

    #[test]
    fn float_rejected() {
        let bytes = enc(ciborium::Value::Float(1.5));
        assert!(matches!(
            validate_canonical(&bytes),
            Err(CanonicalError::FloatForbidden(_))
        ));
    }

    #[test]
    fn tag_rejected() {
        let bytes = enc(ciborium::Value::Tag(0, Box::new(ciborium::Value::Integer(1.into()))));
        assert!(matches!(
            validate_canonical(&bytes),
            Err(CanonicalError::TaggedItem { .. })
        ));
    }

    #[test]
    fn non_shortest_form_uint_rejected() {
        // 0x18 0x01 — encodes the value 1 in a 1-byte argument form (instead of the
        // 1-byte shortest form 0x01). Should be rejected as non-shortest.
        let bytes = vec![0x18, 0x01];
        assert_eq!(
            validate_canonical(&bytes),
            Err(CanonicalError::NonShortestForm(0))
        );
    }

    #[test]
    fn indefinite_length_rejected() {
        // 0x5F (indefinite-length byte string) ... 0xFF (break)
        let bytes = vec![0x5F, 0x40, 0xFF];
        assert!(matches!(
            validate_canonical(&bytes),
            Err(CanonicalError::IndefiniteLength(_))
        ));
    }

    #[test]
    fn trailing_bytes_rejected() {
        let mut bytes = enc(ciborium::Value::Integer(0.into()));
        bytes.push(0xAA);
        assert!(matches!(
            validate_canonical(&bytes),
            Err(CanonicalError::TrailingBytes(_))
        ));
    }

    #[test]
    fn truncated_rejected() {
        // 0x18 missing the trailing byte
        let bytes = vec![0x18];
        assert!(matches!(
            validate_canonical(&bytes),
            Err(CanonicalError::Truncated(_))
        ));
    }

    #[test]
    fn deep_nesting_rejected() {
        // Build a nested array structure deeper than MAX_NESTING_DEPTH
        let mut v = ciborium::Value::Integer(0.into());
        for _ in 0..(MAX_NESTING_DEPTH as usize + 2) {
            v = ciborium::Value::Array(vec![v]);
        }
        let bytes = enc(v);
        assert!(matches!(
            validate_canonical(&bytes),
            Err(CanonicalError::NestingTooDeep(_))
        ));
    }
}
