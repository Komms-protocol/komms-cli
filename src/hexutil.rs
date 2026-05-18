use anyhow::Context;

pub fn parse_hex32(s: &str) -> anyhow::Result<[u8; 32]> {
    let s = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    if s.len() != 64 {
        anyhow::bail!("expected 64 hex chars for 32 bytes, got {}", s.len());
    }
    let mut out = [0u8; 32];
    faster_hex::hex_decode(s.as_bytes(), &mut out).context("invalid hex")?;
    Ok(out)
}

pub fn parse_hex_bytes(s: &str) -> anyhow::Result<Vec<u8>> {
    let s = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    if !s.len().is_multiple_of(2) {
        anyhow::bail!("hex length must be even");
    }
    let mut out = vec![0u8; s.len() / 2];
    faster_hex::hex_decode(s.as_bytes(), &mut out).context("invalid hex")?;
    Ok(out)
}

pub fn parse_hex64_sig(s: &str) -> anyhow::Result<[u8; 64]> {
    let s = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    if s.len() != 128 {
        anyhow::bail!("expected 128 hex chars for ed25519 signature");
    }
    let mut out = [0u8; 64];
    faster_hex::hex_decode(s.as_bytes(), &mut out).context("invalid hex")?;
    Ok(out)
}

pub fn parse_hex32_pk(s: &str) -> anyhow::Result<[u8; 32]> {
    parse_hex32(s)
}
