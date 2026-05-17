# AGENTS.md — komms-cli

> **For**: AI coding agents (Cursor, Claude, Codex, etc.) and
> human contributors who want a fast orientation to this repo.
> **Status**: v0.1 (May 16, 2026).

This repo is the **Komms developer CLI** — a standalone Rust
binary (`komms`) for decoding, posting, reading, and inspecting
KOMMS payloads on Kaspa. It also houses the **vendored
`protocol` crate** that other Rust services (`komms-miner-submit`)
take as a path dependency until ADR-004 consolidates the
protocol crate into its own repo in Horizon B.

## Read this first (mandatory orientation order)

1. **[`komms-planning/KOMMS_PRINCIPLES.md`](../komms-planning/KOMMS_PRINCIPLES.md)**
   — §6 (canonical bytes are one path) is the critical
   principle for this repo, because the `protocol/` crate IS
   the canonical encoder.
2. **[`komms-planning/komms-protocol/02_MESSAGING_CONTENT.md`](../komms-planning/komms-protocol/02_MESSAGING_CONTENT.md)**
   — the spec the `protocol/` crate implements.
3. **ADR-004** in
   [`komms-planning/ARCHITECTURE_DECISIONS.md`](../komms-planning/ARCHITECTURE_DECISIONS.md)
   — "consolidate to one `komms-protocol` crate". Until that
   ships, this is the home of the spec implementation.

## Stack

- **Language**: Rust 2024 edition.
- **CLI**: `clap 4.5` (derive macros + env).
- **Codec**: `ciborium` for CBOR; protocol crate owns canonical
  encoding.
- **Crypto**: `ed25519-dalek`. **No hand-rolled crypto**
  (KOMMS_PRINCIPLES §4).
- **Hex**: `faster-hex`.
- **Optional feature**: `submit` (gated behind a feature flag
  to keep the default CLI build offline-safe).

## Local validation gates

Run before every commit; CI runs the same:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check
cargo audit
cargo nextest run --workspace --all-features
```

Scoped runs while iterating:

```bash
cargo check -p protocol         # protocol crate only
cargo build --bin komms          # binary build
cargo run -- decode <bytes>      # exercise the CLI
```

## Repo map

| Path | Purpose |
| ------------------------------------- | ----------------------------------------------------- |
| `src/main.rs`                         | CLI entrypoint |
| `src/lib.rs`                          | Library surface for downstream Rust consumers |
| `protocol/`                           | The canonical-bytes encoder/decoder (workspace member) |
| `Cargo.toml`                          | Workspace + main `komms` binary |
| `deny.toml`                           | `cargo-deny` licence + advisory policy |
| `.github/workflows/`                  | CC-Q.1 baseline CI |

## Hot wires (security-touching)

- `protocol/` — **shared with `komms-miner-submit` via path
  dependency** and **byte-for-byte paired with
  `komms-indexer/protocol/`**. Any change here ripples to
  two other repos. Always:
  1. Update the protocol crate.
  2. Update `komms-indexer/protocol/` in the same logical PR
     (cross-repo coordination).
  3. Run the canonical-bytes parity tests on both sides.
- `--submit` feature path (when enabled) — this is the only
  CLI path that talks to a remote miner. Treat like any other
  signing path: fail-closed, no plaintext logs.

Anti-patterns to never ship in this repo:

- Diverging the `protocol/` crate from
  `komms-indexer/protocol/`. They are one spec implemented
  twice (until ADR-004 lands).
- Hand-coded CBOR. The protocol crate uses `ciborium` because
  ciborium produces deterministic encodings; rolling your own
  byte-pack breaks parity.
- A `--insecure` or `--no-verify` CLI flag. Fail-closed
  (KOMMS_PRINCIPLES §5).

## Common operations

| Task | Command |
| ------------------------------ | -------------------------------------- |
| Build CLI                      | `cargo build --release --bin komms` |
| Build with submit feature      | `cargo build --release --features submit` |
| Format check                   | `cargo fmt --check` |
| Apply formatting               | `cargo fmt` |
| Lint                           | `cargo clippy --workspace --all-targets --all-features -- -D warnings` |
| Licence + advisory policy      | `cargo deny check` |
| Security audit                 | `cargo audit` |
| Tests                          | `cargo nextest run --workspace --all-features` |
| Run CLI                        | `cargo run -- <subcommand>` |

## What this repo deliberately does NOT do

- Hold any keys. The CLI signs only when the user supplies a
  key explicitly (env var or arg); it does not persist them.
- Ship as a service. The `submit` feature is for testing;
  production submission goes through `komms-miner-submit`.

## When stuck

- **`komms-miner-submit` build fails after a protocol change**:
  the sibling-checkout path dep in that repo expects
  `../komms-cli/protocol`. If you renamed or moved the crate,
  update the downstream `Cargo.toml`.
- **A canonical-bytes parity test fails between this crate and
  `komms-indexer/protocol/`**: see KOMMS_PRINCIPLES §6 — there
  is one spec; pick which side has the bug and fix that side,
  do not silently diverge.
