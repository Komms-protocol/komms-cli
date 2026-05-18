# AGENTS.md — komms-cli

> **For**: AI coding agents (Cursor, Claude, Codex, etc.) and
> human contributors who want a fast orientation to this repo.
> **Status**: v0.1 (May 16, 2026).

This repo is the **Komms developer CLI** — a standalone Rust
binary (`komms`) for decoding, posting, reading, and inspecting
KOMMS payloads on Kaspa. It is also the **single Rust source of
truth for the `protocol` crate** that every other Komms Rust
service takes as a sibling-checkout path dependency, per
ADR-016 §2 (canonical-bytes / cross-language parity contract)
and WS-D.4 (May 17, 2026). Today the only consumer workspace is
`komms-indexer` (which holds both the `indexer` and the
`komms-miner-submit` crates after the May 18, 2026 consolidation);
in Horizon B, `komms-gateway` joins the consumer set per ADR-004.

## Read this first (mandatory orientation order)

1. **[`komms-planning/KOMMS_PRINCIPLES.md`](../komms-planning/KOMMS_PRINCIPLES.md)**
   — §6 (canonical bytes are one path) is the critical
   principle for this repo, because the `protocol/` crate IS
   the canonical encoder for every Komms service.
2. **[`komms-planning/komms-protocol/02_MESSAGING_CONTENT.md`](../komms-planning/komms-protocol/02_MESSAGING_CONTENT.md)**
   — the spec the `protocol/` crate implements.
3. **ADR-004 + ADR-016** in
   [`komms-planning/ARCHITECTURE_DECISIONS.md`](../komms-planning/ARCHITECTURE_DECISIONS.md)
   — ADR-016 §2 makes `komms-cli/protocol/` the single Rust
   source of truth; ADR-004 plans the longer-term consolidation
   into a dedicated `komms-protocol` repo in Horizon B.

## Stack

- **Layout**: 2-member Cargo workspace (`.`, `protocol`).
  Promoting `protocol/` to a workspace member (WS-D.4) is
  load-bearing because `cargo test --workspace` is the only
  way to reach `protocol/tests/parity_fixtures.rs`, the
  ADR-016 canonical-bytes parity gate. A single-package layout
  silently skips that test surface.
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

- `protocol/` — **the single Rust source of truth** consumed
  by every other Komms Rust service via the
  `protocol = { path = "../komms-cli/protocol" }`
  sibling-checkout path dep (today: the `komms-indexer`
  workspace, which holds both the `indexer` crate and the
  `komms-miner-submit` crate). It is **byte-for-byte paired
  with the `komms-client` TypeScript mirror at
  `komms-client/src/lib/komms/payload/`** via the ADR-016
  parity-fixture pipeline. Any change here ripples to every
  downstream crate that does a sibling-checkout build.
  Always:
  1. Update the protocol crate.
  2. Regenerate parity fixtures
     (`cargo test --workspace --nocapture` pipes into the
     `komms-client` fixtures via the WS-CC-Q.5.1 substrate).
  3. Run the canonical-bytes parity tests on both languages.
- `--submit` feature path (when enabled) — this is the only
  CLI path that talks to a remote miner. Treat like any other
  signing path: fail-closed, no plaintext logs.

Anti-patterns to never ship in this repo:

- Forking a second Rust copy of `protocol/`. WS-D.4 retired
  the old `komms-indexer/protocol/` vendored copy precisely
  to eliminate the silent-drift failure class.
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
  production submission goes through the `komms-miner-submit`
  crate inside the `komms-indexer` workspace
  (`komms-indexer/komms-miner-submit/`).

## When stuck

- **A sibling-checkout build of `komms-indexer` (or any future
  Rust consumer) fails after a protocol change**: every
  downstream workspace expects this repo to live at
  `../komms-cli/` relative to its own root. If you renamed or
  moved the protocol crate inside this repo, update the
  downstream `Cargo.toml` workspace path dep accordingly.
- **A canonical-bytes parity test fails between this crate and
  the `komms-client` TypeScript mirror**: see
  KOMMS_PRINCIPLES §6 + ADR-016 §2 — there is one spec; pick
  which side has the bug and fix that side, do not silently
  diverge.
