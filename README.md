# `komms` CLI

Developer CLI for the KOMMS protocol (v0 payloads): decode CBOR payloads, inspect refs, derive identifiers, read events from Kaspa RPC or a local indexer DB, build hex posting payloads, and optionally submit transactions.

## Build and install

```bash
cd komms-cli
cargo build --release
# Binary: target/release/komms
```

Default build outputs JSON and builds posting payloads only. To enable on-chain submit (`post --submit` and related flags), build with:

```bash
cargo build --release --features submit
```

## Build and submit a transaction (on-chain)

This flow builds a **real Kaspa transaction** whose **payload** carries your KOMMS event, signs it with your **secp256k1** private key, and broadcasts it via **wRPC** (`submit_transaction`).

### 1. Use a `submit` build

Without this feature, `--submit` fails with a message to rebuild:

```bash
cd komms-cli
cargo build --release --features submit
# ./target/release/komms
```

### 2. Prerequisites

| Requirement | Notes |
|-------------|--------|
| **Network** | Pick `mainnet`, `testnet`, `devnet`, or `simnet` with `--network`. Must match the chain your node/RPC and wallet use. |
| **Funded address** | `--change-address` must be a valid Kaspa address that **already has spendable UTXOs**. The CLI only queries UTXOs for this address. |
| **Private key** | `--private-key-hex` is **32 bytes (64 hex chars)** — secp256k1 secret that **controls those UTXOs** (same wallet as the funded address). |
| **Identifiers in `post`** | `--sid`, `--cid`, `--mid`, `--did`, etc. are **32-byte values as 64 hex characters** (optional `0x`), not short names. Derive ids with `komms id …` or copy them from your app/indexer. |

### 3. RPC connection

- If you **omit** `--rpc-url`, the client uses the default **resolver** for the selected network (public-style defaults from the Kaspa wRPC stack).
- If you **set** `--rpc-url`, that **wRPC WebSocket URL** is used directly (must match `--network`).

Example:

```bash
--network testnet --rpc-url 'ws://127.0.0.1:17110'
```

### 4. Submit command shape

Add **`--submit`** to any `komms post <subcommand>` invocation, plus the wallet/RPC flags:

```bash
./target/release/komms post <subcommand> \
  ... event-specific flags (--sid, --cid, refs, etc.) ... \
  --submit \
  --network testnet \
  --change-address 'kaspa:...' \
  --private-key-hex '<64_hex_chars_no_0x_or_with_0x>' \
  [--rpc-url 'ws://...'] \
  [--priority-fee 0]
```

On success, stdout is JSON with **`submitted_transaction_id`** and **`payload_hex`**.

### 5. What the CLI builds (high level)

1. Encodes your event with **`encode_komms_payload`** (KOMM envelope).
2. Fetches UTXOs for **`--change-address`**.
3. Selects inputs, pays a fee (internal fee rate + optional **`--priority-fee`**), builds a transaction with **one change output** back to that address and the KOMMS bytes in the tx **payload**.
4. Signs with the given private key and calls **`submit_transaction`**.

If UTXO selection fails, ensure the change address is funded on that network and try a lower `--priority-fee` or add coins.

### 6. Full example (testnet)

Replace the hex ids and secrets with your own; **`SID`** and **`CID`** below must each be **64 hex digits**:

```bash
export SID='0000000000000000000000000000000000000000000000000000000000000001'
export CID='0000000000000000000000000000000000000000000000000000000000000002'

./target/release/komms post message-post \
  --sid "$SID" \
  --cid "$CID" \
  --ref-cid 'bafybeiexamplecid000000000000000000000000000000000000000' \
  --submit \
  --network testnet \
  --change-address 'kaspa:qz...' \
  --private-key-hex '0123...abcd'
```

**Payload-only** (no broadcast): same command **without** `--submit` (works with the default build); output includes **`payload_hex`** for your own integrator.

### 7. Submit troubleshooting

- **`failed to verify the signature script` / `false stack entry at end of script execution`**  
  Almost always means the node rejected the input scripts as invalid. Common causes:
  - **`--private-key-hex` does not match `--change-address`** (the key must control the UTXOs returned for that address).
  - **P2SH or non-standard UTXOs** — submit only supports standard **pay-to-pubkey (Schnorr)** and **pay-to-pubkey-ecdsa** scripts; fund a normal `kaspa:` / `kaspatest:` / `kaspadev:` wallet address.
  Older `komms` builds always signed with Schnorr; **ECDSA** addresses (common on Kaspa) need a build that signs per-UTXO script type (current `submit` implementation does this).

### 8. Safety

- Treat **`--private-key-hex`** like a hot wallet secret: shell history, logs, and screen shares can leak it. Prefer a throwaway key on devnets and never commit real keys to git.

## Conventions

- **Hex input**: Many arguments expect hex strings (with or without `0x`—see `hexutil` in the crate).
- **File input**: Prefix a path with `@` (for example `@./payload.hex`) where the command documents it.
- **Stdin**: For `decode`, pass `-` as the input argument to read hex from stdin.
- **JSON output**: Most commands print JSON to stdout. Use `--pretty` where available for indented output.
- **Network**: `--network` accepts `mainnet`, `testnet`, `devnet`, or `simnet`.

Run `komms --help` or `komms <command> --help` for the exact flag list.

---

## `komms decode`

Decode a KOMM-prefixed payload: parse envelope and event, optionally validate strictly, pretty-print CBOR, or verify an Ed25519 signature over the signing payload.

**Usage:** `komms decode [OPTIONS] [INPUT]`

| Option | Meaning |
|--------|---------|
| `[INPUT]` | Hex string, `@path` to raw bytes, or `-` for stdin |
| `--strict` | Fail on invalid payload instead of best-effort parse |
| `--pretty` | Pretty-print JSON |
| `--pretty-cbor` | Include human-oriented CBOR detail in output |
| `--verify-sig` | Verify signature (requires `--ed25519-pubkey-hex`) |
| `--ed25519-pubkey-hex` | Hex-encoded Ed25519 public key |

**Examples:**

```bash
komms decode '4b4f4d4d...' --pretty
komms decode @./tx_payload.bin --strict --pretty
echo '4b4f4d4d...' | komms decode - --pretty
```

---

## `komms ref-inspect`

Decode a `ref` field (protocol byte string) from hex and show its structure (type, parsed fields).

**Usage:** `komms ref-inspect --hex <HEX> [--pretty]`

**Example:**

```bash
komms ref-inspect --hex '0201...' --pretty
```

---

## `komms id`

Derive protocol identifiers (A4) for messages, servers, channels, or DMs.

**Usage:** `komms id [OPTIONS] <COMMAND>`

Global: `--pretty`

### `komms id message`

**Usage:** `komms id message --txid <TXID> [--event-index <N>]`

Default `event-index` is `0`.

```bash
komms id message --txid abc...def --event-index 0 --pretty
```

### `komms id server`

**Usage:** `komms id server --creator-address-hex <HEX> --creation-txid <TXID>`

```bash
komms id server --creator-address-hex ... --creation-txid ... --pretty
```

### `komms id channel`

**Usage:** `komms id channel --sid-hex <HEX> --creator-address-hex <HEX> --creation-txid <TXID>`

```bash
komms id channel --sid-hex ... --creator-address-hex ... --creation-txid ... --pretty
```

### `komms id dm`

**Usage:** `komms id dm --addr-a-hex <HEX> --addr-b-hex <HEX>`

```bash
komms id dm --addr-a-hex ... --addr-b-hex ... --pretty
```

---

## `komms read`

Read KOMMS-related data from the network or from a local indexer database.

**Usage:** `komms read [OPTIONS] <COMMAND>`

Global: `--pretty`

### `komms read tx`

Load a transaction by ID from Kaspa (mempool, optional block hint, then a recent-blocks scan), then decode any KOMMS payload like `decode`.

**Usage:** `komms read tx [OPTIONS] --network <NETWORK> <TXID>`

| Option | Meaning |
|--------|---------|
| `--rpc-url` | wRPC endpoint (optional; uses defaults for network if omitted) |
| `--network` | `mainnet` \| `testnet` \| `devnet` \| `simnet` (required) |
| `--block-hash` | Hint block containing the tx |
| `--strict` | Strict payload validation |
| `--pretty-cbor` | Extra CBOR detail |
| `--verify-sig` / `--ed25519-pubkey-hex` | Same as `decode` |

```bash
komms read tx --network mainnet abc...def --pretty
komms read tx --network testnet --rpc-url 'ws://...' abc...def --strict --pretty
```

### `komms read index`

Scan a local Fjall database path (same layout as the indexer’s transactional `data_dir`), partition `komms_events_by_txid`, and filter rows.

**Usage:** `komms read index --data-dir <PATH> [OPTIONS]`

| Option | Meaning |
|--------|---------|
| `--event-type` | Filter by event type byte |
| `--sid-hex` | Filter by server id (hex) |
| `--cid-hex` | Filter by channel id (hex) |
| `--daa-min` / `--daa-max` | DAA score range |

```bash
komms read index --data-dir /var/lib/komms-indexer --pretty
komms read index --data-dir ./data --event-type 5 --sid-hex ... --pretty
```

---

## `komms post`

Build a **hex-encoded KOMMS posting payload** (and optional metadata) for a given event type. Pipe the result into your own tx builder, or use `--submit` when built with `--features submit`.

**Usage:** `komms post [OPTIONS] <COMMAND>`

Global options:

| Option | Meaning |
|--------|---------|
| `--pretty` | Pretty JSON |
| `--submit` | Submit transaction (requires `submit` feature build) |
| `--rpc-url` | RPC for submit |
| `--network` | Network for submit |
| `--change-address` | Required with `--submit`: Kaspa address that holds UTXOs and receives change |
| `--private-key-hex` | Required with `--submit`: secp256k1 secret, 32 bytes as 64 hex chars |
| `--priority-fee` | Extra sompi added on top of the built-in fee estimate (default `0`) |

**Identifiers:** `--sid`, `--cid`, `--mid`, and similar **`post` fields are 32-byte ids (64 hex characters)**, not human-readable slugs. See [Build and submit a transaction](#build-and-submit-a-transaction-on-chain).

Subcommands (kebab-case in CLI):

- `server-create`, `server-update` — `--sid`, optional `--ref-hex`, `--cid-str`, `--content-hash`, plus `OptMeta`
- `channel-create`, `channel-update` — `--sid`, `--cid`, optional `--ref-hex`, `OptMeta`
- `message-post` — `--sid`, `--cid`, optional `--ref-hex`, `--ref-cid` (UTF-8 CID, ref type 0x01), `--content-hash`, `--pid`, `OptMeta`
- `message-edit` — `--sid`, `--cid`, `--mid`, plus ref/meta fields
- `message-delete` — `--sid`, `--cid`, `--mid`, `OptMeta`
- `dm-message-post` — `--did`, optional refs / `--content-hash`, `OptMeta`
- `reaction-add`, `reaction-remove` — `--sid`, `--cid`, `--mid`, optional `--ref-hex`, `OptMeta`
- `member-join`, `member-leave` — `--sid`, optional `--ref-hex`, `OptMeta`
- `role-assign`, `role-revoke` — `--sid`, optional `--cid`, optional `--ref-hex`, `OptMeta`
- `moderation-action` — `--sid`, optional `--cid`, optional `--mid`, optional `--ref-hex`, `OptMeta`

**OptMeta** (optional on each post subcommand): `--ts`, `--n`, `--sig-hex`

**Examples (payload only):** (`SID` / `CID` = 64 hex chars each)

```bash
komms post message-post \
  --sid "$SID" --cid "$CID" --ref-cid 'bafy...' --pretty
komms post server-create --sid "$SID" --cid-str 'bafy...' --pretty
komms post channel-create --sid "$SID" --cid "$CID" --pretty
```

**Example (submit):** see [Build and submit a transaction](#build-and-submit-a-transaction-on-chain).

---

## `komms verify-content`

Verify that the SHA-256 of a file matches a `ref` of type **0x02** (content hash).

**Usage:** `komms verify-content --file <PATH> --ref-hex <REF_HEX> [--pretty]`

```bash
komms verify-content --file ./message.md --ref-hex '0202...' --pretty
```

---

## See also

- Repository layout: `komms-cli` is standalone; protocol types live in `komms-cli/protocol`.
- For authoritative flags, run `komms --help` and nested helps after upgrading the binary.
