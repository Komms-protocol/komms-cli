//! `komms` developer CLI library.

mod hexutil;
mod index_scan;
mod output;
mod read_rpc;
#[cfg(feature = "submit")]
mod submit;

use anyhow::Context;
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, VerifyingKey};
use kaspa_addresses::{Address, Prefix, Version};
// `TransactionId` is needed both for `read tx` (always available) and
// for the gated submit paths. Importing unconditionally lets the
// default no-feature build succeed.
use kaspa_consensus_core::tx::TransactionId;
use kaspa_rpc_core::RpcHash;
use kaspa_wrpc_client::prelude::NetworkType;
use kaspa_wrpc_client::{KaspaRpcClient, Resolver, WrpcEncoding};
use output::{event_to_json, ref_json};
use protocol::{
    self, EventType, ParsedKommsEvent, encode_komms_payload, parse_cbor_map, parse_komms_payload,
    participant_id, ref_from_cid_str, ref_from_content_hash, signing_payload_cbor,
    strip_komms_envelope, validate_event,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "komms")]
#[command(about = "KOMMS protocol developer CLI (v0 payloads)")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Decode a KOMM-prefixed payload (hex string, @file, or stdin with `-`).
    Decode {
        /// Hex payload, path prefixed with `@`, or `-` for stdin
        input: Option<String>,
        #[arg(long)]
        strict: bool,
        #[arg(long)]
        pretty: bool,
        #[arg(long)]
        pretty_cbor: bool,
        #[arg(long)]
        verify_sig: bool,
        #[arg(long)]
        ed25519_pubkey_hex: Option<String>,
    },
    /// Inspect a `ref` byte string (hex).
    RefInspect {
        #[arg(long)]
        hex: String,
        #[arg(long)]
        pretty: bool,
    },
    /// Derive protocol identifiers (A4).
    Id {
        #[command(subcommand)]
        cmd: IdCmd,
        #[arg(long)]
        pretty: bool,
    },
    Read {
        #[command(subcommand)]
        cmd: ReadCmd,
        #[arg(long)]
        pretty: bool,
    },
    /// Build posting payload (hex). With `--submit`, rebuild with `--features submit` to broadcast.
    Post {
        #[command(subcommand)]
        cmd: PostCmd,
        #[arg(long, global = true)]
        pretty: bool,
        #[arg(long, global = true)]
        submit: bool,
        #[arg(long, global = true)]
        rpc_url: Option<String>,
        #[arg(long, global = true)]
        network: Option<NetworkArg>,
        #[arg(long, global = true)]
        change_address: Option<String>,
        #[arg(long, global = true)]
        private_key_hex: Option<String>,
        #[arg(long, global = true, default_value_t = 0u64)]
        priority_fee: u64,
    },
    /// Verify content SHA-256 matches a `ref` type 0x02.
    VerifyContent {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        ref_hex: String,
        #[arg(long)]
        pretty: bool,
    },
}

#[derive(Subcommand)]
pub enum IdCmd {
    Message {
        #[arg(long)]
        txid: String,
        #[arg(long, default_value_t = 0u64)]
        event_index: u64,
    },
    Server {
        #[arg(long)]
        creation_txid: String,
    },
    Channel {
        #[arg(long)]
        sid_hex: String,
        #[arg(long)]
        creator_address_hex: String,
        #[arg(long)]
        creation_txid: String,
    },
    Dm {
        #[arg(long)]
        addr_a_hex: String,
        #[arg(long)]
        addr_b_hex: String,
    },
    /// Derive the canonical KOMMS `creator_address_bytes` (hex) and
    /// `participant_id` (hex) from a Kaspa bech32 address. Matches
    /// the encoding used by the indexer for `creator_address_hex`
    /// parameters (e.g. `/komms/bootstrap`) and by the protocol's
    /// `participant_id()` for ACL identity.
    CreatorBytes {
        /// Kaspa address, e.g. `kaspa:qpz…` / `kaspatest:qpz…`.
        #[arg(long)]
        address: String,
    },
    /// Generate a fresh secp256k1 keypair and its Kaspa
    /// `Version::PubKey` (Schnorr P2PK) address for the given
    /// network. The private key is printed to stdout — only use
    /// this for testnet / smoke-test wallets, never mainnet
    /// custody. Combine with `--pretty` for human-readable output.
    NewWallet {
        #[arg(long, default_value = "testnet")]
        network: NetworkArg,
    },
}

#[derive(Subcommand)]
pub enum ReadCmd {
    /// Load a transaction from Kaspa (mempool, optional block hint, then recent `get_blocks` scan).
    Tx {
        txid: String,
        #[arg(long)]
        rpc_url: Option<String>,
        #[arg(long)]
        network: NetworkArg,
        #[arg(long)]
        block_hash: Option<String>,
        #[arg(long)]
        strict: bool,
        #[arg(long)]
        pretty_cbor: bool,
        #[arg(long)]
        verify_sig: bool,
        #[arg(long)]
        ed25519_pubkey_hex: Option<String>,
    },
    /// Scan local indexer Fjall DB (`Config::open_transactional` path).
    Index {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        event_type: Option<u8>,
        #[arg(long)]
        sid_hex: Option<String>,
        #[arg(long)]
        cid_hex: Option<String>,
        #[arg(long)]
        daa_min: Option<u64>,
        #[arg(long)]
        daa_max: Option<u64>,
    },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum NetworkArg {
    Mainnet,
    Testnet,
    Devnet,
    Simnet,
}

impl From<NetworkArg> for NetworkType {
    fn from(a: NetworkArg) -> Self {
        match a {
            NetworkArg::Mainnet => NetworkType::Mainnet,
            NetworkArg::Testnet => NetworkType::Testnet,
            NetworkArg::Devnet => NetworkType::Devnet,
            NetworkArg::Simnet => NetworkType::Simnet,
        }
    }
}

#[derive(clap::Args, Clone)]
pub struct OptMeta {
    #[arg(long)]
    pub ts: Option<u64>,
    #[arg(long)]
    pub n: Option<u64>,
    #[arg(long)]
    pub sig_hex: Option<String>,
}

#[derive(Subcommand)]
pub enum PostCmd {
    ServerCreate {
        #[arg(long)]
        sid: String,
        #[arg(long)]
        ref_hex: Option<String>,
        #[arg(long)]
        cid_str: Option<String>,
        #[arg(long)]
        content_hash: Option<String>,
        #[command(flatten)]
        meta: OptMeta,
    },
    ServerUpdate {
        #[arg(long)]
        sid: String,
        #[arg(long)]
        ref_hex: Option<String>,
        #[arg(long)]
        cid_str: Option<String>,
        #[arg(long)]
        content_hash: Option<String>,
        #[command(flatten)]
        meta: OptMeta,
    },
    ChannelCreate {
        #[arg(long)]
        sid: String,
        #[arg(long)]
        cid: String,
        #[arg(long)]
        ref_hex: Option<String>,
        #[command(flatten)]
        meta: OptMeta,
    },
    ChannelUpdate {
        #[arg(long)]
        sid: String,
        #[arg(long)]
        cid: String,
        #[arg(long)]
        ref_hex: Option<String>,
        #[command(flatten)]
        meta: OptMeta,
    },
    MessagePost {
        #[arg(long)]
        sid: String,
        #[arg(long)]
        cid: String,
        #[arg(long)]
        ref_hex: Option<String>,
        /// Hippius / UTF-8 CID (ref type 0x01)
        #[arg(long)]
        ref_cid: Option<String>,
        #[arg(long)]
        content_hash: Option<String>,
        #[arg(long)]
        pid: Option<String>,
        #[command(flatten)]
        meta: OptMeta,
    },
    MessageEdit {
        #[arg(long)]
        sid: String,
        #[arg(long)]
        cid: String,
        #[arg(long)]
        mid: String,
        #[arg(long)]
        ref_hex: Option<String>,
        #[arg(long)]
        ref_cid: Option<String>,
        #[arg(long)]
        content_hash: Option<String>,
        #[command(flatten)]
        meta: OptMeta,
    },
    MessageDelete {
        #[arg(long)]
        sid: String,
        #[arg(long)]
        cid: String,
        #[arg(long)]
        mid: String,
        #[command(flatten)]
        meta: OptMeta,
    },
    DmMessagePost {
        #[arg(long)]
        did: String,
        #[arg(long)]
        ref_hex: Option<String>,
        #[arg(long)]
        ref_cid: Option<String>,
        #[arg(long)]
        content_hash: Option<String>,
        #[command(flatten)]
        meta: OptMeta,
    },
    ReactionAdd {
        #[arg(long)]
        sid: String,
        #[arg(long)]
        cid: String,
        #[arg(long)]
        mid: String,
        #[arg(long)]
        ref_hex: Option<String>,
        #[command(flatten)]
        meta: OptMeta,
    },
    ReactionRemove {
        #[arg(long)]
        sid: String,
        #[arg(long)]
        cid: String,
        #[arg(long)]
        mid: String,
        #[arg(long)]
        ref_hex: Option<String>,
        #[command(flatten)]
        meta: OptMeta,
    },
    MemberJoin {
        #[arg(long)]
        sid: String,
        /// Kaspa address of the joining account (`pid` = participant id hash). Defaults to `--change-address` with `--submit`.
        #[arg(long)]
        member_address: Option<String>,
        #[arg(long)]
        ref_hex: Option<String>,
        #[command(flatten)]
        meta: OptMeta,
    },
    MemberLeave {
        #[arg(long)]
        sid: String,
        /// Kaspa address of the leaving account (`pid`). Defaults to `--change-address` with `--submit`.
        #[arg(long)]
        member_address: Option<String>,
        #[arg(long)]
        ref_hex: Option<String>,
        #[command(flatten)]
        meta: OptMeta,
    },
    RoleAssign {
        #[arg(long)]
        sid: String,
        #[arg(long)]
        cid: Option<String>,
        #[arg(long)]
        ref_hex: Option<String>,
        #[command(flatten)]
        meta: OptMeta,
    },
    RoleRevoke {
        #[arg(long)]
        sid: String,
        #[arg(long)]
        cid: Option<String>,
        #[arg(long)]
        ref_hex: Option<String>,
        #[command(flatten)]
        meta: OptMeta,
    },
    ModerationAction {
        #[arg(long)]
        sid: String,
        #[arg(long)]
        cid: Option<String>,
        #[arg(long)]
        mid: Option<String>,
        #[arg(long)]
        ref_hex: Option<String>,
        #[command(flatten)]
        meta: OptMeta,
    },
}

fn load_input_bytes(s: Option<&str>) -> anyhow::Result<Vec<u8>> {
    let Some(raw) = s else {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        return hexutil::parse_hex_bytes(std::str::from_utf8(&buf).context("stdin utf-8")?.trim());
    };
    let raw = raw.trim();
    if raw == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        return hexutil::parse_hex_bytes(std::str::from_utf8(&buf).context("stdin utf-8")?.trim());
    }
    if let Some(path) = raw.strip_prefix('@') {
        return std::fs::read(path).with_context(|| format!("read {path}"));
    }
    hexutil::parse_hex_bytes(raw)
}

fn decode_payload(
    bytes: &[u8],
    strict: bool,
    pretty_cbor: bool,
    verify_sig: bool,
    pk_hex: Option<&str>,
) -> anyhow::Result<serde_json::Value> {
    let (ev, validation) = if strict {
        match parse_komms_payload(bytes) {
            Ok(ev) => (ev, None),
            Err(e) => return Err(e.into()),
        }
    } else {
        let cbor = strip_komms_envelope(bytes).unwrap_or(bytes);
        let ev = parse_cbor_map(cbor).map_err(|e| anyhow::anyhow!("{e}"))?;
        let v = validate_event(&ev).err().map(|e| e.to_string());
        (ev, v)
    };

    let mut j = event_to_json(&ev);
    if let Some(msg) = validation {
        j["validation_warning"] = json!(msg);
    }

    if pretty_cbor {
        let cbor = strip_komms_envelope(bytes).unwrap_or(bytes);
        let v: ciborium::Value = ciborium::de::from_reader(cbor).context("CBOR debug parse")?;
        j["cbor_debug"] = serde_json::to_value(format!("{v:?}")).unwrap_or(json!(null));
    }

    if verify_sig {
        let pk_s = pk_hex.context("--ed25519-pubkey-hex required with --verify-sig")?;
        let pk = hexutil::parse_hex32_pk(pk_s)?;
        let vk = VerifyingKey::from_bytes(&pk).context("ed25519 public key")?;
        let sig_b = ev.sig.context("event has no sig")?;
        let sig = Signature::from_slice(&sig_b).context("signature bytes")?;
        let msg = signing_payload_cbor(&ev).context("signing payload")?;
        vk.verify_strict(&msg, &sig).context("ed25519 verify")?;
        j["sig_verified"] = json!(true);
    }

    Ok(j)
}

fn make_client(url: Option<&str>, network: NetworkType) -> anyhow::Result<KaspaRpcClient> {
    let encoding = WrpcEncoding::Borsh;
    let resolver = if url.is_some() {
        None
    } else {
        Some(Resolver::default())
    };
    let nid = read_rpc::network_id_for_cli(network);
    KaspaRpcClient::new(encoding, url, resolver, Some(nid), None)
        .map_err(|e| anyhow::anyhow!("{e}"))
}

fn ref_from_opts(
    ref_hex: &Option<String>,
    cid_str: &Option<String>,
    content_hash: &Option<String>,
) -> anyhow::Result<Option<Vec<u8>>> {
    let n = ref_hex.is_some() as u8 + cid_str.is_some() as u8 + content_hash.is_some() as u8;
    if n > 1 {
        anyhow::bail!("use only one of --ref-hex, --cid-str, --content-hash");
    }
    if let Some(h) = ref_hex {
        return Ok(Some(hexutil::parse_hex_bytes(h)?));
    }
    if let Some(c) = cid_str {
        return Ok(Some(ref_from_cid_str(c)?));
    }
    if let Some(h) = content_hash {
        return Ok(Some(ref_from_content_hash(hexutil::parse_hex32(h)?)));
    }
    Ok(None)
}

fn meta_sig(m: &OptMeta) -> anyhow::Result<Option<[u8; 64]>> {
    match &m.sig_hex {
        None => Ok(None),
        Some(h) => Ok(Some(hexutil::parse_hex64_sig(h)?)),
    }
}

fn creator_address_body_from_addr(addr: &Address) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + addr.payload.len());
    v.push(addr.version as u8);
    v.extend_from_slice(addr.payload.as_slice());
    v
}

/// `MEMBER_JOIN` / `MEMBER_LEAVE` require `pid` (indexer + protocol validation). Resolved from `--member-address` or `--change-address` with `--submit`.
fn patch_member_join_leave_pid(
    ev: &mut ParsedKommsEvent,
    cmd: &PostCmd,
    submit: bool,
    change_address: &Option<String>,
) -> anyhow::Result<()> {
    let member_address_opt = match cmd {
        PostCmd::MemberJoin { member_address, .. } => member_address.as_deref(),
        PostCmd::MemberLeave { member_address, .. } => member_address.as_deref(),
        _ => return Ok(()),
    };
    let addr_str = if let Some(s) = member_address_opt {
        s
    } else if submit {
        change_address.as_deref().context(
            "member-join/member-leave: use --member-address, or --submit with --change-address",
        )?
    } else {
        anyhow::bail!(
            "member-join/member-leave: provide --member-address (or use --submit with --change-address)"
        );
    };
    let addr: Address = addr_str.try_into().context("member/change address")?;
    let body = creator_address_body_from_addr(&addr);
    ev.pid = Some(participant_id(&body));
    Ok(())
}

fn build_post_ev(cmd: &PostCmd) -> anyhow::Result<ParsedKommsEvent> {
    let z = |s: &str| hexutil::parse_hex32(s);
    let ev = match cmd {
        PostCmd::ServerCreate {
            sid,
            ref_hex,
            cid_str,
            content_hash,
            meta,
        } => ParsedKommsEvent {
            v: 0,
            t: EventType::ServerCreate,
            sid: Some(z(sid)?),
            cid: None,
            did: None,
            pid: None,
            mid: None,
            ref_bytes: ref_from_opts(ref_hex, cid_str, content_hash)?,
            enc: false,
            ts: meta.ts,
            n: meta.n,
            sig: meta_sig(meta)?,
            ..Default::default()
        },
        PostCmd::ServerUpdate {
            sid,
            ref_hex,
            cid_str,
            content_hash,
            meta,
        } => ParsedKommsEvent {
            v: 0,
            t: EventType::ServerUpdate,
            sid: Some(z(sid)?),
            cid: None,
            did: None,
            pid: None,
            mid: None,
            ref_bytes: ref_from_opts(ref_hex, cid_str, content_hash)?,
            enc: false,
            ts: meta.ts,
            n: meta.n,
            sig: meta_sig(meta)?,
            ..Default::default()
        },
        PostCmd::ChannelCreate {
            sid,
            cid,
            ref_hex,
            meta,
        } => ParsedKommsEvent {
            v: 0,
            t: EventType::ChannelCreate,
            sid: Some(z(sid)?),
            cid: Some(z(cid)?),
            did: None,
            pid: None,
            mid: None,
            ref_bytes: ref_hex
                .as_ref()
                .map(|h| hexutil::parse_hex_bytes(h))
                .transpose()?,
            enc: false,
            ts: meta.ts,
            n: meta.n,
            sig: meta_sig(meta)?,
            ..Default::default()
        },
        PostCmd::ChannelUpdate {
            sid,
            cid,
            ref_hex,
            meta,
        } => ParsedKommsEvent {
            v: 0,
            t: EventType::ChannelUpdate,
            sid: Some(z(sid)?),
            cid: Some(z(cid)?),
            did: None,
            pid: None,
            mid: None,
            ref_bytes: ref_hex
                .as_ref()
                .map(|h| hexutil::parse_hex_bytes(h))
                .transpose()?,
            enc: false,
            ts: meta.ts,
            n: meta.n,
            sig: meta_sig(meta)?,
            ..Default::default()
        },
        PostCmd::MessagePost {
            sid,
            cid,
            ref_hex,
            ref_cid,
            content_hash,
            pid,
            meta,
        } => ParsedKommsEvent {
            v: 0,
            t: EventType::MessagePost,
            sid: Some(z(sid)?),
            cid: Some(z(cid)?),
            did: None,
            pid: pid.as_ref().map(|p| z(p)).transpose()?,
            mid: None,
            ref_bytes: Some(
                ref_from_opts(ref_hex, ref_cid, content_hash)?.context("message-post needs ref")?,
            ),
            enc: false,
            ts: meta.ts,
            n: meta.n,
            sig: meta_sig(meta)?,
            ..Default::default()
        },
        PostCmd::MessageEdit {
            sid,
            cid,
            mid,
            ref_hex,
            ref_cid,
            content_hash,
            meta,
        } => ParsedKommsEvent {
            v: 0,
            t: EventType::MessageEdit,
            sid: Some(z(sid)?),
            cid: Some(z(cid)?),
            did: None,
            pid: None,
            mid: Some(z(mid)?),
            ref_bytes: Some(
                ref_from_opts(ref_hex, ref_cid, content_hash)?.context("message-edit needs ref")?,
            ),
            enc: false,
            ts: meta.ts,
            n: meta.n,
            sig: meta_sig(meta)?,
            ..Default::default()
        },
        PostCmd::MessageDelete {
            sid,
            cid,
            mid,
            meta,
        } => ParsedKommsEvent {
            v: 0,
            t: EventType::MessageDelete,
            sid: Some(z(sid)?),
            cid: Some(z(cid)?),
            did: None,
            pid: None,
            mid: Some(z(mid)?),
            ref_bytes: None,
            enc: false,
            ts: meta.ts,
            n: meta.n,
            sig: meta_sig(meta)?,
            ..Default::default()
        },
        PostCmd::DmMessagePost {
            did,
            ref_hex,
            ref_cid,
            content_hash,
            meta,
        } => ParsedKommsEvent {
            v: 0,
            t: EventType::DmMessagePost,
            sid: None,
            cid: None,
            did: Some(z(did)?),
            pid: None,
            mid: None,
            ref_bytes: Some(
                ref_from_opts(ref_hex, ref_cid, content_hash)?
                    .context("dm-message-post needs ref")?,
            ),
            enc: true,
            ts: meta.ts,
            n: meta.n,
            sig: meta_sig(meta)?,
            ..Default::default()
        },
        PostCmd::ReactionAdd {
            sid,
            cid,
            mid,
            ref_hex,
            meta,
        } => ParsedKommsEvent {
            v: 0,
            t: EventType::ReactionAdd,
            sid: Some(z(sid)?),
            cid: Some(z(cid)?),
            did: None,
            pid: None,
            mid: Some(z(mid)?),
            ref_bytes: ref_hex
                .as_ref()
                .map(|h| hexutil::parse_hex_bytes(h))
                .transpose()?,
            enc: false,
            ts: meta.ts,
            n: meta.n,
            sig: meta_sig(meta)?,
            ..Default::default()
        },
        PostCmd::ReactionRemove {
            sid,
            cid,
            mid,
            ref_hex,
            meta,
        } => ParsedKommsEvent {
            v: 0,
            t: EventType::ReactionRemove,
            sid: Some(z(sid)?),
            cid: Some(z(cid)?),
            did: None,
            pid: None,
            mid: Some(z(mid)?),
            ref_bytes: ref_hex
                .as_ref()
                .map(|h| hexutil::parse_hex_bytes(h))
                .transpose()?,
            enc: false,
            ts: meta.ts,
            n: meta.n,
            sig: meta_sig(meta)?,
            ..Default::default()
        },
        PostCmd::MemberJoin {
            sid, ref_hex, meta, ..
        } => ParsedKommsEvent {
            v: 0,
            t: EventType::MemberJoin,
            sid: Some(z(sid)?),
            cid: None,
            did: None,
            pid: None,
            mid: None,
            ref_bytes: ref_hex
                .as_ref()
                .map(|h| hexutil::parse_hex_bytes(h))
                .transpose()?,
            enc: false,
            ts: meta.ts,
            n: meta.n,
            sig: meta_sig(meta)?,
            ..Default::default()
        },
        PostCmd::MemberLeave {
            sid, ref_hex, meta, ..
        } => ParsedKommsEvent {
            v: 0,
            t: EventType::MemberLeave,
            sid: Some(z(sid)?),
            cid: None,
            did: None,
            pid: None,
            mid: None,
            ref_bytes: ref_hex
                .as_ref()
                .map(|h| hexutil::parse_hex_bytes(h))
                .transpose()?,
            enc: false,
            ts: meta.ts,
            n: meta.n,
            sig: meta_sig(meta)?,
            ..Default::default()
        },
        PostCmd::RoleAssign {
            sid,
            cid,
            ref_hex,
            meta,
        } => ParsedKommsEvent {
            v: 0,
            t: EventType::RoleAssign,
            sid: Some(z(sid)?),
            cid: cid.as_ref().map(|c| z(c)).transpose()?,
            did: None,
            pid: None,
            mid: None,
            ref_bytes: ref_hex
                .as_ref()
                .map(|h| hexutil::parse_hex_bytes(h))
                .transpose()?,
            enc: false,
            ts: meta.ts,
            n: meta.n,
            sig: meta_sig(meta)?,
            ..Default::default()
        },
        PostCmd::RoleRevoke {
            sid,
            cid,
            ref_hex,
            meta,
        } => ParsedKommsEvent {
            v: 0,
            t: EventType::RoleRevoke,
            sid: Some(z(sid)?),
            cid: cid.as_ref().map(|c| z(c)).transpose()?,
            did: None,
            pid: None,
            mid: None,
            ref_bytes: ref_hex
                .as_ref()
                .map(|h| hexutil::parse_hex_bytes(h))
                .transpose()?,
            enc: false,
            ts: meta.ts,
            n: meta.n,
            sig: meta_sig(meta)?,
            ..Default::default()
        },
        PostCmd::ModerationAction {
            sid,
            cid,
            mid,
            ref_hex,
            meta,
        } => ParsedKommsEvent {
            v: 0,
            t: EventType::ModerationAction,
            sid: Some(z(sid)?),
            cid: cid.as_ref().map(|c| z(c)).transpose()?,
            did: None,
            pid: None,
            mid: mid.as_ref().map(|m| z(m)).transpose()?,
            ref_bytes: ref_hex
                .as_ref()
                .map(|h| hexutil::parse_hex_bytes(h))
                .transpose()?,
            enc: false,
            ts: meta.ts,
            n: meta.n,
            sig: meta_sig(meta)?,
            ..Default::default()
        },
    };
    Ok(ev)
}

pub async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Decode {
            input,
            strict,
            pretty,
            pretty_cbor,
            verify_sig,
            ed25519_pubkey_hex,
        } => {
            let bytes = load_input_bytes(input.as_deref())?;
            let j = decode_payload(
                &bytes,
                strict,
                pretty_cbor,
                verify_sig,
                ed25519_pubkey_hex.as_deref(),
            )?;
            print_json(&j, pretty)?;
        }
        Commands::RefInspect { hex, pretty } => {
            let b = hexutil::parse_hex_bytes(&hex)?;
            let j = ref_json(&b);
            print_json(&j, pretty)?;
        }
        Commands::Id { cmd, pretty } => {
            let j = match cmd {
                IdCmd::Message {
                    txid,
                    event_index: _,
                } => {
                    let t = hexutil::parse_hex32(&txid)?;
                    let mid = protocol::message_id(&t);
                    json!({ "message_id": faster_hex::hex_string(&mid) })
                }
                IdCmd::Server { creation_txid } => {
                    let tx = hexutil::parse_hex32(&creation_txid)?;
                    let sid = protocol::server_id(&tx);
                    json!({ "server_id": faster_hex::hex_string(&sid) })
                }
                IdCmd::Channel {
                    sid_hex: _,
                    creator_address_hex: _,
                    creation_txid,
                } => {
                    let tx = hexutil::parse_hex32(&creation_txid)?;
                    let cid = protocol::channel_id(&tx);
                    json!({ "channel_id": faster_hex::hex_string(&cid) })
                }
                IdCmd::Dm {
                    addr_a_hex,
                    addr_b_hex,
                } => {
                    let a = hexutil::parse_hex_bytes(&addr_a_hex)?;
                    let b = hexutil::parse_hex_bytes(&addr_b_hex)?;
                    let did = protocol::dm_thread_id(&a, &b);
                    json!({ "dm_thread_id": faster_hex::hex_string(&did) })
                }
                IdCmd::CreatorBytes { address } => {
                    let addr: Address = address
                        .as_str()
                        .try_into()
                        .with_context(|| format!("could not parse kaspa address: {address}"))?;
                    let body = creator_address_body_from_addr(&addr);
                    let pid = protocol::participant_id(&body);
                    json!({
                        "kaspa_address": address,
                        "address_version": addr.version as u8,
                        "creator_address_hex": faster_hex::hex_string(&body),
                        "participant_id_hex": faster_hex::hex_string(&pid),
                    })
                }
                IdCmd::NewWallet { network } => {
                    // Use the OS RNG via secp256k1's `rand` feature so
                    // the resulting key has full 256-bit entropy. The
                    // address is the bech32m of `[Version::PubKey || xonly]`
                    // — same encoding `derive_admin_pubkey` produces, so
                    // smoke-test wallets are indistinguishable from any
                    // miner/user wallet on the wire.
                    let (secret_key, _) =
                        secp256k1::SECP256K1.generate_keypair(&mut secp256k1::rand::thread_rng());
                    let kp = secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, &secret_key);
                    let (xonly, _parity) = kp.x_only_public_key();
                    let xonly_bytes = xonly.serialize();
                    let prefix = match network {
                        NetworkArg::Mainnet => Prefix::Mainnet,
                        NetworkArg::Testnet => Prefix::Testnet,
                        NetworkArg::Devnet => Prefix::Devnet,
                        NetworkArg::Simnet => Prefix::Simnet,
                    };
                    let addr = Address::new(prefix, Version::PubKey, &xonly_bytes);
                    let priv_hex = faster_hex::hex_string(&secret_key.secret_bytes());
                    let body = creator_address_body_from_addr(&addr);
                    let pid = protocol::participant_id(&body);
                    json!({
                        "private_key_hex": priv_hex,
                        "xonly_pubkey_hex": faster_hex::hex_string(&xonly_bytes),
                        "kaspa_address": addr.to_string(),
                        "address_version": addr.version as u8,
                        "creator_address_hex": faster_hex::hex_string(&body),
                        "participant_id_hex": faster_hex::hex_string(&pid),
                    })
                }
            };
            print_json(&j, pretty)?;
        }
        Commands::Read { cmd, pretty } => match cmd {
            ReadCmd::Tx {
                txid,
                rpc_url,
                network,
                block_hash,
                strict,
                pretty_cbor,
                verify_sig,
                ed25519_pubkey_hex,
            } => {
                let nt: NetworkType = network.into();
                let client = make_client(rpc_url.as_deref(), nt)?;
                read_rpc::connect_rpc(&client).await?;
                let tid = TransactionId::from_bytes(hexutil::parse_hex32(&txid)?);
                let bh = block_hash
                    .as_deref()
                    .map(hexutil::parse_hex32)
                    .transpose()?
                    .map(RpcHash::from_bytes);
                let payload = read_rpc::fetch_transaction_payload(&client, tid, bh).await?;
                let mut j = decode_payload(
                    &payload,
                    strict,
                    pretty_cbor,
                    verify_sig,
                    ed25519_pubkey_hex.as_deref(),
                )?;
                j["txid"] = json!(txid);
                print_json(&j, pretty)?;
            }
            ReadCmd::Index {
                data_dir,
                event_type,
                sid_hex,
                cid_hex,
                daa_min,
                daa_max,
            } => {
                let entries = index_scan::load_komms_events(&data_dir)?;
                let sid_f = sid_hex.as_deref().map(hexutil::parse_hex32).transpose()?;
                let cid_f = cid_hex.as_deref().map(hexutil::parse_hex32).transpose()?;
                let mut rows = Vec::new();
                for (tx_id, rec) in entries {
                    if let Some(t) = event_type
                        && rec.event_type != t
                    {
                        continue;
                    }
                    if let Some(s) = sid_f
                        && rec.sid != Some(s)
                    {
                        continue;
                    }
                    if let Some(c) = cid_f
                        && rec.cid != Some(c)
                    {
                        continue;
                    }
                    if let Some(lo) = daa_min
                        && rec.containing_daa < lo
                    {
                        continue;
                    }
                    if let Some(hi) = daa_max
                        && rec.containing_daa > hi
                    {
                        continue;
                    }
                    rows.push(json!({
                        "txid": faster_hex::hex_string(&tx_id),
                        "containing_block_hash": faster_hex::hex_string(&rec.containing_block_hash),
                        "containing_daa": rec.containing_daa,
                        "event_type": rec.event_type,
                        "enc": rec.enc,
                        "sid": rec.sid.map(|b| faster_hex::hex_string(&b)),
                        "cid": rec.cid.map(|b| faster_hex::hex_string(&b)),
                        "did": rec.did.map(|b| faster_hex::hex_string(&b)),
                        "pid": rec.pid.map(|b| faster_hex::hex_string(&b)),
                        "mid": rec.mid.map(|b| faster_hex::hex_string(&b)),
                        "ref": rec.ref_bytes.as_ref().map(|r| faster_hex::hex_string(r)),
                        "ts": rec.ts,
                        "n": rec.n,
                        "sig": rec.sig.as_ref().map(|s| faster_hex::hex_string(s)),
                    }));
                }
                print_json(&json!({ "events": rows }), pretty)?;
            }
        },
        #[allow(unused_variables)]
        Commands::Post {
            cmd,
            pretty,
            submit,
            rpc_url,
            network,
            change_address,
            private_key_hex,
            priority_fee,
        } => {
            let mut ev = build_post_ev(&cmd)?;
            patch_member_join_leave_pid(&mut ev, &cmd, submit, &change_address)?;
            encode_komms_payload(&ev).context("validate + encode event")?;
            if submit {
                #[cfg(feature = "submit")]
                {
                    let nt = network.map(|n| n.into()).unwrap_or(NetworkType::Mainnet);
                    let addr: Address = change_address
                        .as_deref()
                        .context("--change-address required for --submit")?
                        .try_into()
                        .context("change address")?;
                    let pk = private_key_hex
                        .as_deref()
                        .context("--private-key-hex required")?;
                    let client = make_client(rpc_url.as_deref(), nt)?;
                    read_rpc::connect_rpc(&client).await?;
                    let tid =
                        submit::submit_komms_payload(&client, &ev, &addr, pk, priority_fee, nt)
                            .await?;
                    let j = json!({ "submitted_transaction_id": tid.to_string(), "payload_hex": faster_hex::hex_string(&encode_komms_payload(&ev)?) });
                    print_json(&j, pretty)?;
                }
                #[cfg(not(feature = "submit"))]
                {
                    anyhow::bail!("rebuild komms-cli with --features submit for --submit");
                }
            } else {
                let raw = encode_komms_payload(&ev)?;
                let j = json!({
                    "payload_hex": faster_hex::hex_string(&raw),
                    "event": event_to_json(&ev),
                });
                print_json(&j, pretty)?;
            }
        }
        Commands::VerifyContent {
            file,
            ref_hex,
            pretty,
        } => {
            let data = std::fs::read(&file)?;
            let digest: [u8; 32] = Sha256::digest(&data).into();
            let r = hexutil::parse_hex_bytes(&ref_hex)?;
            let ok = r.first() == Some(&0x02) && r.len() == 33 && r[1..] == digest;
            let j = json!({
                "file_sha256": faster_hex::hex_string(&digest),
                "ref_hex": ref_hex,
                "matches_ref_content_hash": ok,
            });
            print_json(&j, pretty)?;
        }
    }
    Ok(())
}

fn print_json(v: &serde_json::Value, pretty: bool) -> anyhow::Result<()> {
    if pretty {
        println!("{}", serde_json::to_string_pretty(v)?);
    } else {
        println!("{}", serde_json::to_string(v)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_fixture_server_create() {
        let sid = [7u8; 32];
        let ev = ParsedKommsEvent {
            v: 0,
            t: EventType::ServerCreate,
            sid: Some(sid),
            cid: None,
            did: None,
            pid: None,
            mid: None,
            ref_bytes: None,
            enc: false,
            ts: None,
            n: None,
            sig: None,
            ..Default::default()
        };
        let raw = encode_komms_payload(&ev).unwrap();
        let j = decode_payload(&raw, true, false, false, None).unwrap();
        assert_eq!(j["t"], json!(0));
    }
}
