//! Read komms indexer Fjall data without depending on `indexer-db`.
//! Partition name and postcard layout match [`komms-indexer`](../../komms-indexer/indexer-db/src/komms_events.rs).

use anyhow::Context;
use fjall::{Config, PartitionCreateOptions};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KommsEventRecord {
    pub containing_block_hash: [u8; 32],
    pub containing_daa: u64,
    pub event_type: u8,
    pub enc: bool,
    pub sid: Option<[u8; 32]>,
    pub cid: Option<[u8; 32]>,
    pub did: Option<[u8; 32]>,
    pub pid: Option<[u8; 32]>,
    pub mid: Option<[u8; 32]>,
    pub ref_bytes: Option<Vec<u8>>,
    pub ts: Option<u64>,
    pub n: Option<u64>,
    pub sig: Option<Vec<u8>>,
    #[serde(default)]
    pub creator_address_body: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct KommsEventRecordV1 {
    pub containing_block_hash: [u8; 32],
    pub containing_daa: u64,
    pub event_type: u8,
    pub enc: bool,
    pub sid: Option<[u8; 32]>,
    pub cid: Option<[u8; 32]>,
    pub did: Option<[u8; 32]>,
    pub pid: Option<[u8; 32]>,
    pub mid: Option<[u8; 32]>,
    pub ref_bytes: Option<Vec<u8>>,
    pub ts: Option<u64>,
    pub n: Option<u64>,
    pub sig: Option<Vec<u8>>,
}

fn decode_record(bytes: &[u8]) -> anyhow::Result<KommsEventRecord> {
    if let Ok(rec) = postcard::from_bytes::<KommsEventRecord>(bytes) {
        return Ok(rec);
    }
    let v1: KommsEventRecordV1 = postcard::from_bytes(bytes)?;
    Ok(KommsEventRecord {
        containing_block_hash: v1.containing_block_hash,
        containing_daa: v1.containing_daa,
        event_type: v1.event_type,
        enc: v1.enc,
        sid: v1.sid,
        cid: v1.cid,
        did: v1.did,
        pid: v1.pid,
        mid: v1.mid,
        ref_bytes: v1.ref_bytes,
        ts: v1.ts,
        n: v1.n,
        sig: v1.sig,
        creator_address_body: None,
    })
}

/// Load all rows from `komms_events_by_txid` (suitable for dev / filtered CLI output).
pub fn load_komms_events(data_dir: &Path) -> anyhow::Result<Vec<([u8; 32], KommsEventRecord)>> {
    let ks = Config::new(data_dir).open_transactional()?;
    let part = ks.open_partition(
        "komms_events_by_txid",
        PartitionCreateOptions::default(),
    )?;
    let rtx = ks.read_tx();
    let mut out = Vec::new();
    for item in rtx.iter(&part) {
        let (key, value) = item.context("fjall iter")?;
        if key.len() != 32 {
            anyhow::bail!("komms_events_by_txid key must be 32 bytes, got {}", key.len());
        }
        let tx_id: [u8; 32] = key.as_ref().try_into().expect("length checked");
        let rec: KommsEventRecord = decode_record(value.as_ref())
            .with_context(|| format!("postcard decode tx {}", faster_hex::hex_string(&tx_id)))?;
        out.push((tx_id, rec));
    }
    Ok(out)
}
