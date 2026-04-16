//! Fetch transaction payload bytes via Kaspa wRPC.
//!
//! Resolution order:
//! 1. `get_mempool_entry` — pending transactions.
//! 2. If `--block-hash` is set, `get_block` with transactions and locate by tx id.
//! 3. Otherwise `get_blocks` in pages from the virtual tip (bounded passes) scanning block txs.

use anyhow::Context;
use kaspa_consensus_core::tx::{Transaction, TransactionId};
use kaspa_rpc_core::{RpcHash, RpcTransaction, api::rpc::RpcApi};
use kaspa_wrpc_client::KaspaRpcClient;
use kaspa_wrpc_client::client::ConnectOptions;
use kaspa_wrpc_client::prelude::NetworkId;

pub async fn connect_rpc(
    client: &KaspaRpcClient,
) -> anyhow::Result<()> {
    client
        .connect(Some(ConnectOptions::default()))
        .await
        .map_err(|e| anyhow::anyhow!("wRPC connect failed: {e}"))?;
    Ok(())
}

pub async fn fetch_transaction_payload(
    client: &KaspaRpcClient,
    tx_id: TransactionId,
    block_hash_hint: Option<RpcHash>,
) -> anyhow::Result<Vec<u8>> {
    if let Ok(entry) = client.get_mempool_entry(tx_id, false, false).await {
        return Ok(entry.transaction.payload);
    }

    if let Some(h) = block_hash_hint {
        let block = client
            .get_block(h, true)
            .await
            .context("get_block with --block-hash")?;
        if let Some(p) = find_payload_in_block(&block.transactions, tx_id)? {
            return Ok(p);
        }
    }

    let mut low_hash: Option<RpcHash> = None;
    for _ in 0..250u32 {
        let resp = client
            .get_blocks(low_hash, true, true)
            .await
            .context("get_blocks")?;
        if resp.blocks.is_empty() {
            break;
        }
        for block in &resp.blocks {
            if let Some(p) = find_payload_in_block(&block.transactions, tx_id)? {
                return Ok(p);
            }
        }
        low_hash = resp.block_hashes.last().copied();
    }

    anyhow::bail!(
        "transaction not found in mempool or scanned blocks; pass --block-hash for deep confirmations"
    );
}

fn find_payload_in_block(
    txs: &[RpcTransaction],
    want: TransactionId,
) -> anyhow::Result<Option<Vec<u8>>> {
    for tx in txs {
        let consensus: Transaction = tx.clone().try_into()?;
        if consensus.id() == want {
            return Ok(Some(tx.payload.clone()));
        }
    }
    Ok(None)
}

pub fn network_id_for_cli(network: kaspa_wrpc_client::prelude::NetworkType) -> NetworkId {
    use kaspa_wrpc_client::prelude::NetworkType;
    match network {
        NetworkType::Mainnet => NetworkId::new(NetworkType::Mainnet),
        _ => NetworkId::with_suffix(network, 10),
    }
}
