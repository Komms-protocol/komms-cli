//! Optional: build, sign, and `submit_transaction` with a KOMMS payload.
//! Enable with `cargo build -p komms-cli --features submit`.

use anyhow::Context;
use kaspa_addresses::Address;
use kaspa_consensus_core::{
    config::params::Params,
    constants::TX_VERSION,
    hashing::sighash::{
        SigHashReusedValuesUnsync, calc_ecdsa_signature_hash, calc_schnorr_signature_hash,
    },
    hashing::sighash_type::SIG_HASH_ALL,
    mass::MassCalculator,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{
        MutableTransaction, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput,
        UtxoEntry,
    },
};
use kaspa_rpc_core::{RpcTransaction, RpcUtxosByAddressesEntry, api::rpc::RpcApi};
use kaspa_txscript::{pay_to_address_script, script_class::ScriptClass};
use kaspa_wrpc_client::KaspaRpcClient;
use protocol::ParsedKommsEvent;
use protocol::encode_komms_payload;
use secp256k1::{Keypair, SecretKey};

// Kaspad's mempool relay-fee floor, per
// `wallet/core/src/tx/mass.rs::MINIMUM_RELAY_TRANSACTION_FEE` at tn10-toc2:
// `100_000 sompi / kg` of mass, i.e. exactly `100 sompi / gram`. Kaspad
// rejects with `transaction has X fees which is under the required amount
// of Y for compute mass M` when `fee < mass * 100 + priority_fee`. The old
// `FEE_RATE = 10` constant predated the Toccata fee schedule and was 10x
// too low, AND the byte-count heuristic below ignored payload bytes —
// together those two defects under-paid the fee by ~14x for a typical
// 72-byte KOMMS join event (paid 12_340 vs required 170_700 sompi).
const MIN_RELAY_FEE_PER_GRAM: u64 = 100;

/// Conservative upper-bound estimate of the kaspad-assigned compute mass
/// for a signed Schnorr P2PK transaction with `num_utxos` inputs, `num_outs`
/// P2PK outputs, and `payload_len` bytes of payload.
///
/// The decomposition exactly mirrors
/// `kaspa_consensus_core::mass::MassCalculator::calc_non_contextual_masses`
/// at rusty-kaspa tag `tn10-toc2`. Constants embedded here (mass_per_tx_byte
/// = 1, mass_per_script_pub_key_byte = 10, GRAMS_PER_SIGOP_COUNT_UNIT =
/// 1000, P2PK script length = 35, signed Schnorr sig_script length = 66)
/// are stable consensus parameters / well-known script byte counts.
fn predicted_compute_mass(num_utxos: usize, num_outs: u64, payload_len: usize) -> u64 {
    const BASE_TX_BYTES: u64 = 94;
    const SIGNED_P2PK_INPUT_BYTES: u64 = 118;
    const P2PK_OUTPUT_BYTES: u64 = 53;
    const P2PK_SCRIPT_PUB_KEY_LEN: u64 = 35;
    const MASS_PER_TX_BYTE: u64 = 1;
    const MASS_PER_SCRIPT_PUB_KEY_BYTE: u64 = 10;
    const GRAMS_PER_SIGOP: u64 = 1000;

    let serialized_size = BASE_TX_BYTES
        + SIGNED_P2PK_INPUT_BYTES * num_utxos as u64
        + P2PK_OUTPUT_BYTES * num_outs
        + payload_len as u64;
    let compute_for_size = serialized_size * MASS_PER_TX_BYTE;
    let output_spk_mass = (2 + P2PK_SCRIPT_PUB_KEY_LEN) * MASS_PER_SCRIPT_PUB_KEY_BYTE * num_outs;
    let script_mass = GRAMS_PER_SIGOP * num_utxos as u64;
    compute_for_size + output_spk_mass + script_mass
}

fn required_fee(num_utxos: usize, num_outs: u64, payload_len: usize, priority_fee: u64) -> u64 {
    MIN_RELAY_FEE_PER_GRAM * predicted_compute_mass(num_utxos, num_outs, payload_len) + priority_fee
}

pub async fn submit_komms_payload(
    client: &KaspaRpcClient,
    ev: &ParsedKommsEvent,
    change_address: &Address,
    private_key_sechex: &str,
    priority_fee: u64,
    network_type: kaspa_wrpc_client::prelude::NetworkType,
) -> anyhow::Result<kaspa_consensus_core::tx::TransactionId> {
    let payload = encode_komms_payload(ev).context("encode KOMMS payload")?;
    let sk = crate::hexutil::parse_hex_bytes(private_key_sechex)?;
    if sk.len() != 32 {
        anyhow::bail!("private key must be 32 bytes (64 hex chars)");
    }
    let secret_key = SecretKey::from_slice(&sk).context("invalid secp256k1 key")?;
    let keypair = Keypair::from_secret_key(secp256k1::SECP256K1, &secret_key);

    let entries = client
        .get_utxos_by_addresses(vec![change_address.clone()])
        .await
        .context("get_utxos_by_addresses")?;

    let (picked, _total_in, _fee, output_value) =
        pick_utxos(&entries, payload.len(), priority_fee).context("UTXO selection")?;

    let script = pay_to_address_script(change_address);
    let inputs: Vec<TransactionInput> = picked
        .iter()
        .map(|e| TransactionInput::new(TransactionOutpoint::from(e.outpoint), vec![], 0, 1))
        .collect();

    let outputs = vec![TransactionOutput::new(output_value, script)];

    let unsigned = Transaction::new_non_finalized(
        TX_VERSION,
        inputs,
        outputs,
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        payload,
    );

    let utxo_entries: Vec<UtxoEntry> = picked
        .iter()
        .map(|e| UtxoEntry::from(e.utxo_entry.clone()))
        .collect();

    // Toccata-era `TransactionInput` replaces the flat `sig_op_count: u8`
    // field with `mass: TxInputMass` (enum of `SigopCount(u8)` for v0 txs
    // / `ComputeBudget(u16)` for v1 = `TX_VERSION_TOCCATA`). The
    // `TransactionInput::new(..,1)` constructor above already wraps the
    // sig-op count in `TxInputMass::SigopCount(1)`, so no per-input
    // post-construction mass assignment is required for our v0 txs.
    let mut signable = MutableTransaction::with_entries(unsigned, utxo_entries);

    let reused = SigHashReusedValuesUnsync::new();
    let sighash_byte = SIG_HASH_ALL.to_u8();
    for i in 0..signable.tx.inputs.len() {
        let entry = signable.entries[i]
            .as_ref()
            .with_context(|| format!("missing utxo entry for input {i}"))?;
        let class = ScriptClass::from_script(&entry.script_public_key);
        let signature_script = match class {
            ScriptClass::PubKey => {
                let sig_hash = calc_schnorr_signature_hash(
                    &signable.as_verifiable(),
                    i,
                    SIG_HASH_ALL,
                    &reused,
                );
                let msg =
                    secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();
                let sig: [u8; 64] = *keypair.sign_schnorr(msg).as_ref();
                std::iter::once(65u8)
                    .chain(sig)
                    .chain([sighash_byte])
                    .collect()
            }
            ScriptClass::PubKeyECDSA => {
                let sig_hash =
                    calc_ecdsa_signature_hash(&signable.as_verifiable(), i, SIG_HASH_ALL, &reused);
                let msg =
                    secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();
                let sig = secret_key.sign_ecdsa(msg).serialize_compact();
                std::iter::once(65u8)
                    .chain(sig)
                    .chain([sighash_byte])
                    .collect()
            }
            ScriptClass::ScriptHash | ScriptClass::NonStandard => {
                anyhow::bail!(
                    "unsupported UTXO script for input {i}: use a standard pay-to-pubkey (Schnorr) or pay-to-pubkey-ecdsa address for --change-address"
                );
            }
        };
        signable.tx.inputs[i].signature_script = signature_script;
    }

    let signed = signable;

    let params = Params::from(network_type);
    let calc = MassCalculator::new_with_consensus_params(&params);
    // Toccata split the single-scalar mass into three dimensions
    // (compute / transient / storage). The scalar consensus mass is
    // recovered by normalising both `NonContextualMasses` (compute +
    // transient) and `ContextualMasses` (storage) into the compute-mass
    // reference scale via the active block-mass cofactors. We pin to the
    // mempool cofactors so the mass we set matches the value the mempool
    // will re-derive during admission.
    let non = calc.calc_non_contextual_masses(signed.tx.as_ref());
    let ctx = calc
        .calc_contextual_masses(&signed.as_verifiable())
        .context("contextual mass")?;
    let cofactors = params.mempool_block_mass_cofactors().after();
    let mass = kaspa_consensus_core::mass::Mass::new(non, ctx).normalized_max(&cofactors);

    let final_tx = signed.tx;
    final_tx.set_mass(mass);

    let rpc_tx = RpcTransaction::from(&final_tx);
    let tid = client
        .submit_transaction(rpc_tx, false)
        .await
        .context("submit_transaction")?;
    Ok(tid)
}

fn pick_utxos(
    entries: &[RpcUtxosByAddressesEntry],
    payload_len: usize,
    priority_fee: u64,
) -> anyhow::Result<(Vec<RpcUtxosByAddressesEntry>, u64, u64, u64)> {
    let mut v: Vec<_> = entries.to_vec();
    v.sort_by_key(|e| std::cmp::Reverse(e.utxo_entry.amount));

    let mut picked = Vec::new();
    let mut sum = 0u64;
    for e in v {
        sum += e.utxo_entry.amount;
        picked.push(e);
        let n = picked.len();
        let fee = required_fee(n, 1, payload_len, priority_fee);
        if sum > fee {
            let out = sum - fee;
            if out > 0 {
                return Ok((picked, sum, fee, out));
            }
        }
    }
    anyhow::bail!("insufficient UTXOs for fee + output (fund the change address)");
}
