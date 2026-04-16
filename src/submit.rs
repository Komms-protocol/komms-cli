//! Optional: build, sign, and `submit_transaction` with a KOMMS payload.
//! Enable with `cargo build -p komms-cli --features submit`.

use anyhow::Context;
use kaspa_addresses::Address;
use kaspa_consensus_core::{
    config::params::Params,
    constants::TX_VERSION,
    hashing::sighash::{calc_ecdsa_signature_hash, calc_schnorr_signature_hash, SigHashReusedValuesUnsync},
    hashing::sighash_type::SIG_HASH_ALL,
    mass::MassCalculator,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{
        MutableTransaction, Transaction, TransactionInput, TransactionOutput, TransactionOutpoint,
        UtxoEntry,
    },
};
use kaspa_rpc_core::{RpcTransaction, RpcUtxosByAddressesEntry, api::rpc::RpcApi};
use kaspa_txscript::{pay_to_address_script, script_class::ScriptClass};
use kaspa_wrpc_client::KaspaRpcClient;
use protocol::encode_komms_payload;
use protocol::ParsedKommsEvent;
use secp256k1::{Keypair, SecretKey};

const FEE_RATE: u64 = 10;

fn estimated_mass(num_utxos: usize, num_outs: u64) -> u64 {
    200 + 34 * num_outs + 1000 * (num_utxos as u64)
}

fn required_fee(num_utxos: usize, num_outs: u64, priority_fee: u64) -> u64 {
    FEE_RATE * estimated_mass(num_utxos, num_outs) + priority_fee
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
        pick_utxos(&entries, priority_fee).context("UTXO selection")?;

    let script = pay_to_address_script(change_address);
    let inputs: Vec<TransactionInput> = picked
        .iter()
        .map(|e| {
            TransactionInput::new(
                TransactionOutpoint::from(e.outpoint),
                vec![],
                0,
                1,
            )
        })
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

    let mut signable = MutableTransaction::with_entries(unsigned, utxo_entries);
    for i in 0..signable.tx.inputs.len() {
        signable.tx.inputs[i].sig_op_count = 1;
    }

    let reused = SigHashReusedValuesUnsync::new();
    let sighash_byte = SIG_HASH_ALL.to_u8();
    for i in 0..signable.tx.inputs.len() {
        let entry = signable.entries[i]
            .as_ref()
            .with_context(|| format!("missing utxo entry for input {i}"))?;
        let class = ScriptClass::from_script(&entry.script_public_key);
        let signature_script = match class {
            ScriptClass::PubKey => {
                let sig_hash =
                    calc_schnorr_signature_hash(&signable.as_verifiable(), i, SIG_HASH_ALL, &reused);
                let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();
                let sig: [u8; 64] = *keypair.sign_schnorr(msg).as_ref();
                std::iter::once(65u8).chain(sig).chain([sighash_byte]).collect()
            }
            ScriptClass::PubKeyECDSA => {
                let sig_hash =
                    calc_ecdsa_signature_hash(&signable.as_verifiable(), i, SIG_HASH_ALL, &reused);
                let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();
                let sig = secret_key.sign_ecdsa(msg).serialize_compact();
                std::iter::once(65u8).chain(sig).chain([sighash_byte]).collect()
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
    let non = calc.calc_non_contextual_masses(signed.tx.as_ref());
    let ctx = calc
        .calc_contextual_masses(&signed.as_verifiable())
        .context("contextual mass")?;
    let mass = ctx.max(non);

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
        let fee = required_fee(n, 1, priority_fee);
        if sum > fee {
            let out = sum - fee;
            if out > 0 {
                return Ok((picked, sum, fee, out));
            }
        }
    }
    anyhow::bail!("insufficient UTXOs for fee + output (fund the change address)");
}
