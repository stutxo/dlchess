use std::str::FromStr;

use anyhow::Result;

use bitcoin::{
    absolute::{self},
    consensus::{deserialize, encode::serialize_hex},
    hex::FromHex,
    key::{Keypair, Secp256k1},
    opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_VERIFY},
    script::Builder,
    secp256k1::{self, Message},
    sighash::{self, Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo},
    transaction, Address, Amount, OutPoint, ScriptBuf, TapLeafHash, Transaction, TxIn, TxOut, Txid,
    XOnlyPublicKey,
};

use reqwest::Client;
use serde::{Deserialize, Serialize};

const WHITE_PUB_KEY: &str = "020dea9012c69c522326ac5b44200225d653b0f5034e2e06f85e394a069da14856";
const BLACK_PUB_KEY: &str = "03800ced3eeb9d407dbcc3c79d74cba26a31a7309151b90685f31b888f1bb04ea9";

const WHITE_OUTCOME_DECRYPTION_KEY: &str =
    "72e5ef60a984a562e6bbe25c8f5d0dd09c662be53e4365da868bc8910efc9633";
const BLACK_OUTCOME_DECRYPTION_KEY: &str =
    "1ee5c6aaa46aba68876c0b25f13d454ee223720be2350fa089e4077b688a4078";

#[derive(Debug, Serialize, Deserialize)]
struct Utxo {
    txid: String,
    vout: u32,
    status: UtxoStatus,
    value: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct UtxoStatus {
    confirmed: bool,
    block_height: u64,
    block_hash: String,
    block_time: u64,
}

#[tokio::main]
async fn main() {
    match create_script() {
        Ok(taproot_spend_info) => {
            unlock_script(taproot_spend_info).await;
        }
        Err(e) => println!("Error: {}", e),
    }
}

async fn unlock_script(taproot_spend_info: TaprootSpendInfo) {
    let secp = Secp256k1::new();

    let address = Address::p2tr_tweaked(taproot_spend_info.output_key(), bitcoin::Network::Signet);
    println!("Address: {address}",);

    let res_utxo = reqwest::get(&format!(
        "https://mutinynet.com/api/address/{}/utxo",
        address
    ))
    .await
    .unwrap()
    .text()
    .await
    .unwrap();

    let utxos: Vec<Utxo> = serde_json::from_str(&res_utxo).expect("Failed to parse JSON");

    if utxos.is_empty() {
        println!("No UTXOs found, pls fund address {:?}", address);
        return;
    }

    let inputs: Vec<TxIn> = utxos
        .iter()
        .map(|utxo| TxIn {
            previous_output: OutPoint::new(
                Txid::from_str(&utxo.txid).expect("Invalid txid format"),
                utxo.vout,
            ),
            ..Default::default()
        })
        .collect();

    println!("Found UTXOs: {:?}. {:?}", inputs.len(), inputs);

    let mut prev_tx = Vec::new();

    for input in inputs.clone() {
        println!(
            "Fetching previous tx: {:?}, {:?}",
            input.previous_output.txid, input.previous_output.vout
        );
        let url = format!(
            "https://mutinynet.com/api/tx/{}/hex",
            input.previous_output.txid
        );
        let response = reqwest::get(&url).await.unwrap().text().await.unwrap();

        let tx: Transaction = deserialize(&Vec::<u8>::from_hex(&response).unwrap()).unwrap();

        let mut outpoint: Option<OutPoint> = None;
        for (i, out) in tx.output.iter().enumerate() {
            if address.script_pubkey() == out.script_pubkey {
                outpoint = Some(OutPoint::new(tx.compute_txid(), i as u32));
                break;
            }
        }

        let prevout = outpoint.expect("Outpoint must exist in tx");

        prev_tx.push(tx.output[prevout.vout as usize].clone());
    }

    let total_amount = utxos.iter().map(|utxo| utxo.value).sum::<u64>();
    let fee = 500;

    let spend = TxOut {
        value: Amount::from_sat(total_amount - fee),
        script_pubkey: address.script_pubkey(),
    };

    let mut unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: inputs,
        output: vec![spend],
    };

    let unsigned_tx_clone = unsigned_tx.clone();

    //set to white for testing
    let white_winner_script = dlchess_script(get_xonly_pubkey(WHITE_PUB_KEY).unwrap());
    let tap_leaf_hash = TapLeafHash::from_script(&white_winner_script, LeafVersion::TapScript);

    let white_priv_key = Keypair::from_secret_key(
        &secp,
        &secp256k1::SecretKey::from_str(WHITE_OUTCOME_DECRYPTION_KEY).unwrap(),
    );

    let sighash_type = TapSighashType::Default;

    for (index, input) in unsigned_tx.input.iter_mut().enumerate() {
        let sighash = SighashCache::new(&unsigned_tx_clone)
            .taproot_script_spend_signature_hash(
                index,
                &Prevouts::All(&prev_tx),
                tap_leaf_hash,
                sighash_type,
            )
            .expect("failed to construct sighash");

        let message = Message::from(sighash);

        let signature = secp.sign_schnorr_no_aux_rand(&message, &white_priv_key);

        println!("Signature: {:?}", signature);

        let verify_sig = secp.verify_schnorr(
            &signature,
            &message,
            &get_xonly_pubkey(WHITE_PUB_KEY).unwrap(),
        );

        match verify_sig {
            Ok(_) => println!("Signature verified"),
            Err(e) => println!("Signature verification failed: {:?}", e),
        };

        let script_ver = (white_winner_script.clone(), LeafVersion::TapScript);
        let ctrl_block = taproot_spend_info.control_block(&script_ver).unwrap();

        input.witness.push(signature.serialize());
        input.witness.push(script_ver.0.into_bytes());
        input.witness.push(ctrl_block.serialize());
    }

    let serialized_tx = serialize_hex(&unsigned_tx);
    println!("Hex Encoded Transaction: {}", serialized_tx);

    let client = Client::new();
    let res = client
        .post("https://mutinynet.com/api/tx")
        .body(serialized_tx)
        .send()
        .await;

    println!("TXID: {:?}", res);
}

fn create_script() -> Result<TaprootSpendInfo> {
    let secp = Secp256k1::new();

    let internal_key = get_xonly_pubkey(WHITE_PUB_KEY)?;
    let white_script = dlchess_script(get_xonly_pubkey(WHITE_PUB_KEY)?);
    let black_script = dlchess_script(get_xonly_pubkey(BLACK_PUB_KEY)?);

    println!("White Script: {:?}", white_script);

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(1, white_script)
        .unwrap()
        .add_leaf(1, black_script)
        .unwrap()
        .finalize(&secp, internal_key)
        .unwrap();

    Ok(taproot_spend_info)
}

fn get_xonly_pubkey(hex: &str) -> Result<XOnlyPublicKey> {
    let bytes = hex::decode(hex)?;
    let pubkey = bitcoin::secp256k1::PublicKey::from_slice(&bytes)?;
    Ok(XOnlyPublicKey::from(pubkey))
}

fn dlchess_script(oracle_pubkey: XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_x_only_key(&oracle_pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}
