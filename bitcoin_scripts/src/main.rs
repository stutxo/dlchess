use std::str::FromStr;

use anyhow::Result;

use clap::{Parser, Subcommand};

use bitcoin::{
    absolute::{self},
    consensus::{deserialize, encode::serialize_hex},
    hex::FromHex,
    key::{Keypair, Secp256k1},
    opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY},
    script::Builder,
    secp256k1::{self, Message, SecretKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo},
    transaction, Address, Amount, OutPoint, ScriptBuf, TapLeafHash, Transaction, TxIn, TxOut, Txid,
    XOnlyPublicKey,
};

use rand::rngs::ThreadRng;
use reqwest::Client;
use schnorr_fun::{
    adaptor::{Adaptor, EncryptedSignature},
    fun::{
        marker::{EvenY, Normal, Public},
        Point,
    },
    nonce, Schnorr, Signature,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

//hardcoded for testing
const WHITE_PLAYER_SECRET_KEY: &str =
    "0eae283124be737cfef1a2f224e252fe501614987fdc7d8afda607011bd7f939";
const BLACK_PLAYER_SECRET_KEY: &str =
    "8302235fe68dccbeb724807416598359ffca97766684cc3fd3bd1b7d513cc0be";

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, value_name = "GAME_ID")]
    game_id: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DLChess {
    oracle_public_key: Point<EvenY>,
    attestations: GameAttestations,
    outcome: Option<Outcome>,
    game_id: String,
    game_over: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Outcome {
    signature: Signature,
    attestation: Attestation,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GameAttestations {
    white: Attestation,
    black: Attestation,
    draw: Attestation,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Attestation {
    key: Point<Normal>,
    adaptor_sig: EncryptedSignature,
    message: Vec<u8>,
}

#[derive(Subcommand)]
enum Commands {
    SpendAddressUnHappyPath,
}

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
    block_height: Option<u64>,
    block_hash: Option<String>,
    block_time: Option<u64>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let secp = Secp256k1::new();

    let white_player_secret = SecretKey::from_str(WHITE_PLAYER_SECRET_KEY).unwrap();

    let black_player_secret = SecretKey::from_str(BLACK_PLAYER_SECRET_KEY).unwrap();

    let white_player_keys = Keypair::from_secret_key(&secp, &white_player_secret);
    let black_player_keys = Keypair::from_secret_key(&secp, &black_player_secret);

    match args.command {
        Commands::SpendAddressUnHappyPath => {
            match create_script(white_player_keys, black_player_keys, args.game_id.as_str()).await {
                Ok((taproot_spend_info, oracle_response)) => {
                    unlock_script(
                        taproot_spend_info,
                        white_player_keys,
                        black_player_keys,
                        oracle_response,
                    )
                    .await;
                }
                Err(e) => println!("Error creating script for spending: {}", e),
            }
        }
    }
}

async fn unlock_script(
    taproot_spend_info: TaprootSpendInfo,
    white_player_keys: Keypair,
    black_player_keys: Keypair,
    oracle_response: DLChess,
) {
    let address = Address::p2tr_tweaked(taproot_spend_info.output_key(), bitcoin::Network::Signet);

    if !oracle_response.game_over {
        println!("Game still in progress, cannot spend yet");
        return;
    }

    let secp = Secp256k1::new();

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

    if utxos.len() < 2 {
        println!(
            "Only 1 UTXO found, player 2 needs to fund address {:?}",
            address
        );
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

    let schnorr: Schnorr<Sha256, nonce::Synthetic<Sha256, nonce::GlobalRng<ThreadRng>>> =
        Schnorr::new(nonce::Synthetic::default());

    let winning_pub_key = &oracle_response.outcome.as_ref().unwrap().attestation.key;

    let winning_player = match &oracle_response
        .outcome
        .as_ref()
        .unwrap()
        .attestation
        .message
    {
        msg if msg == b"white" => {
            println!("🔑 Winning player: White");
            &white_player_keys
        }
        msg if msg == b"black" => {
            println!("🔑 Winning player: Black");
            &black_player_keys
        }
        _ => panic!("Invalid outcome for now"),
    };

    let oracle_winning_decryption_key = schnorr.recover_decryption_key(
        winning_pub_key,
        &oracle_response
            .outcome
            .as_ref()
            .unwrap()
            .attestation
            .adaptor_sig,
        &oracle_response.outcome.as_ref().unwrap().signature,
    );

    let winner_script = dlchess_script(
        XOnlyPublicKey::from_slice(&winning_pub_key.to_xonly_bytes()).unwrap(),
        winning_player.x_only_public_key().0,
    );
    let tap_leaf_hash = TapLeafHash::from_script(&winner_script, LeafVersion::TapScript);

    let white_priv_key = Keypair::from_secret_key(
        &secp,
        &secp256k1::SecretKey::from_slice(&oracle_winning_decryption_key.unwrap().to_bytes())
            .unwrap(),
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

        let oracle_signature = secp.sign_schnorr_no_aux_rand(&message, &white_priv_key);

        let verify_oracle_sig = secp.verify_schnorr(
            &oracle_signature,
            &message,
            &XOnlyPublicKey::from_slice(&winning_pub_key.to_xonly_bytes()).unwrap(),
        );

        assert!(
            verify_oracle_sig.is_ok(),
            "Oracle signature verification failed"
        );

        let winning_player_signature = secp.sign_schnorr_no_aux_rand(&message, &winning_player);

        let verify_player_sig = secp.verify_schnorr(
            &winning_player_signature,
            &message,
            &winning_player.x_only_public_key().0,
        );

        assert!(
            verify_player_sig.is_ok(),
            "Winning player signature verification failed"
        );

        let script_ver = (winner_script.clone(), LeafVersion::TapScript);
        let ctrl_block = taproot_spend_info.control_block(&script_ver).unwrap();

        //test bad sig
        input.witness.push(winning_player_signature.serialize());
        input.witness.push(oracle_signature.serialize());
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

    if let Ok(response) = res {
        println!("mutinynet status code: {}", response.status().as_u16());
    } else if let Err(e) = res {
        println!("Failed to send request: {:?}", e);
    }
}

async fn create_script(
    white_player_keys: Keypair,
    black_player_keys: Keypair,
    game_id: &str,
) -> Result<(TaprootSpendInfo, DLChess)> {
    println!("🏗️ Creating address for game: {}", game_id);
    let secp = Secp256k1::new();

    let combined_pubkey = secp256k1::PublicKey::combine_keys(&[
        &white_player_keys.public_key(),
        &black_player_keys.public_key(),
    ])
    .expect("Failed to combine keys");

    let res_att = reqwest::get(&format!("http://127.0.0.1:3000/game/{}", game_id))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    let oracle_response: DLChess = serde_json::from_str(&res_att)?;

    //verify oracle response

    verify_all_outcomes(&oracle_response);

    let white_script = dlchess_script(
        XOnlyPublicKey::from_slice(&oracle_response.attestations.white.key.to_xonly_bytes())
            .unwrap(),
        white_player_keys.x_only_public_key().0,
    );

    let black_script = dlchess_script(
        XOnlyPublicKey::from_slice(&oracle_response.attestations.black.key.to_xonly_bytes())
            .unwrap(),
        black_player_keys.x_only_public_key().0,
    );

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(1, white_script)
        .unwrap()
        .add_leaf(1, black_script)
        .unwrap()
        .finalize(&secp, combined_pubkey.into())
        .unwrap();

    Ok((taproot_spend_info, oracle_response))
}

fn dlchess_script(oracle_pubkey: XOnlyPublicKey, player_pubkey: XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_x_only_key(&oracle_pubkey)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_x_only_key(&player_pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

pub fn verify_all_outcomes(oracle: &DLChess) {
    let schnorr: Schnorr<Sha256, nonce::Synthetic<Sha256, nonce::GlobalRng<ThreadRng>>> =
        Schnorr::new(nonce::Synthetic::default());

    let outcomes = [
        ("White", &oracle.attestations.white),
        ("Black", &oracle.attestations.black),
        ("Draw", &oracle.attestations.draw),
    ];

    for (name, attestation) in outcomes.iter() {
        println!("🔍 Verifying attestation for outcome: {}", name);
        println!("🔑 Encrypted key: {:?}", attestation.key);
        let message = schnorr_fun::Message::<Public>::plain(name, &attestation.message);

        let is_valid = schnorr.verify_encrypted_signature(
            &oracle.oracle_public_key,
            &attestation.key,
            message,
            &attestation.adaptor_sig,
        );

        if is_valid {
            println!(
                "✅ Attestation Verification successful for outcome: {}",
                name
            );
        } else {
            println!(
                "❌ Attestation Verification failed for outcome: {}. Reason: Not valid.",
                name
            );
        }
    }
}
