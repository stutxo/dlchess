use anyhow::Result;

use bitcoin::{
    key::Secp256k1, opcodes::all::OP_CHECKSIGVERIFY, script::Builder, taproot::TaprootBuilder,
    Address, ScriptBuf, XOnlyPublicKey,
};

const WHITE_PUB_KEY: &str = "020dea9012c69c522326ac5b44200225d653b0f5034e2e06f85e394a069da14856";
const BLACK_PUB_KEY: &str = "03800ced3eeb9d407dbcc3c79d74cba26a31a7309151b90685f31b888f1bb04ea9";

const WHITE_OUTCOME_DECRYPTION_KEY: &str =
    "72e5ef60a984a562e6bbe25c8f5d0dd09c662be53e4365da868bc8910efc9633";
const BLACK_OUTCOME_DECRYPTION_KEY: &str =
    "1ee5c6aaa46aba68876c0b25f13d454ee223720be2350fa089e4077b688a4078";

const CONTRACT_ADDRESS: &str = "tb1pq0adgccxa5a6z6sqegtg9t22vq9nlswhje9c7ptqerk56mtxzkes9lskgd";

fn main() {
    match create_script() {
        Ok(address) => println!("Address: {}", address),
        Err(e) => println!("Error: {}", e),
    }

    unlock_script()
}

fn unlock_script() {}

fn create_script() -> Result<Address> {
    let secp = Secp256k1::new();

    let internal_key = get_xonly_pubkey(WHITE_PUB_KEY)?;
    let white_script = dlchess_script(get_xonly_pubkey(WHITE_PUB_KEY)?);
    let black_script = dlchess_script(get_xonly_pubkey(BLACK_PUB_KEY)?);

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(1, white_script)
        .unwrap()
        .add_leaf(1, black_script)
        .unwrap()
        .finalize(&secp, internal_key)
        .unwrap();

    let address = Address::p2tr_tweaked(taproot_spend_info.output_key(), bitcoin::Network::Signet);

    Ok(address)
}

fn get_xonly_pubkey(hex: &str) -> Result<XOnlyPublicKey> {
    let bytes = hex::decode(hex)?;
    let pubkey = bitcoin::secp256k1::PublicKey::from_slice(&bytes)?;
    Ok(XOnlyPublicKey::from(pubkey))
}

fn dlchess_script(oracle_pubkey: XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_slice(oracle_pubkey.serialize())
        .push_opcode(OP_CHECKSIGVERIFY)
        .into_script()
}
