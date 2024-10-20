use rand::rngs::ThreadRng;
use schnorr_fun::{
    adaptor::{Adaptor, EncryptedSign, EncryptedSignature},
    fun::{marker::*, nonce, KeyPair, Point, Scalar},
    Message, Schnorr,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use std::convert::TryInto;

#[derive(Serialize, Deserialize)]
pub enum GameResult {
    White,
    Black,
    Draw,
}

#[derive(Serialize, Deserialize)]
pub struct DLChess {
    public_key: Vec<u8>,
    attestations: GameAttestations,
}

#[derive(Serialize, Deserialize)]
pub struct GameAttestations {
    white: Attestation,
    black: Attestation,
    draw: Attestation,
}

#[derive(Serialize, Deserialize)]
pub struct Attestation {
    key: Vec<u8>,
    adaptor_sig: SerializableEncryptedSignature,
    message: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SerializableEncryptedSignature {
    r_point: SerializablePoint,
    s_hat: SerializableScalar,
    needs_negation: bool,
}

#[derive(Serialize, Deserialize, Clone)]
struct SerializablePoint {
    bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
struct SerializableScalar {
    bytes: Vec<u8>,
}

impl From<EncryptedSignature> for SerializableEncryptedSignature {
    fn from(sig: EncryptedSignature) -> Self {
        SerializableEncryptedSignature {
            r_point: SerializablePoint {
                bytes: sig.R.to_bytes().to_vec(),
            },
            s_hat: SerializableScalar {
                bytes: sig.s_hat.to_bytes().to_vec(),
            },
            needs_negation: sig.needs_negation,
        }
    }
}

impl From<SerializableEncryptedSignature> for EncryptedSignature {
    fn from(sig: SerializableEncryptedSignature) -> Self {
        let r_bytes: [u8; 33] = sig.r_point.bytes[..]
            .try_into()
            .expect("slice with incorrect length");
        let r: Point<EvenY> =
            Point::from_xonly_bytes(r_bytes[1..].try_into().expect("Invalid R point bytes"))
                .expect("Invalid R point bytes");

        let s_hat_bytes: [u8; 32] = sig.s_hat.bytes[..]
            .try_into()
            .expect("slice with incorrect length");
        let s_hat = Scalar::from_bytes_mod_order(s_hat_bytes);

        EncryptedSignature {
            R: r,
            s_hat,
            needs_negation: sig.needs_negation,
        }
    }
}

pub struct ChessOracle {
    schnorr: Schnorr<Sha256, nonce::Synthetic<Sha256, nonce::GlobalRng<ThreadRng>>>,
    signing_keypair: KeyPair<EvenY>,
    secret_keys: Option<GameSecretKeys>,
}

impl Default for ChessOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl ChessOracle {
    pub fn new() -> Self {
        let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
        let schnorr = Schnorr::<Sha256, _>::new(nonce_gen);
        let signing_keypair = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));

        Self {
            schnorr,
            signing_keypair,
            secret_keys: None,
        }
    }

    pub fn generate_game_setup(&mut self) -> DLChess {
        let secret_keys = self.generate_secret_keys();
        self.secret_keys = Some(secret_keys.clone());
        let encrypted_keys = self.generate_encrypted_keys(&secret_keys);
        let messages = self.generate_messages();
        let adaptor_sigs = self.generate_adaptor_signatures(&encrypted_keys, &messages);

        self.build_dlchess(encrypted_keys, adaptor_sigs)
    }

    fn generate_secret_keys(&self) -> GameSecretKeys {
        GameSecretKeys {
            white: Scalar::random(&mut rand::thread_rng()),
            black: Scalar::random(&mut rand::thread_rng()),
            draw: Scalar::random(&mut rand::thread_rng()),
        }
    }

    fn generate_encrypted_keys(&self, secret_keys: &GameSecretKeys) -> GameEncryptedKeys {
        GameEncryptedKeys {
            white: self.schnorr.encryption_key_for(&secret_keys.white),
            black: self.schnorr.encryption_key_for(&secret_keys.black),
            draw: self.schnorr.encryption_key_for(&secret_keys.draw),
        }
    }

    fn generate_messages(&self) -> GameMessages {
        GameMessages {
            white: Message::<Public>::plain("text-bitcoin", b"white"),
            black: Message::<Public>::plain("text-bitcoin", b"black"),
            draw: Message::<Public>::plain("text-bitcoin", b"draw"),
        }
    }

    fn generate_adaptor_signatures(
        &self,
        encrypted_keys: &GameEncryptedKeys,
        messages: &GameMessages,
    ) -> GameAdaptorSignatures {
        GameAdaptorSignatures {
            white: self.schnorr.encrypted_sign(
                &self.signing_keypair,
                &encrypted_keys.white,
                messages.white,
            ),
            black: self.schnorr.encrypted_sign(
                &self.signing_keypair,
                &encrypted_keys.black,
                messages.black,
            ),
            draw: self.schnorr.encrypted_sign(
                &self.signing_keypair,
                &encrypted_keys.draw,
                messages.draw,
            ),
        }
    }

    fn build_dlchess(
        &self,
        encrypted_keys: GameEncryptedKeys,
        adaptor_sigs: GameAdaptorSignatures,
    ) -> DLChess {
        DLChess {
            public_key: self.signing_keypair.public_key().to_bytes().to_vec(),
            attestations: GameAttestations {
                white: Attestation {
                    key: encrypted_keys.white.to_bytes().to_vec(),
                    adaptor_sig: adaptor_sigs.white.into(),
                    message: b"white".to_vec(),
                },
                black: Attestation {
                    key: encrypted_keys.black.to_bytes().to_vec(),
                    adaptor_sig: adaptor_sigs.black.into(),
                    message: b"black".to_vec(),
                },
                draw: Attestation {
                    key: encrypted_keys.draw.to_bytes().to_vec(),
                    adaptor_sig: adaptor_sigs.draw.into(),
                    message: b"draw".to_vec(),
                },
            },
        }
    }
}

#[derive(Clone)]
struct GameSecretKeys {
    white: Scalar,
    black: Scalar,
    draw: Scalar,
}

struct GameEncryptedKeys {
    white: Point,
    black: Point,
    draw: Point,
}

struct GameMessages<'a> {
    white: Message<'a, Public>,
    black: Message<'a, Public>,
    draw: Message<'a, Public>,
}

struct GameAdaptorSignatures {
    white: EncryptedSignature,
    black: EncryptedSignature,
    draw: EncryptedSignature,
}

fn main() {
    let mut oracle = ChessOracle::new();
    let game_setup = oracle.generate_game_setup();

    let serialized = serde_json::to_string(&game_setup).unwrap();

    let deserialized: DLChess = serde_json::from_str(&serialized).unwrap();

    let public_key_bytes: [u8; 33] = deserialized.public_key[..]
        .try_into()
        .expect("slice with incorrect length");

    let public_key = Point::<EvenY>::from_xonly_bytes(
        public_key_bytes[1..]
            .try_into()
            .expect("slice with incorrect length"),
    )
    .unwrap();

    let white_att = &deserialized.attestations.white;

    let white_adaptor_sig: EncryptedSignature = white_att.adaptor_sig.clone().into();

    let white_encrypted_key_bytes: [u8; 33] = white_att.key[..]
        .try_into()
        .expect("slice with incorrect length");
    let white_encrypted_key: Point<Normal> = Point::from_bytes(white_encrypted_key_bytes).unwrap();

    println!("White encrypted key: {:?}", white_encrypted_key);

    let white_message = Message::<Public>::plain("text-bitcoin", &white_att.message);

    let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
    let schnorr = Schnorr::<Sha256, _>::new(nonce_gen);

    assert!(schnorr.verify_encrypted_signature(
        &public_key,
        &white_encrypted_key,
        white_message,
        &white_adaptor_sig
    ));

    let white_signature = oracle
        .schnorr
        .decrypt_signature(oracle.secret_keys.unwrap().white, white_adaptor_sig.clone());

    let serialized_sig = serde_json::to_string(&white_signature).unwrap();

    let deserialized_sig: schnorr_fun::Signature = serde_json::from_str(&serialized_sig).unwrap();

    match schnorr.recover_decryption_key(
        &white_encrypted_key,
        &white_adaptor_sig,
        &deserialized_sig,
    ) {
        Some(decryption_key) => {
            println!("White won!! {}", decryption_key);
            //need to check that decryption_key can be used to create white_encrypted_key
            assert_eq!(
                schnorr.encryption_key_for(&decryption_key),
                white_encrypted_key
            );
        }
        None => eprintln!("signature is not the decryption of our original encrypted signature"),
    }
}
