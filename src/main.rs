use rand::rngs::ThreadRng;
use schnorr_fun::{
    adaptor::{Adaptor, EncryptedSign, EncryptedSignature},
    fun::{marker::*, nonce, KeyPair, Point, Scalar},
    Message, Schnorr,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Serialize, Deserialize)]
pub struct DLChess {
    public_key: Point<EvenY>,
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
    key: Point<Normal>,
    adaptor_sig: EncryptedSignature,
    message: Vec<u8>,
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

        DLChess {
            public_key: self.signing_keypair.public_key(),
            attestations: GameAttestations {
                white: Attestation {
                    key: encrypted_keys.white,
                    adaptor_sig: adaptor_sigs.white,
                    message: b"white".to_vec(),
                },
                black: Attestation {
                    key: encrypted_keys.black,
                    adaptor_sig: adaptor_sigs.black,
                    message: b"black".to_vec(),
                },
                draw: Attestation {
                    key: encrypted_keys.draw,
                    adaptor_sig: adaptor_sigs.draw,
                    message: b"draw".to_vec(),
                },
            },
        }
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
}

#[derive(Clone)]
struct GameSecretKeys {
    white: Scalar,
    black: Scalar,
    draw: Scalar,
}

struct GameEncryptedKeys {
    white: Point<Normal>,
    black: Point<Normal>,
    draw: Point<Normal>,
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

    let white_att = &deserialized.attestations.white;

    let white_key = white_att.key;

    println!("White encrypted key: {:?}", white_key);

    let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
    let schnorr = Schnorr::<Sha256, _>::new(nonce_gen);

    let white_message = Message::<Public>::plain("text-bitcoin", &white_att.message);

    assert!(schnorr.verify_encrypted_signature(
        &deserialized.public_key,
        &white_key,
        white_message,
        &white_att.adaptor_sig
    ));

    let white_signature = oracle.schnorr.decrypt_signature(
        oracle.secret_keys.unwrap().white,
        white_att.adaptor_sig.clone(),
    );

    let serialized_sig = serde_json::to_string(&white_signature).unwrap();
    let deserialized_sig: schnorr_fun::Signature<Public> =
        serde_json::from_str(&serialized_sig).unwrap();

    match schnorr.recover_decryption_key(&white_att.key, &white_att.adaptor_sig, &deserialized_sig)
    {
        Some(decryption_key) => {
            println!("white decrypted key!! {}", decryption_key);
            assert_eq!(schnorr.encryption_key_for(&decryption_key), white_att.key);
        }
        None => eprintln!("signature is not the decryption of our original encrypted signature"),
    }
}
