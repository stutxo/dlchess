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

#[derive(Serialize, Deserialize, Clone)]
pub struct Attestation {
    key: Point<Normal>,
    adaptor_sig: EncryptedSignature,
    message: Vec<u8>,
}

#[derive(Clone, Copy)]
enum GameOutcome {
    White,
    Black,
    Draw,
}

impl GameOutcome {
    fn message(&self) -> &'static [u8] {
        match self {
            Self::White => b"white",
            Self::Black => b"black",
            Self::Draw => b"draw",
        }
    }
}

pub struct ChessOracle {
    schnorr: Schnorr<Sha256, nonce::Synthetic<Sha256, nonce::GlobalRng<ThreadRng>>>,
    signing_keypair: KeyPair<EvenY>,
    secret_keys: [Scalar; 3], // [white, black, draw]
}

impl Default for ChessOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl ChessOracle {
    pub fn new() -> Self {
        let schnorr = Schnorr::new(nonce::Synthetic::default());
        let signing_keypair = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
        let secret_keys = [(); 3].map(|_| Scalar::random(&mut rand::thread_rng()));

        Self {
            schnorr,
            signing_keypair,
            secret_keys,
        }
    }

    pub fn generate_game_setup(&self) -> DLChess {
        let outcomes = [GameOutcome::White, GameOutcome::Black, GameOutcome::Draw];
        let attestations = outcomes
            .into_iter()
            .enumerate()
            .map(|(i, outcome)| {
                let secret_key = self.secret_keys[i];
                let encrypted_key = self.schnorr.encryption_key_for(&secret_key);
                let message = Message::<Public>::plain("text-bitcoin", outcome.message());
                let adaptor_sig =
                    self.schnorr
                        .encrypted_sign(&self.signing_keypair, &encrypted_key, message);

                (
                    outcome,
                    Attestation {
                        key: encrypted_key,
                        adaptor_sig,
                        message: outcome.message().to_vec(),
                    },
                )
            })
            .collect::<Vec<_>>();

        DLChess {
            public_key: self.signing_keypair.public_key(),
            attestations: GameAttestations {
                white: attestations[0].1.clone(),
                black: attestations[1].1.clone(),
                draw: attestations[2].1.clone(),
            },
        }
    }

    pub fn verify_all_outcomes(&self, attestations: &GameAttestations) {
        let outcomes = [
            ("White", &attestations.white, 0),
            ("Black", &attestations.black, 1),
            ("Draw", &attestations.draw, 2),
        ];

        for (name, attestation, index) in outcomes.iter() {
            if let Some(decryption_key) = self.verify_and_decrypt_with_index(attestation, *index) {
                println!("{} outcome decryption key: {}", name, decryption_key);
            } else {
                println!("{} outcome attestation verification failed.", name);
            }
        }
    }

    pub fn verify_and_decrypt_with_index(
        &self,
        attestation: &Attestation,
        index: usize,
    ) -> Option<Scalar> {
        let message = Message::<Public>::plain("text-bitcoin", &attestation.message);

        if !self.schnorr.verify_encrypted_signature(
            &self.signing_keypair.public_key(),
            &attestation.key,
            message,
            &attestation.adaptor_sig,
        ) {
            return None;
        }

        println!("{} encrypted key: {:?}", index, self.secret_keys[index]);

        let signature = self
            .schnorr
            .decrypt_signature(self.secret_keys[index], attestation.adaptor_sig.clone());

        self.schnorr
            .recover_decryption_key(&attestation.key, &attestation.adaptor_sig, &signature)
    }
}

fn main() {
    let oracle = ChessOracle::new();
    let game_setup = oracle.generate_game_setup();

    oracle.verify_all_outcomes(&game_setup.attestations);

    // Serialize/deserialize example
    let _serialized = serde_json::to_string(&game_setup).unwrap();
}
