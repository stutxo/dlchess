use std::{collections::HashMap, env, str::FromStr, sync::Arc};

use axum::{
    extract::{Path, State},
    routing::get,
    Router,
};
use rand::rngs::ThreadRng;
use reqwest::Client;
use schnorr_fun::{
    adaptor::{Adaptor, EncryptedSign, EncryptedSignature},
    fun::{marker::*, nonce, KeyPair, Point, Scalar},
    Message, Schnorr, Signature,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use tokio::sync::Mutex;
use tracing::{error, info, Level};

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

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
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

struct Game {
    dl_chess: DLChess,
    secret_keys: HashMap<GameOutcome, Scalar>,
}

#[derive(Clone)]
pub struct ChessOracle {
    schnorr: Schnorr<Sha256, nonce::Synthetic<Sha256, nonce::GlobalRng<ThreadRng>>>,
    signing_keypair: KeyPair<EvenY>,
    games: Arc<Mutex<HashMap<String, Game>>>,
}

impl Default for ChessOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl ChessOracle {
    fn new() -> Self {
        let schnorr = Schnorr::new(nonce::Synthetic::default());

        let oracle_key_str =
            env::var("ORACLE_PRIVATE_KEY").expect("ORACLE_PRIVATE_KEY must be set");

        let oracle_key = Scalar::from_str(&oracle_key_str).expect("Invalid ORACLE_PRIVATE_KEY");

        let signing_keypair = schnorr.new_keypair(oracle_key);

        Self {
            schnorr,
            signing_keypair,
            games: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn generate_game_setup(&self, game_id: String) -> Result<DLChess, String> {
        let client = Client::new();
        let url = format!("https://lichess.org/api/game/{}", game_id);
        let res = client.get(url).send().await;

        let mut games = self.games.lock().await;

        if let Ok(response) = res {
            if response.status().is_success() {
                match response.json::<Value>().await {
                    Ok(json) => {
                        if let Some(game) = games.get_mut(&game_id) {
                            info!("{}: Game status: {}", game_id, json["status"]);
                            if let Some(winner) = json["winner"].as_str() {
                                info!("{}: Winner : {}", game_id, winner);

                                if !game.dl_chess.game_over {
                                    let winning_outcome = match winner {
                                        "white" => GameOutcome::White,
                                        "black" => GameOutcome::Black,
                                        _ => GameOutcome::Draw,
                                    };

                                    let attestation = match winning_outcome {
                                        GameOutcome::White => &game.dl_chess.attestations.white,
                                        GameOutcome::Black => &game.dl_chess.attestations.black,
                                        GameOutcome::Draw => &game.dl_chess.attestations.draw,
                                    };

                                    let secret_key = game.secret_keys[&winning_outcome];
                                    let signature = self.schnorr.decrypt_signature(
                                        secret_key,
                                        attestation.adaptor_sig.clone(),
                                    );

                                    let outcome = Outcome {
                                        signature,
                                        attestation: attestation.clone(),
                                    };

                                    game.dl_chess.outcome = Some(outcome);
                                    game.dl_chess.game_over = true;
                                }
                                Ok(game.dl_chess.clone())
                            } else {
                                info!("{}: Game not over", game_id);
                                Ok(game.dl_chess.clone())
                            }
                        } else {
                            info!("{}: Game not found in cache", game_id);
                            let mut secret_keys = HashMap::new();
                            let mut attestations = HashMap::new();

                            for outcome in
                                &[GameOutcome::White, GameOutcome::Black, GameOutcome::Draw]
                            {
                                let secret_key = Scalar::random(&mut rand::thread_rng());
                                let encrypted_key = self.schnorr.encryption_key_for(&secret_key);

                                let message = Message::<Public>::plain(
                                    match outcome {
                                        GameOutcome::White => "White",
                                        GameOutcome::Black => "Black",
                                        GameOutcome::Draw => "Draw",
                                    },
                                    outcome.message(),
                                );

                                let adaptor_sig = self.schnorr.encrypted_sign(
                                    &self.signing_keypair,
                                    &encrypted_key,
                                    message,
                                );

                                attestations.insert(
                                    *outcome,
                                    Attestation {
                                        key: encrypted_key,
                                        adaptor_sig,
                                        message: outcome.message().to_vec(),
                                    },
                                );

                                secret_keys.insert(*outcome, secret_key);
                            }

                            let dl_chess = DLChess {
                                oracle_public_key: self.signing_keypair.public_key(),
                                attestations: GameAttestations {
                                    white: attestations[&GameOutcome::White].clone(),
                                    black: attestations[&GameOutcome::Black].clone(),
                                    draw: attestations[&GameOutcome::Draw].clone(),
                                },
                                outcome: None,
                                game_id: game_id.clone(),
                                game_over: false,
                            };

                            games.insert(
                                game_id.clone(),
                                Game {
                                    dl_chess: dl_chess.clone(),
                                    secret_keys,
                                },
                            );

                            Ok(dl_chess)
                        }
                    }
                    Err(e) => {
                        error!("Failed to parse JSON: {:?}", e);
                        Err(format!("Failed to parse JSON: {:?}", e))
                    }
                }
            } else {
                error!("Request failed with status: {}", response.status());
                Err(format!(
                    "Request for game ID {} failed with status: {}",
                    game_id,
                    response.status()
                ))
            }
        } else {
            error!("Unexpected error occurred");
            Err("Unexpected error occurred".to_string())
        }

        // Ok(dl_chess)
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    let oracle = ChessOracle::new();

    let app = Router::new()
        .route("/game/:game_id", get(get_game))
        .with_state(oracle);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    tracing::info!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

async fn get_game(Path(game_id): Path<String>, State(oracle): State<ChessOracle>) -> String {
    match oracle.generate_game_setup(game_id.clone()).await {
        Ok(game_setup) => {
            let game = serde_json::to_string(&game_setup).unwrap();
            info!("{}: {}", game_id, game);
            game
        }
        Err(error_message) => {
            info!("Error for game {}: {}", game_id, error_message);
            error_message
        }
    }
}
