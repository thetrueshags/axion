use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing_subscriber::FmtSubscriber;
use warp::http::Method;
use warp::Filter;

use axion_core::{AccessPolicy, AxionBlock, BlockPayload, GlobalState};
use axion_crypto::{EncryptionKeypair, IdentityPoW, Keypair};
use axion_net::AxionP2P;

#[derive(Parser)]
#[command(name = "axion")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Start,
    Init,
    Reset,
}

#[derive(Serialize, Deserialize, Clone)]
struct NodeConfig {
    node_name: String,
    rpc_port: u16,
    db_path: String,
    bootstrap_peers: Vec<String>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_name: "Axion-Node".to_string(),
            rpc_port: 3030,
            db_path: "./axion_db".to_string(),
            bootstrap_peers: vec![],
        }
    }
}

struct NodeContext {
    state: Arc<GlobalState>,
    cmd_tx: mpsc::Sender<AxionBlock>,
    did: String,
    sign_keys: Keypair,
    enc_keys: EncryptionKeypair,
    sync_req_tx: mpsc::Sender<PeerId>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistentIdentity {
    signing: Keypair,
    encryption: EncryptionKeypair,
    pow: IdentityPoW,
}

#[derive(Deserialize)]
struct AnnounceRequest {
    did: Option<String>,
    encryption_key: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;
    let cli = Cli::parse();
    match &cli.command {
        Commands::Init => handle_init().await,
        Commands::Start => handle_start().await,
        Commands::Reset => handle_reset(),
    }
}

async fn handle_init() -> Result<()> {
    if !Path::new("config.toml").exists() {
        let config = NodeConfig::default();
        fs::write("config.toml", toml::to_string_pretty(&config)?)?;
        println!("✅ Created default 'config.toml'");
    }
    if !Path::new("identity.json").exists() {
        let (_, _, did) = load_or_create_identity("identity.json")?;
        println!("✅ Identity Minted: {}", did);
    }
    Ok(())
}

async fn handle_start() -> Result<()> {
    if !Path::new("config.toml").exists() || !Path::new("identity.json").exists() {
        return Err(anyhow!("Run 'axion init' first"));
    }
    let config: NodeConfig = toml::from_str(&fs::read_to_string("config.toml")?)?;
    let (sign_keys, enc_keys, did) = load_or_create_identity("identity.json")?;
    println!("👤 DID: {}", did);

    let state = Arc::new(GlobalState::load(&config.db_path)?);
    if state.get_canonical_head()?.is_empty() {
        let genesis = create_block(
            0,
            vec!["0".repeat(64)],
            &sign_keys,
            &did,
            BlockPayload::Genesis {
                message: "Axion Network Live".into(),
            },
        )?;
        state.apply_genesis(&genesis)?;
    }

    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let (event_tx, mut event_rx) = mpsc::channel(32);
    let (sync_req_tx, sync_req_rx) = mpsc::channel(32);
    let bootstrap = config.bootstrap_peers.first().cloned();

    let mut p2p = AxionP2P::new(
        "axion-mainnet",
        cmd_rx,
        event_tx,
        sync_req_rx,
        bootstrap,
        state.clone(),
    )
    .await
    .map_err(|e| anyhow!("P2P Layer Failed: {}", e))?;

    tokio::spawn(async move {
        p2p.run().await;
    });

    let ctx = Arc::new(NodeContext {
        state: state.clone(),
        cmd_tx: cmd_tx.clone(),
        did: did.clone(),
        sign_keys: sign_keys.clone(),
        enc_keys: enc_keys.clone(),
        sync_req_tx: sync_req_tx.clone(),
    });

    let rpc_routes = build_routes(ctx);
    let rpc_port = config.rpc_port;
    tokio::spawn(async move {
        println!("🌍 RPC API listening on http://127.0.0.1:{}", rpc_port);
        warp::serve(rpc_routes)
            .run(([127, 0, 0, 1], rpc_port))
            .await;
    });

    println!("🟢 Node Online. Processing Mesh events...");

    while let Some(block) = event_rx.recv().await {
        if block.is_valid() {
            if state.get_block(&block.hash)?.is_none() {
                match state.process_block(&block) {
                    Ok(_) => println!(
                        "✅ Synced Block #{} (Hash: {}...)",
                        block.index,
                        &block.hash[0..8]
                    ),
                    Err(e) => eprintln!("❌ Block Rejection: {}", e),
                }
            }
        }
    }
    Ok(())
}

fn handle_reset() -> Result<()> {
    let _ = fs::remove_dir_all("axion_db");
    let _ = fs::remove_file("config.toml");
    println!("✅ Reset Complete.");
    Ok(())
}

fn build_routes(
    ctx: Arc<NodeContext>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let cors = warp::cors()
        .allow_any_origin()
        .allow_methods(vec![Method::GET, Method::POST])
        .allow_headers(vec!["content-type"]);

    let announce_route = warp::path("announce_key")
        .and(warp::post())
        .and(warp::body::json())
        .map({
            let ctx = ctx.clone();
            move |req: AnnounceRequest| {
                let target_did = req.did.unwrap_or(ctx.did.clone());
                let target_key_bytes = if let Some(hex_key) = req.encryption_key {
                    hex::decode(hex_key).unwrap_or(ctx.enc_keys.public.clone())
                } else {
                    ctx.enc_keys.public.clone()
                };

                let payload = BlockPayload::IdentityUpdate {
                    did: target_did.clone(),
                    new_encryption_key: target_key_bytes,
                };
                match submit_block_sync(&ctx, payload) {
                    Ok(_) => warp::reply::json(&"Key Announced and Committed"),
                    Err(e) => warp::reply::json(&format!("Error: {}", e)),
                }
            }
        });

    let publish_route = warp::path("publish")
        .and(warp::post())
        .and(warp::body::json())
        .map({
            let ctx = ctx.clone();
            move |json: serde_json::Value| {
                let mode = json["type"].as_str().unwrap_or("public");
                let data_hex = json["data"].as_str().unwrap_or("");
                let data_bytes = hex::decode(data_hex).unwrap_or_default();

                if mode == "private" {
                    let raw_recipient = json["recipient"].as_str().unwrap_or("");
                    let lookup_key = if raw_recipient.starts_with("did:axion:") {
                        raw_recipient.to_string()
                    } else {
                        format!("did:axion:{}", raw_recipient)
                    };

                    match ctx.state.get_validator(&lookup_key) {
                        Ok(Some(val)) => {
                            let (kem, nonce, cipher) =
                                axion_crypto::hybrid_encrypt(&val.encryption_key, &data_bytes)
                                    .unwrap();
                            let mut key_map = std::collections::HashMap::new();
                            key_map.insert(lookup_key.clone(), (kem, nonce));

                            let payload = BlockPayload::DataStore {
                                policy: AccessPolicy::Private {
                                    recipient: lookup_key.into(),
                                },
                                blob: cipher,
                                keys: key_map,
                            };
                            let _ = submit_block_sync(&ctx, payload);
                            warp::reply::json(&"Data Double-Encrypted & Published")
                        }
                        _ => warp::reply::json(&"Error: DID not found"),
                    }
                } else {
                    warp::reply::json(&"Public not supported")
                }
            }
        });

    let list_route = warp::path!("api" / "vault" / String).and(warp::get()).map({
        let ctx = ctx.clone();
        move |target_did: String| {
            let all_blocks = ctx.state.get_recent_blocks(100).unwrap_or_default();

            let my_secrets: Vec<AxionBlock> = all_blocks
                .into_iter()
                .filter_map(|b| {
                    if let BlockPayload::DataStore { policy, .. } = &b.payload {
                        match policy {
                            AccessPolicy::Private { recipient } if recipient == &target_did => {
                                ctx.state.get_block(&b.hash).ok().flatten()
                            }
                            _ => None,
                        }
                    } else {
                        None
                    }
                })
                .collect();

            warp::reply::json(&my_secrets)
        }
    });

    let sync_trigger = warp::path!("api" / "sync" / String).and(warp::post()).map({
        let ctx = ctx.clone();
        move |peer_str: String| {
            if let Ok(peer_id) = peer_str.parse::<PeerId>() {
                let _ = ctx.sync_req_tx.try_send(peer_id);
                warp::reply::json(&"Sync Triggered")
            } else {
                warp::reply::json(&"Invalid Peer ID")
            }
        }
    });

    announce_route
        .or(publish_route)
        .or(list_route)
        .or(sync_trigger)
        .with(cors)
}

fn submit_block_sync(ctx: &NodeContext, payload: BlockPayload) -> Result<()> {
    let parent = ctx.state.get_canonical_head().unwrap_or("0".repeat(64));
    let block = create_block(1, vec![parent], &ctx.sign_keys, &ctx.did, payload)?;

    let tx = ctx.cmd_tx.clone();
    let block_clone = block.clone();
    tokio::spawn(async move {
        let _ = tx.send(block_clone).await;
    });

    ctx.state
        .process_block(&block)
        .map_err(|e| anyhow!("State Write Failed: {}", e))?;
    println!("💾 State Sync: Block #{} committed.", block.index);
    Ok(())
}

fn create_block(
    idx: u64,
    parents: Vec<String>,
    keys: &Keypair,
    did: &str,
    payload: BlockPayload,
) -> Result<AxionBlock> {
    let mut b = AxionBlock::new(
        idx,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        parents,
        did.to_string(),
        payload,
        keys.public.clone(),
    );
    b.hash = b.calculate_hash();
    b.signature = keys.sign(&hex::decode(&b.hash)?)?;
    Ok(b)
}

fn load_or_create_identity(path: &str) -> Result<(Keypair, EncryptionKeypair, String)> {
    if let Ok(data) = fs::read(path) {
        if let Ok(identity) = serde_json::from_slice::<PersistentIdentity>(&data) {
            let did = axion_crypto::PublicKey::from_bytes(&identity.signing.public).to_did_hash();
            return Ok((identity.signing, identity.encryption, did));
        }
    }
    let s_keys = Keypair::generate();
    let e_keys = EncryptionKeypair::generate();
    let pow = IdentityPoW::mint(&s_keys.public, 16);
    let did = axion_crypto::PublicKey::from_bytes(&s_keys.public).to_did_hash();
    let identity = PersistentIdentity {
        signing: s_keys.clone(),
        encryption: e_keys.clone(),
        pow,
    };
    fs::write(path, serde_json::to_string_pretty(&identity)?)?;
    Ok((s_keys, e_keys, did))
}
