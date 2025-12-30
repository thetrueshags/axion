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
        Commands::Reset => {
            let _ = fs::remove_dir_all("axion_db");
            let _ = fs::remove_file("config.toml");
            println!("✅ Reset Complete.");
            Ok(())
        }
    }
}

async fn handle_init() -> Result<()> {
    if !Path::new("config.toml").exists() {
        fs::write(
            "config.toml",
            toml::to_string_pretty(&NodeConfig::default())?,
        )?;
        println!("✅ Config created.");
    }
    if !Path::new("identity.json").exists() {
        let (_, _, did) = load_or_create_identity("identity.json")?;
        println!("✅ Identity Minted: {}", did);
    }
    Ok(())
}

async fn handle_start() -> Result<()> {
    if !Path::new("config.toml").exists() {
        return Err(anyhow!("Run 'init' first"));
    }

    let config: NodeConfig = toml::from_str(&fs::read_to_string("config.toml")?)?;
    let (sign_keys, enc_keys, did) = load_or_create_identity("identity.json")?;
    println!("👤 DID: {}\n🌍 Bootstrapping...", did);

    let state = Arc::new(GlobalState::load(&config.db_path)?);

    if state.get_canonical_head()?.is_empty() {
        let genesis = create_block(
            0,
            vec!["0".repeat(64)],
            &sign_keys,
            &did,
            BlockPayload::Genesis {
                message: "Axion Mainnet".into(),
            },
        )?;
        state.apply_genesis(&genesis)?;
    }

    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let (event_tx, mut event_rx) = mpsc::channel(32);
    let (sync_req_tx, sync_req_rx) = mpsc::channel(32);

    let mut p2p = AxionP2P::new(
        "axion-mainnet",
        cmd_rx,
        event_tx,
        sync_req_rx,
        config.bootstrap_peers,
        state.clone(),
    )
    .await
    .map_err(|e| anyhow!("P2P Layer Initialization Failed: {}", e))?;

    tokio::spawn(async move {
        p2p.run().await;
    });

    let ctx = Arc::new(NodeContext {
        state: state.clone(),
        cmd_tx: cmd_tx.clone(),
        did,
        sign_keys,
        enc_keys,
        sync_req_tx,
    });

    let routes = build_routes(ctx);
    tokio::spawn(async move {
        println!(
            "🌍 RPC API listening on http://127.0.0.1:{}",
            config.rpc_port
        );
        warp::serve(routes)
            .run(([127, 0, 0, 1], config.rpc_port))
            .await;
    });

    println!("🟢 Online. Processing events...");

    while let Some(block) = event_rx.recv().await {
        if block.is_valid() {
            if let Err(e) = state.process_block(&block) {
                eprintln!("⚠️ Block Rejected: {}", e);
            } else {
                println!("🔗 Synced Block #{}", block.index);
            }
        }
    }
    Ok(())
}

fn build_routes(
    ctx: Arc<NodeContext>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let cors = warp::cors()
        .allow_any_origin()
        .allow_methods(vec![Method::GET, Method::POST])
        .allow_headers(vec!["content-type"]);

    let publish = warp::path("publish")
        .and(warp::post())
        .and(warp::body::json())
        .map({
            let ctx = ctx.clone();
            move |json: serde_json::Value| {
                let target = json["recipient"].as_str().unwrap_or_default();
                let data = hex::decode(json["data"].as_str().unwrap_or("")).unwrap_or_default();

                if let Ok(Some(val)) = ctx.state.get_validator(target) {
                    if let Ok((kem, nonce, cipher)) =
                        axion_crypto::hybrid_encrypt(&val.encryption_key, &data)
                    {
                        let mut keys = std::collections::HashMap::new();
                        keys.insert(target.to_string(), (kem, nonce));

                        let payload = BlockPayload::DataStore {
                            policy: AccessPolicy::Private {
                                recipient: target.into(),
                            },
                            blob: cipher,
                            keys,
                        };
                        let _ = submit_block_sync(&ctx, payload);
                        return warp::reply::json(&"Published");
                    }
                }
                warp::reply::json(&"Error: Recipient not found or encryption failed")
            }
        });

    publish.with(cors)
}

fn submit_block_sync(ctx: &NodeContext, payload: BlockPayload) -> Result<()> {
    let parent = ctx.state.get_canonical_head()?;
    let prev_idx = if let Some(b) = ctx.state.get_block(&parent)? {
        b.index
    } else {
        0
    };

    let block = create_block(
        prev_idx + 1,
        vec![parent],
        &ctx.sign_keys,
        &ctx.did,
        payload,
    )?;

    ctx.state.process_block(&block)?;

    let tx = ctx.cmd_tx.clone();
    tokio::spawn(async move {
        let _ = tx.send(block).await;
    });

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
        if let Ok(id) = serde_json::from_slice::<PersistentIdentity>(&data) {
            let did = axion_crypto::PublicKey::from_bytes(&id.signing.public).to_did_hash();
            return Ok((id.signing, id.encryption, did));
        }
    }
    let s = Keypair::generate();
    let e = EncryptionKeypair::generate();
    let pow = IdentityPoW::mint(&s.public, 16);
    let did = axion_crypto::PublicKey::from_bytes(&s.public).to_did_hash();

    fs::write(
        path,
        serde_json::to_string_pretty(&PersistentIdentity {
            signing: s.clone(),
            encryption: e.clone(),
            pow,
        })?,
    )?;
    Ok((s, e, did))
}
