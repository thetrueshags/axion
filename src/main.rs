use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing_subscriber::FmtSubscriber;
use warp::Filter;
use warp::http::Method; // Required for CORS
use anyhow::{Result, Context, anyhow};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

// Crate Imports
use axion_core::{AxionBlock, BlockPayload, GlobalState, AccessPolicy};
use axion_crypto::{Keypair, EncryptionKeypair, IdentityPoW};
use axion_net::AxionP2P;

// --- 1. CLI DEFINITIONS ---

#[derive(Parser)]
#[command(name = "axion")]
#[command(about = "Axion: The Quantum-Safe Decentralized Data Mesh", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Start,
    Init,
    ImportIdentity {
        #[arg(short, long)]
        path: String,
    },
    ExportIdentity {
        #[arg(short, long)]
        output: String,
    },
    Info,
    Prune {
        #[arg(long, default_value_t = 2592000)]
        retention: u64,
    },
    Reset,
}

// --- 2. CONFIGURATION MANAGEMENT ---

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

// --- 3. SHARED CONTEXT ---

struct NodeContext {
    state: Arc<GlobalState>,
    cmd_tx: mpsc::Sender<AxionBlock>,
    did: String,
    sign_keys: Keypair,
    enc_keys: EncryptionKeypair,
}

// --- 4. IDENTITY STRUCTURE (Disk Format) ---

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistentIdentity {
    signing: Keypair,
    encryption: EncryptionKeypair,
    pow: IdentityPoW,
}

// --- 5. MAIN ENTRY POINT ---

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let cli = Cli::parse();

    match &cli.command {
        Commands::Init => handle_init().await,
        Commands::Start => handle_start().await,
        Commands::ImportIdentity { path } => handle_import(path).await,
        Commands::ExportIdentity { output } => handle_export(output),
        Commands::Info => handle_info(),
        Commands::Prune { retention } => handle_prune(*retention),
        Commands::Reset => handle_reset(),
    }
}

// --- 6. COMMAND HANDLERS ---

async fn handle_init() -> Result<()> {
    println!("⚙️  Initializing Axion Node...");

    if Path::new("config.toml").exists() {
        println!("⚠️  'config.toml' already exists. Skipping config generation.");
    } else {
        let config = NodeConfig::default();
        let toml_str = toml::to_string_pretty(&config)?;
        fs::write("config.toml", toml_str)?;
        println!("✅ Created default 'config.toml'");
    }

    if Path::new("identity.json").exists() {
        println!("⚠️  'identity.json' already exists. Skipping identity minting.");
    } else {
        let (_, _, did) = load_or_create_identity("identity.json")?;
        println!("✅ Identity Minted: {}", did);
    }

    println!("🚀 Initialization Complete. Run 'axion start' to join the mesh.");
    Ok(())
}

async fn handle_start() -> Result<()> {
    if !Path::new("config.toml").exists() {
        return Err(anyhow!("Config not found. Please run 'axion init' first."));
    }
    if !Path::new("identity.json").exists() {
        return Err(anyhow!("Identity not found. Please run 'axion init' first."));
    }

    let config_str = fs::read_to_string("config.toml")?;
    let config: NodeConfig = toml::from_str(&config_str)?;

    println!("------------------------------------------------");
    println!("Axion: Starting Node '{}'", config.node_name);
    println!("------------------------------------------------");

    let (sign_keys, enc_keys, did) = load_or_create_identity("identity.json")?;
    println!("👤 DID: {}", did);

    let state = Arc::new(GlobalState::load(&config.db_path)?);

    if state.get_canonical_head()?.is_empty() {
        println!("✨ Fresh Database detected. Applying Local Genesis...");
        let genesis = create_block(
            0,
            vec!["0".repeat(64)],
            &sign_keys,
            &did,
            BlockPayload::Genesis { message: "Axion Network Live".into() }
        )?;
        state.apply_genesis(&genesis)?;
    }

    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let (event_tx, mut event_rx) = mpsc::channel(32);

    let bootstrap = config.bootstrap_peers.first().cloned();

    if bootstrap.is_some() {
        println!("🔗 Connecting to DHT Bootstrap Peer...");
    } else {
        println!("📡 Running as standalone/seed. Waiting for mDNS peers...");
    }

    let p2p = AxionP2P::new("axion-mainnet", cmd_rx, event_tx, bootstrap)
        .await
        .map_err(|e| anyhow!("P2P Layer Failed: {}", e))?;

    tokio::spawn(async move {
        let mut active_p2p = p2p;
        active_p2p.run().await;
    });

    let ctx = Arc::new(NodeContext {
        state: state.clone(),
        cmd_tx,
        did: did.clone(),
        sign_keys: sign_keys.clone(),
        enc_keys: enc_keys.clone(),
    });

    let rpc_routes = build_routes(ctx);
    let rpc_port = config.rpc_port;

    tokio::spawn(async move {
        println!("🌍 RPC API listening on http://127.0.0.1:{}", rpc_port);
        warp::serve(rpc_routes).run(([127, 0, 0, 1], rpc_port)).await;
    });

    println!("🟢 Node Online. Joining the Blob...");

    while let Some(block) = event_rx.recv().await {
        if block.is_valid() {
            match state.process_block(&block) {
                Ok(_) => println!("✅ Synced Block #{} (Hash: {}...)", block.index, &block.hash[0..8]),
                Err(e) => eprintln!("❌ Block Rejection: {}", e),
            }
        } else {
            eprintln!("⚠️  Dropped Invalid Block (Bad Signature/Hash)");
        }
    }
    Ok(())
}

async fn handle_import(source_path: &str) -> Result<()> {
    if !Path::new(source_path).exists() {
        return Err(anyhow!("Source file not found: {}", source_path));
    }

    println!("🔄 Importing identity from '{}'...", source_path);
    let data = fs::read(source_path)?;
    let _: PersistentIdentity = serde_json::from_slice(&data)
        .context("File is not a valid Axion Identity JSON")?;

    fs::copy(source_path, "identity.json")?;
    println!("✅ Identity Imported Successfully.");
    Ok(())
}

fn handle_export(dest_path: &str) -> Result<()> {
    if !Path::new("identity.json").exists() {
        return Err(anyhow!("No active identity found. Run 'axion init' first."));
    }
    fs::copy("identity.json", dest_path)?;
    println!("💾 Identity exported to '{}'", dest_path);
    Ok(())
}

fn handle_info() -> Result<()> {
    if !Path::new("identity.json").exists() {
        return Err(anyhow!("Node is not initialized. Run 'axion init'."));
    }
    let (_, _, did) = load_or_create_identity("identity.json")?;

    println!("--- Axion Node Status ---");
    println!("👤 Identity (DID): {}", did);

    if Path::new("config.toml").exists() {
        let config: NodeConfig = toml::from_str(&fs::read_to_string("config.toml")?)?;
        println!("📂 Database Path:  {}", config.db_path);
        println!("🌐 RPC Port:       {}", config.rpc_port);
    }
    println!("-------------------------");
    Ok(())
}

fn handle_prune(retention: u64) -> Result<()> {
    if !Path::new("config.toml").exists() {
        return Err(anyhow!("Config not found."));
    }
    let config: NodeConfig = toml::from_str(&fs::read_to_string("config.toml")?)?;

    println!("🧹 Starting Garbage Collection...");
    println!("📉 Pruning blocks older than {} seconds...", retention);

    let state = GlobalState::load(&config.db_path)?;
    let count = state.prune_stale_data(retention)?;

    println!("✅ Pruning Complete. Removed {} stale items.", count);
    Ok(())
}

fn handle_reset() -> Result<()> {
    println!("⚠️  DANGER ZONE ⚠️");
    println!("This will permanently DELETE your local database and configuration.");
    println!("Type 'RESET' to confirm:");

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    if input.trim() == "RESET" {
        println!("💥 Wiping data...");
        if Path::new("axion_db").exists() { fs::remove_dir_all("axion_db")?; }
        if Path::new("config.toml").exists() { fs::remove_file("config.toml")?; }
        println!("✅ Reset Complete. Run 'axion init' to start fresh.");
    } else {
        println!("❌ Cancelled.");
    }
    Ok(())
}

// --- 7. HELPER FUNCTIONS ---

fn build_routes(ctx: Arc<NodeContext>) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {

    // 1. CORS Policy
    let cors = warp::cors()
        .allow_any_origin()
        .allow_methods(vec![Method::GET, Method::POST])
        .allow_headers(vec!["content-type"]);

    let announce_route = warp::path("announce_key")
        .and(warp::post())
        .map({
            let ctx = ctx.clone();
            move || {
                let payload = BlockPayload::IdentityUpdate {
                    did: ctx.did.clone(),
                    new_encryption_key: ctx.enc_keys.public.clone()
                };
                submit_block(&ctx, payload);
                warp::reply::json(&"Key Announced")
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

                let (policy, blob, keys) = match mode {
                    "public" => (AccessPolicy::Public, data_bytes, std::collections::HashMap::new()),
                    "private" => {
                        let recipient_did = json["recipient"].as_str().unwrap_or("");
                        if let Ok(Some(val)) = ctx.state.get_validator(recipient_did) {
                            if val.encryption_key.is_empty() {
                                return warp::reply::json(&"Error: Recipient has no Kyber key registered");
                            }
                            let (kem, nonce, cipher) = axion_crypto::hybrid_encrypt(&val.encryption_key, &data_bytes).unwrap();
                            let mut key_map = std::collections::HashMap::new();
                            key_map.insert(recipient_did.to_string(), (kem, nonce));
                            (AccessPolicy::Private { recipient: recipient_did.into() }, cipher, key_map)
                        } else {
                            return warp::reply::json(&"Error: Recipient DID not found in state");
                        }
                    },
                    _ => (AccessPolicy::Public, vec![], std::collections::HashMap::new())
                };

                let payload = BlockPayload::DataStore { policy, blob, keys };
                submit_block(&ctx, payload);
                warp::reply::json(&"Data Published to Mesh")
            }
        });

    let query_route = warp::path!("query" / String)
        .and(warp::get())
        .map({
            let ctx = ctx.clone();
            move |hash: String| {
                match ctx.state.get_block(&hash) {
                    Ok(Some(block)) => warp::reply::json(&block),
                    Ok(None) => warp::reply::json(&"Error: Block not found"),
                    Err(e) => warp::reply::json(&format!("Error: {}", e)),
                }
            }
        });

    let state_route = warp::path("state")
        .and(warp::get())
        .map(|| {
            warp::reply::json(&"Node is Active.")
        });

    // NEW: API for Explorer - Recent Blocks
    let blocks_route = warp::path!("api" / "blocks")
        .and(warp::get())
        .map({
            let ctx = ctx.clone();
            move || {
                let blocks = ctx.state.get_recent_blocks(50).unwrap_or_default();
                warp::reply::json(&blocks)
            }
        });

    // NEW: API for Explorer - Stats
    let stats_route = warp::path!("api" / "stats")
        .and(warp::get())
        .map({
            let ctx = ctx.clone();
            move || {
                let (blocks, peers, cas) = ctx.state.get_stats().unwrap_or((0,0,0));
                warp::reply::json(&serde_json::json!({
                    "block_height": blocks,
                    "known_peers": peers,
                    "cas_objects": cas,
                    "node_did": ctx.did
                }))
            }
        });

    // NEW: Serve Explorer UI
    // Access at http://localhost:3030/ui
    let ui_route = warp::path("ui")
        .and(warp::fs::file("explorer.html"));

    announce_route
        .or(publish_route)
        .or(query_route)
        .or(state_route)
        .or(blocks_route)
        .or(stats_route)
        .or(ui_route)
        .with(cors)
}

fn submit_block(ctx: &NodeContext, payload: BlockPayload) {
    let parent = ctx.state.get_canonical_head().unwrap_or("0".repeat(64));

    if let Ok(block) = create_block(1, vec![parent], &ctx.sign_keys, &ctx.did, payload) {
        println!("🚀 Locally Minted Block #{} (Hash: {}...)", block.index, &block.hash[0..8]);

        let tx = ctx.cmd_tx.clone();
        let block_clone = block.clone();

        tokio::spawn(async move {
            if let Err(e) = tx.send(block_clone).await {
                eprintln!("❌ Failed to send block to P2P layer: {}", e);
            }
        });

        if let Err(e) = ctx.state.process_block(&block) {
            eprintln!("❌ Failed to commit local block: {}", e);
        }
    } else {
        eprintln!("❌ Failed to create block");
    }
}

fn create_block(idx: u64, parents: Vec<String>, keys: &Keypair, did: &str, payload: BlockPayload) -> Result<AxionBlock> {
    let mut b = AxionBlock::new(
        idx,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        parents,
        did.to_string(),
        payload,
        keys.public.clone()
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

    println!("⛏️  Minting new Quantum Identity (Difficulty: 16)...");
    let s_keys = Keypair::generate();
    let e_keys = EncryptionKeypair::generate();

    let pow = IdentityPoW::mint(&s_keys.public, 16);
    println!("✅ PoW Solved! Nonce: {}", pow.nonce);

    let did = axion_crypto::PublicKey::from_bytes(&s_keys.public).to_did_hash();

    let identity = PersistentIdentity {
        signing: s_keys.clone(),
        encryption: e_keys.clone(),
        pow,
    };

    let json = serde_json::to_string_pretty(&identity).context("Failed to serialize identity")?;
    fs::write(path, json).context("Failed to save identity file")?;

    Ok((s_keys, e_keys, did))
}