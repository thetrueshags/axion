use std::env;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing_subscriber::FmtSubscriber;
use warp::Filter;

use axion_core::{AxionBlock, BlockPayload, GlobalState};
use axion_crypto::Keypair;
use axion_net::AxionP2P;

struct NodeContext {
    db: sled::Db,
    cmd_tx: mpsc::Sender<AxionBlock>,
    node_did: String,
    node_keys: Keypair,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let args: Vec<String> = env::args().collect();
    let db_path = args.get(1).map(|s| s.as_str()).unwrap_or("./axion_db");
    let bootstrap_peer = args.get(2).cloned();
    let rpc_port = 3030;

    println!("🚀 Starting Axion Platform Node...");
    let state = GlobalState::load(db_path);
    let my_keys = Keypair::generate();
    let my_did = axion_crypto::PublicKey::from_bytes(&my_keys.public).to_did_hash();

    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let (event_tx, mut event_rx) = mpsc::channel(32);

    let p2p = AxionP2P::new("axion-mainnet", cmd_rx, event_tx.clone(), bootstrap_peer).await?;
    tokio::spawn(async move { p2p.run().await; });

    let ctx = Arc::new(NodeContext {
        db: state.db.clone(),
        cmd_tx: cmd_tx.clone(),
        node_did: my_did.clone(),
        node_keys: my_keys.clone(),
    });

    let state_route = warp::path("state")
        .map({
            let ctx = ctx.clone();
            move || {
                let mut validators = std::collections::HashMap::new();
                for item in ctx.db.iter() {
                    if let Ok((k, v)) = item {
                        if let Ok(did) = String::from_utf8(k.to_vec()) {
                            if let Ok(bytes) = <[u8; 8]>::try_from(v.as_ref()) {
                                validators.insert(did, u64::from_be_bytes(bytes));
                            }
                        }
                    }
                }
                warp::reply::json(&validators)
            }
        });

    let submit_route = warp::path("submit_rollup")
        .and(warp::post())
        .and(warp::body::json())
        .and_then({
            let ctx = ctx.clone();
            move |payload: serde_json::Value| {
                let ctx = ctx.clone();
                async move {
                    let tx_count = payload["tx_count"].as_u64().unwrap_or(0) as u32;
                    let state_root = payload["state_root"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    let zk_proof = payload["zk_proof"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();

                    let block_payload = BlockPayload::Standard {
                        tx_count,
                        state_root,
                        zk_proof_root: zk_proof,
                    };

                    let block = match create_block(
                        0,
                        vec!["0".repeat(64)],
                        &ctx.node_keys,
                        &ctx.node_did,
                        block_payload,
                    ) {
                        Ok(block) => block,
                        Err(_) => {
                            return Err(warp::reject::not_found());
                        }
                    };

                    let tx = ctx.cmd_tx.clone();
                    tokio::spawn(async move {
                        let _ = tx.send(block).await;
                    });

                    Ok::<warp::reply::Json, warp::Rejection>(warp::reply::json(&"Block submitted"))
                }
            }
        });

    let routes = state_route.or(submit_route);

    tokio::spawn(async move {
        println!("🌍 RPC API listening on http://127.0.0.1:{}", rpc_port);
        warp::serve(routes).run(([127, 0, 0, 1], rpc_port)).await;
    });

    let mut runtime_state = state;

    loop {
        tokio::select! {
            Some(block) = event_rx.recv() => {
                if block.is_valid() {
                    println!("✅ P2P: Received Block #{} (Hash: {}...)", block.index, &block.hash[0..8]);
                    runtime_state.process_block(&block);
                }
            }
        }
    }
}

fn create_block(
    idx: u64,
    parents: Vec<String>,
    keys: &Keypair,
    did: &str,
    payload: BlockPayload,
) -> Result<AxionBlock, Box<dyn std::error::Error>> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs();
    let mut block = AxionBlock::new(
        idx,
        timestamp,
        parents,
        did.to_string(),
        payload,
        keys.public.clone(),
    );
    block.hash = block.calculate_hash();
    let hash_bytes = hex::decode(&block.hash)?;
    block.signature = keys.sign(&hash_bytes)?;
    Ok(block)
}
