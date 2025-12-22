# Axion
Axion is a quantum-safe Layer 1 blockchain built in Rust. It provides a secure settlement and data availability layer for rollups using post-quantum cryptography and a reputation-weighted consensus model.

## Core Features
- Post-Quantum Security: Implements Dilithium5 signatures to protect against future quantum computing attacks.

- Reputation Consensus: Uses a Directed Acyclic Graph (DAG) where nodes earn authority through network participation rather than gas fees.

- Built for Rollups: Includes an RPC interface designed for L2 sequencers to submit state roots and ZK-proofs.

- Efficient Networking: Utilizes libp2p Gossipsub for fast block propagation and Sled for persistent storage.

## Running the Node
Build the project using Cargo: cargo build --release

Start a seed node: ./target/release/axion ./db_main

Connect a peer node: ./target/release/axion ./db_peer /ip4/127.0.0.1/tcp/[PORT]

Developer API
Submit rollup data via the RPC endpoint: curl -X POST http://127.0.0.1:3030/submit_rollup -H "Content-Type: application/json" -d '{"tx_count": 100, "state_root": "0x123", "zk_proof": "0x456"}'

Check network state: curl http://127.0.0.1:3030/state