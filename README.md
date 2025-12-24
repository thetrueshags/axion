# Axion: The Quantum-Safe Data Mesh

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Status](https://img.shields.io/badge/status-v1.1--production-green.svg)
![Consensus](https://img.shields.io/badge/consensus-Reputation%20DAG-orange.svg)
![Cryptography](https://img.shields.io/badge/crypto-Dilithium5%20%2F%20Kyber1024-red.svg)

**Axion** is a decentralized, post-quantum Layer 1 network designed for secure data availability, sovereign identity, and censorship-resistant communication.

Unlike traditional blockchains that function like a "stock market" for blockspace (where you pay high fees to transact), Axion functions like a **digital immune system**. It replaces the "pay-to-play" gas model with a **Proof of Utility** reputation system, creating a neutral, resilient substrate for the next generation of applications.

---

## Table of Contents
- [1. The Whitepaper](#1-the-whitepaper)
  - [The Post-Quantum Necessity](#11-the-post-quantum-necessity)
  - [The Economic Flaw of "Gas"](#12-the-economic-flaw-of-gas)
  - [Solution: Identity-Weighted Consensus](#13-solution-identity-weighted-consensus)
- [2. Technical Architecture](#2-technical-architecture)
  - [Hybrid Cryptography](#21-hybrid-cryptography)
  - [Content-Addressable Storage (CAS)](#22-content-addressable-storage-cas)
  - [Data Access Control](#23-data-access-control)
- [3. Getting Started](#3-getting-started)
  - [Installation](#31-installation)
  - [Running a Node (CLI)](#32-running-a-node-cli)
  - [The Block Explorer](#33-the-block-explorer)
- [4. Developer API](#4-developer-api)
  - [Announce Identity](#41-announce-identity)
  - [Publish Private Data](#42-publish-private-data)
  - [Query Data](#43-query-data)
- [5. Contributing](#5-contributing)

---

## 1. The Whitepaper

### 1.1 The Post-Quantum Necessity
The cryptographic primitives that currently secure the entire internet and blockchain ecosystem (RSA, ECDSA, BLS) rely on a specific math problem: *factoring large numbers is hard*. However, this is only true for classical computers.

A **Quantum Computer** running Shor's Algorithm will solve these problems almost instantly. This is not a "if" but a "when."

**The "Harvest Now, Decrypt Later" Threat:** Adversaries are currently scraping encrypted traffic, financial records, and blockchain history. They store this encrypted data in massive data centers. Once a sufficiently powerful quantum computer comes online, they will retroactively decrypt *everything*—your past messages, your private keys, and your intellectual property.

**Axion is Quantum-Safe from Genesis.** We do not use "patches" or "upgrades." We exclusively use NIST-standardized Post-Quantum Cryptography (PQC) for all operations:
* **Signatures (Identity):** ML-DSA (Dilithium5) — Ensures that when you sign a transaction, it is mathematically impossible to forge, even with a quantum computer.
* **Encryption (Privacy):** ML-KEM (Kyber-1024) — Ensures that data sent between nodes cannot be read by anyone but the intended recipient.



### 1.2 The Economic Flaw of "Gas"
Legacy blockchains (like Bitcoin or Ethereum) treat "blockspace" (the ability to write data to the ledger) as a scarce commodity to be auctioned off.
* **The Bidding War:** To get your transaction processed, you must outbid others.
* **The Consequence:** This creates a "Fee Market" that prices out regular utility. You cannot build a decentralized chat app or supply chain tracker if every message costs $5.00 to send.
* **Centralization:** Only wealthy actors can afford to use the network during congestion.

### 1.3 Solution: Identity-Weighted Consensus
Axion removes the native token completely. There is no coin to pump, dump, or speculate on. Instead, we use **Reputation Weight ($RW$)**.

* **Proof of Utility:** Nodes earn $RW$ by performing useful work for the network—validating blocks, storing data files, and relaying messages.
* **The Circular Economy:** To use the network, you must contribute to the network. This mirrors the incentives of **BitTorrent**: if you seed (share) files, your download speed increases.
* **Canonical Spine:** Instead of a single-file line (Blockchain), Axion uses a **DAG (Directed Acyclic Graph)**. Imagine a braided rope or a web where multiple blocks can be added simultaneously. The network reaches consensus on the order of events by following the path with the highest total Reputation.



---

## 2. Technical Architecture

### 2.1 Hybrid Cryptography
Axion implements a dual-key system for every identity (DID):
1.  **The Signet Ring (Signing Key - Dilithium5):** You use this to stamp documents. It proves *you* authorized an action. It guarantees integrity and non-repudiation.
2.  **The Safe Box (Encryption Key - Kyber-1024):** You give copies of this box to people who want to send you secrets. Only you have the key to open it. This guarantees privacy.



### 2.2 Content-Addressable Storage (CAS)
Axion solves the "bloat" problem of blockchains by separating the **"Spine"** from the **"Meat"**.

* **The Spine (Consensus):** These are lightweight Block Headers. They contain metadata (who sent it, when, signatures). They are very small and fast to sync.
* **The Meat (Storage):** The actual data (images, code, documents) is stored in a Content-Addressable Storage layer.
* **Deduplication:** If User A uploads a file, and User B uploads the exact same file, Axion realizes they are identical mathematically. It stores the file only once but gives both users a reference to it.

### 2.3 Data Access Control
Unlike "public-only" blockchains where everything is visible to everyone, Axion supports granular access control at the protocol layer via **Hybrid Encryption** (Kyber KEM + AES-256-GCM).

| Data Type | Visibility | Mechanism |
| :--- | :--- | :--- |
| **Public** | Everyone | Stored as verified plaintext. Any node can serve it. |
| **Private** | 1-to-1 | Encrypted with the recipient's Kyber Key. Only they can decrypt the blob. |
| **Group** | 1-to-Many | Data is encrypted once with a symmetric key; that symmetric key is then encrypted individually for each group member. |

---

## 3. Getting Started

### 3.1 Installation
Ensure you have Rust (v1.75+) installed.

```bash
git clone https://github.com/axion-foundation/axion-network.git
cd axion
cargo build --release

```

### 3.2 Running a Node (CLI)

Axion v1.1 features a robust CLI for node management.

**1. Initialize a new Node (Mint Identity):**
This generates your quantum-safe keys and solves a Proof-of-Work puzzle to prevent spam identities.

```bash
./target/release/axion init
# Output: ✅ Identity Minted: did:axion:8f7a...

```

**2. Start the Node:**
Connect to the peer-to-peer mesh and begin syncing the DAG.

```bash
./target/release/axion start
# Output: 🟢 Node Online. Joining the Blob...

```

**3. Pruning (Garbage Collection):**
To free up disk space by removing old blocks (e.g., older than 30 days):

```bash
./target/release/axion prune --retention 2592000

```

### 3.3 The Block Explorer

Every Axion node comes with a built-in visualization dashboard.
Once your node is running, open your browser to:
**`http://127.0.0.1:3030/ui`**

This provides a real-time view of the DAG structure, your connected peers, and allows you to inspect data payloads.

---

## 4. Developer API

Axion exposes a REST/JSON interface for developers to build sovereign applications.

### 4.1 Announce Identity

Before receiving private data, a node must publish its **Kyber Encryption Key** to the network so others know how to message it securely.

```bash
curl -X POST [http://127.0.0.1:3030/announce_key](http://127.0.0.1:3030/announce_key)

```

### 4.2 Publish Private Data

Send encrypted data to another specific DID on the network.

```bash
curl -X POST [http://127.0.0.1:3030/publish](http://127.0.0.1:3030/publish) \
     -H "Content-Type: application/json" \
     -d '{
           "type": "private",
           "recipient": "did:axion:TARGET_DID_HASH",
           "data": "48656c6c6f20576f726c64"
         }'

```

*(Note: Data should be a hex-encoded string).*

### 4.3 Query Data

Retrieve a block and its payload by hash. If the data is locally available in your CAS, it will be returned instantly. If not, your node will attempt to fetch it from the mesh.

```bash
curl [http://127.0.0.1:3030/query/](http://127.0.0.1:3030/query/)<BLOCK_HASH>

```

---

## 5. Contributing

Axion is an open-source project building public infrastructure.

1. **Fork the Repository**
2. **Create a Feature Branch** (`git checkout -b feature/AmazingFeature`)
3. **Commit your Changes** (`git commit -m 'Add some AmazingFeature'`)
4. **Push to the Branch** (`git push origin feature/AmazingFeature`)
5. **Open a Pull Request**

### Contribution Areas

* **Core:** Optimizing the GossipSub propagation or Sled DB storage.
* **Crypto:** Auditing the Dilithium/Kyber implementations.
* **UI:** Enhancing the `explorer.html` visualization.

---

## License

This project is licensed under the MIT License - see the [LICENSE](https://www.google.com/search?q=LICENSE) file for details.

```

```