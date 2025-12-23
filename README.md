
# Axion: The Quantum-Safe Data Mesh

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Status](https://img.shields.io/badge/status-v0.1--dev-green.svg)
![Consensus](https://img.shields.io/badge/consensus-Reputation%20DAG-orange.svg)
![Cryptography](https://img.shields.io/badge/crypto-Dilithium5%20%2F%20Kyber1024-red.svg)

**Axion** is a decentralized, post-quantum Layer 1 network designed for secure data availability, sovereign identity, and censorship-resistant communication. It replaces the "pay-to-play" gas model with a **Proof of Utility** reputation system, creating a neutral substrate for the next generation of resilient applications.

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
The cryptographic primitives underpinning the modern web and blockchain ecosystem (RSA, ECDSA, BLS) are vulnerable to Shor's Algorithm. A sufficiently powerful quantum computer will eventually break these schemes, rendering traditional immutable ledgers insecure.

**The "Harvest Now, Decrypt Later" Threat:** Adversaries are currently scraping encrypted traffic and blockchain history. Once quantum capability is achieved, this historical data—financial records, private keys, and sensitive IP—will be retroactively exposed.

**Axion is Quantum-Safe from Genesis.** It exclusively uses NIST-standardized Post-Quantum Cryptography (PQC) for all operations:
* **Signatures:** ML-DSA (Dilithium5) - Ensures non-repudiation and integrity.
* **Encryption:** ML-KEM (Kyber-1024) - Ensures privacy and secure key exchange.

### 1.2 The Economic Flaw of "Gas"
Legacy blockchains treat blockspace as a scarce commodity auctioned to the highest bidder. This creates a "Fee Market" that:
1.  **Excludes Utility:** High fees price out non-financial use cases (e.g., identity verification, supply chain tracking).
2.  **Centralizes Power:** Wealthy actors dominate the network.

### 1.3 Solution: Identity-Weighted Consensus
Axion removes the native token and replaces gas fees with **Reputation Weight ($RW$)**.
* **Proof of Utility:** Nodes earn $RW$ by performing useful work—validating blocks, storing data, and propagating state via GossipSub.
* **The Circular Economy:** To use the network, you must contribute to the network. This mirrors the incentives of BitTorrent rather than a stock market.
* **Canonical Spine:** The network reaches consensus via a GHOST-DAG protocol weighted by reputation, ensuring a deterministic ordering of events without a central leader.



---

## 2. Technical Architecture

### 2.1 Hybrid Cryptography
Axion implements a dual-key system for every identity (DID):
1.  **Signing Key (Dilithium5):** Used to authorize transactions and sign blocks.
2.  **Encryption Key (Kyber-1024):** Used to create a shared secret for secure data transmission.



### 2.2 Content-Addressable Storage (CAS)
Axion separates the "Spine" (Consensus) from the "Meat" (Data).
* **The Spine:** Lightweight block headers containing metadata, signatures, and hashes.
* **The Meat:** The actual data blobs are stored in a Content-Addressable Storage (CAS) layer.
* **Deduplication:** If two users publish the exact same file, Axion stores it only once, referencing it by its SHA3-256 hash.



### 2.3 Data Access Control
Unlike "public-only" blockchains, Axion supports granular access control at the protocol layer via **Hybrid Encryption** (Kyber KEM + AES-256-GCM).

| Data Type | Visibility | Mechanism |
| :--- | :--- | :--- |
| **Public** | Everyone | Stored as verified plaintext. |
| **Private** | 1-to-1 | Encrypted with recipient's Kyber Key. |
| **Group** | 1-to-Many | Data encrypted once; "Unlock Key" encrypted for each member. |

---

## 3. Getting Started

### 3.1 Installation
Ensure you have Rust (v1.75+) installed.

```bash
git clone [https://github.com/thetrueshags/axion.git](https://github.com/thetrueshags/axion.git)
cd axion
cargo build --release

```

### 3.2 Running a Node (CLI)

Axion v0.1 features a CLI for node management.

**1. Initialize a new Node (Mint Identity):**

```bash
./target/release/axion init
# Output: ✅ Identity Minted: did:axion:8f7a...

```

**2. Start the Node:**

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

This provides a real-time view of the DAG, peer connectivity, and data inspection.

---

## 4. Developer API

Axion exposes a REST/JSON interface for developers to build sovereign applications.

### 4.1 Announce Identity

Before receiving private data, a node must publish its **Kyber Encryption Key** to the network.

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

Retrieve a block and its payload by hash. If the data is locally available in CAS, it will be returned.

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