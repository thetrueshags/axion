use anyhow::{anyhow, Context, Result};
use axion_crypto::{verify_signature, PublicKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use sled::Tree;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

const MIN_RW_TO_PUBLISH: u64 = 50;
const PROOF_BASE_REWARD: u64 = 10;
const SLASH_PENALTY: u64 = 5000;
const CHUNK_SIZE: usize = 1024;
const REPLICATION_TARGET: usize = 8;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum AccessPolicy {
    Public,
    Private { recipient: String },
    Group { members: Vec<String> },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum BlockPayload {
    Genesis {
        message: String,
    },
    CapacityAnnouncement {
        capacity_bytes: u64,
    },
    DataStore {
        policy: AccessPolicy,
        blob: Vec<u8>,
        keys: HashMap<String, (Vec<u8>, Vec<u8>)>,
        merkle_root: String,
    },
    CustodyProof {
        challenge_block_hash: String,
        chunk_index: usize,
        chunk_data: Vec<u8>,
        merkle_path: Vec<String>,
    },
    IdentityUpdate {
        did: String,
        new_encryption_key: Vec<u8>,
    },
    SlashingReport {
        accused_did: String,
        reason: String,
    },
}

impl BlockPayload {
    pub fn get_keys_for(&self, did: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        if let BlockPayload::DataStore { keys, .. } = self {
            let raw_did = did.replace("did:axion:", "");
            if let Some(k) = keys.get(did).or_else(|| keys.get(&raw_did)) {
                return Ok(k.clone());
            }
            Err(anyhow!("Access Denied: No keys found for DID: {}", did))
        } else {
            Err(anyhow!("Not a DataStore block"))
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AxionBlock {
    pub index: u64,
    pub timestamp: u64,
    pub parent_hashes: Vec<String>,
    pub author_did: String,
    pub payload: BlockPayload,
    pub author_public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub hash: String,
}

impl AxionBlock {
    pub fn new(
        idx: u64,
        ts: u64,
        parents: Vec<String>,
        did: String,
        payload: BlockPayload,
        pk: Vec<u8>,
    ) -> Self {
        Self {
            index: idx,
            timestamp: ts,
            parent_hashes: parents,
            author_did: did,
            payload,
            author_public_key: pk,
            signature: vec![],
            hash: String::new(),
        }
    }

    pub fn calculate_hash(&self) -> String {
        let mut hasher = Sha3_256::new();
        let data = bincode::serialize(&(
            self.index,
            self.timestamp,
            &self.parent_hashes,
            &self.author_did,
            &self.payload,
            &self.author_public_key,
        ))
        .expect("Serialization failure");
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    pub fn is_valid(&self) -> bool {
        if self.hash != self.calculate_hash() {
            return false;
        }
        let pk = PublicKey::from_bytes(&self.author_public_key);
        if pk.to_did_hash() != self.author_did {
            return false;
        }
        let msg = hex::decode(&self.hash).unwrap_or_default();
        if msg.is_empty() {
            return false;
        }
        verify_signature(&self.author_public_key, &msg, &self.signature)
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct StoredBlock {
    block: AxionBlock,
    blob_hash: Option<String>,
    cumulative_reputation: u128,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ValidatorState {
    pub rw: u64,
    pub last_seen: u64,
    pub encryption_key: Vec<u8>,
    pub storage_capacity: u64,
    pub proved_shards: u64,
}

pub struct GlobalState {
    blocks: Tree,
    validators: Tree,
    metadata: Tree,
    cas: Tree,
    heights: Tree,
}

impl GlobalState {
    pub fn load(path: &str) -> Result<Self> {
        let db = sled::open(path).context("DB Open Failed")?;
        Ok(Self {
            blocks: db.open_tree("blocks")?,
            validators: db.open_tree("validators")?,
            metadata: db.open_tree("metadata")?,
            cas: db.open_tree("cas")?,
            heights: db.open_tree("heights")?,
        })
    }

    pub fn get_canonical_head(&self) -> Result<String> {
        match self.metadata.get("head_hash")? {
            Some(b) => Ok(String::from_utf8(b.to_vec())?),
            None => Ok(String::new()),
        }
    }

    pub fn process_block(&self, block: &AxionBlock) -> Result<()> {
        if self.blocks.contains_key(&block.hash)? {
            return Ok(());
        }

        let mut author = self.get_validator(&block.author_did)?.unwrap_or(ValidatorState {
            rw: 0,
            last_seen: block.timestamp,
            encryption_key: vec![],
            storage_capacity: 0,
            proved_shards: 0,
        });

        match &block.payload {
            BlockPayload::CapacityAnnouncement { capacity_bytes } => {
                author.storage_capacity = *capacity_bytes;
            },

            BlockPayload::DataStore { merkle_root, blob, .. } => {
                if author.rw < MIN_RW_TO_PUBLISH {
                    return Err(anyhow!("⛔ INSUFFICIENT RW: Need {} to publish.", MIN_RW_TO_PUBLISH));
                }

                if !blob.is_empty() {
                    let calculated_root = calculate_merkle_root(blob);
                    if &calculated_root != merkle_root {
                         return Err(anyhow!("⛔ INVALID MERKLE ROOT: Data corruption detected."));
                    }
                }
            },

            BlockPayload::CustodyProof { challenge_block_hash, chunk_index, chunk_data, merkle_path } => {
                let target_block_opt = self.get_block(challenge_block_hash)?;

                if let Some(target_block) = target_block_opt {
                    if let BlockPayload::DataStore { merkle_root, .. } = &target_block.payload {
                        if verify_merkle_proof(chunk_data, *chunk_index, merkle_path, merkle_root) {

                            if self.is_node_responsible_for_shard(&block.author_did, challenge_block_hash) {
                                let cap_factor = (author.storage_capacity as f64).log2().max(1.0) as u64;
                                let reward = PROOF_BASE_REWARD * cap_factor;

                                author.rw += reward;
                                author.proved_shards += 1;
                            } else {
                                author.rw += 1;
                            }
                        } else {
                            author.rw = author.rw.saturating_sub(SLASH_PENALTY);
                        }
                    }
                } else {
                    author.rw = author.rw.saturating_sub(10);
                }
            },

            BlockPayload::SlashingReport { accused_did, .. } => {
                if let Some(mut bad) = self.get_validator(accused_did)? {
                    bad.rw = bad.rw.saturating_sub(SLASH_PENALTY);
                    bad.proved_shards = 0;
                    self.save_validator(accused_did, bad)?;
                    author.rw += 50;
                }
            },

            BlockPayload::IdentityUpdate { did, new_encryption_key } => {
                 let mut t = self.get_validator(did)?.unwrap_or(ValidatorState {
                    rw: 0, last_seen: 0, encryption_key: vec![], storage_capacity: 0, proved_shards: 0
                 });
                 t.encryption_key = new_encryption_key.clone();
                 self.save_validator(did, t)?;
            },

            _ => {}
        }

        author.last_seen = block.timestamp;
        self.save_validator(&block.author_did, author.clone())?;

        let mut parent_weight = 0u128;
        if let Some(p) = block.parent_hashes.first() {
            if let Some(sb) = self.get_stored_block_internal(p)? {
                parent_weight = sb.cumulative_reputation;
            }
        }
        let new_weight = parent_weight + (author.rw as u128);

        self.save_block_internal(block, new_weight)?;
        self.update_head_if_heavier(block.hash.clone(), new_weight)?;

        Ok(())
    }

    fn is_node_responsible_for_shard(&self, did: &str, block_hash: &str) -> bool {
        let node_hash = Sha3_256::digest(did.as_bytes());
        let content_hash = hex::decode(block_hash).unwrap_or(vec![0u8; 32]);

        let distance = xor_distance(&node_hash, &content_hash);

        // radius = MaxDistance / NumNodes.
        distance[0] < 32
    }

    fn update_head_if_heavier(&self, new_hash: String, new_weight: u128) -> Result<()> {
        let current_max_bytes = self.metadata.get("max_reputation")?.unwrap_or_default();
        let current_max = if current_max_bytes.is_empty() { 0 } else {
             let arr: [u8; 16] = current_max_bytes.as_ref().try_into().unwrap_or([0; 16]);
             u128::from_be_bytes(arr)
        };
        if new_weight > current_max {
            self.metadata.insert("max_reputation", &new_weight.to_be_bytes())?;
            self.metadata.insert("head_hash", new_hash.as_bytes())?;
        }
        Ok(())
    }

    fn save_block_internal(&self, block: &AxionBlock, weight: u128) -> Result<()> {
        let mut skeleton = block.clone();
        let mut extracted_hash = None;
        if let BlockPayload::DataStore { blob, .. } = &mut skeleton.payload {
            if !blob.is_empty() {
                let mut h = Sha3_256::new(); h.update(&blob);
                let bh = hex::encode(h.finalize());
                self.cas.insert(&bh, blob.as_slice())?;
                *blob = Vec::new();
                extracted_hash = Some(bh);
            }
        }
        let stored = StoredBlock { block: skeleton, blob_hash: extracted_hash, cumulative_reputation: weight };
        self.blocks.insert(&block.hash, bincode::serialize(&stored)?)?;

        let h_key = block.index.to_be_bytes();
        let mut hashes: Vec<String> = self.heights.get(&h_key)?.map(|v| bincode::deserialize(&v).unwrap()).unwrap_or_default();
        if !hashes.contains(&block.hash) { hashes.push(block.hash.clone()); }
        self.heights.insert(&h_key, bincode::serialize(&hashes)?)?;

        Ok(())
    }

    pub fn get_block(&self, hash: &str) -> Result<Option<AxionBlock>> {
        if let Some(stored) = self.get_stored_block_internal(hash)? {
            let mut full = stored.block;
            if let Some(bh) = stored.blob_hash {
                if let Some(blob) = self.cas.get(&bh)? {
                    if let BlockPayload::DataStore { blob: b_target, .. } = &mut full.payload {
                        *b_target = blob.to_vec();
                    }
                }
            }
            Ok(Some(full))
        } else { Ok(None) }
    }

    fn get_stored_block_internal(&self, hash: &str) -> Result<Option<StoredBlock>> {
        match self.blocks.get(hash)? {
            Some(b) => Ok(Some(bincode::deserialize(&b)?)),
            None => Ok(None)
        }
    }

    pub fn get_validator(&self, did: &str) -> Result<Option<ValidatorState>> {
        match self.validators.get(did)? {
            Some(b) => Ok(Some(bincode::deserialize(&b)?)),
            None => Ok(None)
        }
    }

    fn save_validator(&self, did: &str, val: ValidatorState) -> Result<()> {
        self.validators.insert(did, bincode::serialize(&val)?)?;
        Ok(())
    }

    pub fn apply_genesis(&self, block: &AxionBlock) -> Result<()> {
        self.save_block_internal(block, 1000)?;
        self.metadata.insert("genesis_hash", block.hash.as_bytes())?;
        self.metadata.insert("head_hash", block.hash.as_bytes())?;
        let val = ValidatorState {
            rw: 1000, last_seen: block.timestamp, encryption_key: vec![],
            storage_capacity: 1024 * 1024 * 1024,
            proved_shards: 0
        };
        self.save_validator(&block.author_did, val)?;
        Ok(())
    }

    pub fn get_recent_blocks(&self, limit: usize) -> Result<Vec<AxionBlock>> {
         let mut res = Vec::new();
         for item in self.heights.iter().rev() {
             let (_, v) = item?;
             let hashes: Vec<String> = bincode::deserialize(&v)?;
             for h in hashes { if let Some(b) = self.get_block(&h)? { res.push(b); } }
             if res.len() >= limit { break; }
         }
         Ok(res)
    }
}

fn calculate_merkle_root(blob: &[u8]) -> String {
    let chunks: Vec<&[u8]> = blob.chunks(CHUNK_SIZE).collect();
    if chunks.is_empty() { return String::new(); }

    let mut nodes: Vec<String> = chunks.iter().map(|c| {
        let mut h = Sha3_256::new(); h.update(c);
        hex::encode(h.finalize())
    }).collect();

    while nodes.len() > 1 {
        let mut next_level = Vec::new();
        for i in (0..nodes.len()).step_by(2) {
            let left = &nodes[i];
            let right = if i + 1 < nodes.len() { &nodes[i + 1] } else { left };
            let mut h = Sha3_256::new();
            h.update(left); h.update(right);
            next_level.push(hex::encode(h.finalize()));
        }
        nodes = next_level;
    }
    nodes[0].clone()
}

fn verify_merkle_proof(chunk: &[u8], index: usize, path: &[String], root: &str) -> bool {
    let mut h = Sha3_256::new(); h.update(chunk);
    let mut current_hash = hex::encode(h.finalize());
    let mut idx = index;

    for sibling in path {
        let mut h = Sha3_256::new();
        if idx % 2 == 0 {
            h.update(&current_hash); h.update(sibling);
        } else {
            h.update(sibling); h.update(&current_hash);
        }
        current_hash = hex::encode(h.finalize());
        idx /= 2;
    }
    current_hash == root
}

fn xor_distance(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}