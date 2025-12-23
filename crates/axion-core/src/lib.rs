use anyhow::{anyhow, Context, Result};
use axion_crypto::{verify_signature, PublicKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use sled::Tree;
use std::time::{SystemTime, UNIX_EPOCH};

// --- 1. ACCESS CONTROL ---

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum AccessPolicy {
    Public,
    Private { recipient: String },
    Group { members: Vec<String> },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum BlockPayload {
    Genesis {
        message: String,
    },
    DataStore {
        policy: AccessPolicy,
        blob: Vec<u8>,
        keys: std::collections::HashMap<String, (Vec<u8>, Vec<u8>)>,
    },
    IdentityUpdate {
        did: String,
        new_encryption_key: Vec<u8>,
    },
}

// --- 2. BLOCK STRUCTURE (Wire/Consensus Format) ---

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
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

// --- 3. STORAGE STRUCTURES (Disk Format) ---

#[derive(Serialize, Deserialize)]
struct StoredBlock {
    block: AxionBlock,
    blob_hash: Option<String>,
}

// --- 4. STATE MACHINE ---

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ValidatorState {
    pub reputation: u64,
    pub last_seen: u64,
    pub signing_key: Vec<u8>,
    pub encryption_key: Vec<u8>,
}

pub struct GlobalState {
    blocks: Tree,
    validators: Tree,
    metadata: Tree,
    cas: Tree,
    heights: Tree, // NEW: Index by Height for Explorer
}

impl GlobalState {
    const INITIAL_REPUTATION: u64 = 1_000_000;

    pub fn load(path: &str) -> Result<Self> {
        let db = sled::open(path).context("DB Open Failed")?;
        Ok(Self {
            blocks: db.open_tree("blocks")?,
            validators: db.open_tree("validators")?,
            metadata: db.open_tree("metadata")?,
            cas: db.open_tree("cas")?,
            heights: db.open_tree("heights")?, // Initialize new tree
        })
    }

    pub fn get_validator(&self, did: &str) -> Result<Option<ValidatorState>> {
        match self.validators.get(did)? {
            Some(b) => Ok(Some(bincode::deserialize::<ValidatorState>(&b)?)),
            None => Ok(None),
        }
    }

    pub fn apply_genesis(&self, block: &AxionBlock) -> Result<()> {
        if self.blocks.contains_key(&block.hash)? {
            return Ok(());
        }
        self.save_block_internal(block)?;

        let val = ValidatorState {
            reputation: Self::INITIAL_REPUTATION,
            last_seen: block.timestamp,
            signing_key: block.author_public_key.clone(),
            encryption_key: vec![],
        };
        self.save_validator(&block.author_did, val)?;
        self.metadata
            .insert("genesis_hash", block.hash.as_bytes())?;
        Ok(())
    }

    pub fn process_block(&self, block: &AxionBlock) -> Result<()> {
        if self.blocks.contains_key(&block.hash)? {
            return Ok(());
        }

        let mut val = self
            .get_validator(&block.author_did)?
            .unwrap_or(ValidatorState {
                reputation: 0,
                last_seen: block.timestamp,
                signing_key: block.author_public_key.clone(),
                encryption_key: vec![],
            });

        val.reputation += 10;
        val.last_seen = block.timestamp;

        if let BlockPayload::IdentityUpdate {
            new_encryption_key, ..
        } = &block.payload
        {
            val.encryption_key = new_encryption_key.clone();
        }

        self.save_validator(&block.author_did, val)?;
        self.save_block_internal(block)?;
        Ok(())
    }

    // --- TRUE CAS IMPLEMENTATION ---

    fn save_block_internal(&self, block: &AxionBlock) -> Result<()> {
        // 1. CAS Deduplication (Unchanged)
        let mut skeleton_block = block.clone();
        let mut extracted_hash = None;
        if let BlockPayload::DataStore { blob, .. } = &mut skeleton_block.payload {
            if !blob.is_empty() {
                let mut hasher = Sha3_256::new();
                hasher.update(&blob);
                let blob_hash = hex::encode(hasher.finalize());
                self.cas.insert(&blob_hash, blob.as_slice())?;
                *blob = Vec::new();
                extracted_hash = Some(blob_hash);
            }
        }

        // 2. Save the Block to the main 'blocks' tree
        let storage_unit = StoredBlock {
            block: skeleton_block,
            blob_hash: extracted_hash,
        };
        let bytes = bincode::serialize(&storage_unit)?;
        self.blocks.insert(&block.hash, bytes)?;

        // 3. HARDENED Height Indexing
        // Ensure we are using Big Endian for the key so Sled sorts properly
        let height_key = block.index.to_be_bytes();

        // Retrieve existing list or create new
        let mut hashes_at_height: Vec<String> = match self.heights.get(&height_key)? {
            Some(data) => bincode::deserialize(&data).unwrap_or_default(),
            None => Vec::new(),
        };

        if !hashes_at_height.contains(&block.hash) {
            hashes_at_height.push(block.hash.clone());
            self.heights
                .insert(&height_key, bincode::serialize(&hashes_at_height)?)?;
        }

        // CRITICAL: Flush to disk to ensure persistence across restarts
        self.blocks.flush()?;
        self.heights.flush()?;
        self.cas.flush()?;

        Ok(())
    }

    pub fn get_block(&self, hash: &str) -> Result<Option<AxionBlock>> {
        match self.blocks.get(hash)? {
            Some(bytes) => {
                let mut storage_unit: StoredBlock = bincode::deserialize(&bytes)?;

                if let Some(blob_hash) = storage_unit.blob_hash {
                    let blob_bytes = self.cas.get(&blob_hash)?.ok_or_else(|| {
                        anyhow!(
                            "Data Corruption: Blob {} missing for block {}",
                            blob_hash,
                            hash
                        )
                    })?;

                    if let BlockPayload::DataStore { blob, .. } = &mut storage_unit.block.payload {
                        *blob = blob_bytes.to_vec();
                    }
                }
                Ok(Some(storage_unit.block))
            }
            None => Ok(None),
        }
    }

    // --- EXPLORER HELPERS ---

    /// Returns the last N blocks (latest first)
    pub fn get_recent_blocks(&self, limit: usize) -> Result<Vec<AxionBlock>> {
        let mut result = Vec::new();

        // Iterate backwards from the end of the heights tree
        for item in self.heights.iter().rev() {
            let (_, value) = item?;
            let hashes: Vec<String> = bincode::deserialize(&value)?;

            for hash in hashes {
                if let Some(block) = self.get_block(&hash)? {
                    result.push(block);
                    if result.len() >= limit {
                        return Ok(result);
                    }
                }
            }
        }
        Ok(result)
    }

    /// Returns basic stats for the dashboard
    pub fn get_stats(&self) -> Result<(usize, usize, usize)> {
        let block_count = self.blocks.len();
        let peer_count = self.validators.len();
        let cas_items = self.cas.len();
        Ok((block_count, peer_count, cas_items))
    }

    // --- PRUNING (Garbage Collection) ---
    pub fn prune_stale_data(&self, retention_seconds: u64) -> Result<usize> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let cutoff = now.saturating_sub(retention_seconds);
        let mut deleted_count = 0;

        for item in self.blocks.iter() {
            let (key, value) = item?;
            if let Ok(storage_unit) = bincode::deserialize::<StoredBlock>(&value) {
                // Never delete Genesis (Index 0)
                if storage_unit.block.index != 0 && storage_unit.block.timestamp < cutoff {
                    // 1. Delete the Block Reference
                    self.blocks.remove(&key)?;

                    // 2. Delete the Blob from CAS if it exists
                    if let Some(blob_hash) = storage_unit.blob_hash {
                        self.cas.remove(blob_hash)?;
                    }

                    // 3. Clean up Heights Index (Optional but good practice)
                    let height_key = storage_unit.block.index.to_be_bytes();
                    self.heights.remove(height_key)?;

                    deleted_count += 1;
                }
            }
        }
        Ok(deleted_count)
    }

    fn save_validator(&self, did: &str, state: ValidatorState) -> Result<()> {
        let bytes = bincode::serialize(&state)?;
        self.validators.insert(did, bytes)?;
        Ok(())
    }

    pub fn get_canonical_head(&self) -> Result<String> {
        match self.metadata.get("genesis_hash")? {
            Some(b) => Ok(String::from_utf8(b.to_vec())?),
            None => Ok(String::new()),
        }
    }
}
