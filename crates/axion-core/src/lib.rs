use anyhow::{anyhow, Context, Result};
use axion_crypto::{verify_signature, PublicKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use sled::Tree;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

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
    DataStore {
        policy: AccessPolicy,
        blob: Vec<u8>,
        keys: HashMap<String, (Vec<u8>, Vec<u8>)>,
    },
    IdentityUpdate {
        did: String,
        new_encryption_key: Vec<u8>,
    },
    FraudProof {
        accused_did: String,
        blob_hash: String,
        witness_votes: Vec<(String, Vec<u8>)>,
    },
}

impl BlockPayload {
    pub fn get_keys_for(&self, did: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        if let BlockPayload::DataStore { keys, .. } = self {
            let raw_did = did.replace("did:axion:", "");
            let full_did = if !did.starts_with("did:axion:") {
                format!("did:axion:{}", did)
            } else {
                did.to_string()
            };

            if let Some(k) = keys.get(did) {
                return Ok(k.clone());
            }
            if let Some(k) = keys.get(&raw_did) {
                return Ok(k.clone());
            }
            if let Some(k) = keys.get(&full_did) {
                return Ok(k.clone());
            }

            Err(anyhow!("No encryption keys found for DID: {}", did))
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

#[derive(Serialize, Deserialize)]
struct StoredBlock {
    block: AxionBlock,
    blob_hash: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ValidatorState {
    pub reputation: u64,
    pub last_seen: u64,
    pub signing_key: Vec<u8>,
    pub encryption_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ValidatorSummary {
    pub did: String,
    pub state: ValidatorState,
}

pub struct GlobalState {
    blocks: Tree,
    validators: Tree,
    metadata: Tree,
    cas: Tree,
    heights: Tree,
}

impl GlobalState {
    const INITIAL_REPUTATION: u64 = 1_000_000;

    pub fn get_blocks_range(&self, start_index: u64, limit: usize) -> Result<Vec<AxionBlock>> {
        let start_key = start_index.to_be_bytes();
        let mut result = Vec::new();

        for item in self.heights.range(start_key..) {
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

    pub fn get_validator(&self, did: &str) -> Result<Option<ValidatorState>> {
        match self.validators.get(did)? {
            Some(b) => Ok(Some(bincode::deserialize::<ValidatorState>(&b)?)),
            None => Ok(None),
        }
    }

    pub fn get_all_validators(&self) -> Result<Vec<ValidatorSummary>> {
        let mut validators = Vec::new();
        for item in self.validators.iter() {
            let (did_bytes, val_bytes) = item?;
            let did = String::from_utf8(did_bytes.to_vec())?;
            if let Ok(state) = bincode::deserialize::<ValidatorState>(&val_bytes) {
                validators.push(ValidatorSummary { did, state });
            }
        }
        Ok(validators)
    }

    pub fn get_top_validators(&self, count: usize) -> Result<Vec<(String, ValidatorState)>> {
        let mut validators = Vec::new();
        for item in self.validators.iter() {
            let (did_bytes, val_bytes) = item?;
            let did = String::from_utf8(did_bytes.to_vec())?;
            let val: ValidatorState = bincode::deserialize(&val_bytes)?;
            validators.push((did, val));
        }

        validators.sort_by(|a, b| b.1.reputation.cmp(&a.1.reputation));
        validators.truncate(count);

        Ok(validators)
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

        self.blocks.flush()?;
        self.heights.flush()?;

        Ok(())
    }

    pub fn process_block(&self, block: &AxionBlock) -> Result<()> {
        if self.blocks.contains_key(&block.hash)? {
            return Ok(());
        }

        let mut author_val = self
            .get_validator(&block.author_did)?
            .unwrap_or(ValidatorState {
                reputation: 0,
                last_seen: block.timestamp,
                signing_key: block.author_public_key.clone(),
                encryption_key: vec![],
            });

        author_val.reputation += 10;
        author_val.last_seen = block.timestamp;

        match &block.payload {
            BlockPayload::IdentityUpdate {
                did: target_did,
                new_encryption_key,
            } => {
                let mut target_val = self.get_validator(target_did)?.unwrap_or(ValidatorState {
                    reputation: 50,
                    last_seen: block.timestamp,
                    signing_key: vec![],
                    encryption_key: vec![],
                });

                target_val.encryption_key = new_encryption_key.clone();
                target_val.last_seen = block.timestamp;

                self.save_validator(target_did, target_val)?;
                println!("💾 [STATE] Registered External Identity: {}", target_did);
            }
            BlockPayload::FraudProof {
                accused_did,
                witness_votes,
                ..
            } => {
                let jury = self.get_top_validators(10)?;
                let jury_dids: Vec<&String> = jury.iter().map(|(d, _)| d).collect();

                let mut valid_votes = 0;
                for (witness_did, _sig) in witness_votes {
                    if jury_dids.contains(&witness_did) {
                        valid_votes += 1;
                    }
                }

                if valid_votes >= 2 {
                    if let Some(mut bad_actor) = self.get_validator(accused_did)? {
                        println!(
                            "⚖️ JUSTICE: Slashing DID {} for Data Withholding!",
                            accused_did
                        );
                        bad_actor.reputation /= 2;
                        self.save_validator(accused_did, bad_actor)?;
                        author_val.reputation += 500;
                    }
                }
            }
            _ => {}
        }

        self.save_validator(&block.author_did, author_val)?;
        self.save_block_internal(block)?;
        Ok(())
    }

    fn save_block_internal(&self, block: &AxionBlock) -> Result<()> {
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

        let storage_unit = StoredBlock {
            block: skeleton_block,
            blob_hash: extracted_hash,
        };
        let bytes = bincode::serialize(&storage_unit)?;
        self.blocks.insert(&block.hash, bytes)?;

        let height_key = block.index.to_be_bytes();
        let mut hashes_at_height: Vec<String> = match self.heights.get(&height_key)? {
            Some(data) => bincode::deserialize(&data).unwrap_or_default(),
            None => Vec::new(),
        };

        if !hashes_at_height.contains(&block.hash) {
            hashes_at_height.push(block.hash.clone());
            self.heights
                .insert(&height_key, bincode::serialize(&hashes_at_height)?)?;
        }

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

    pub fn get_recent_blocks(&self, limit: usize) -> Result<Vec<AxionBlock>> {
        let mut result = Vec::new();

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

    pub fn get_stats(&self) -> Result<(usize, usize, usize)> {
        let block_count = self.blocks.len();
        let peer_count = self.validators.len();
        let cas_items = self.cas.len();
        Ok((block_count, peer_count, cas_items))
    }

    pub fn prune_stale_data(&self, retention_seconds: u64) -> Result<usize> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let cutoff = now.saturating_sub(retention_seconds);
        let mut deleted_count = 0;

        for item in self.blocks.iter() {
            let (key, value) = item?;
            if let Ok(storage_unit) = bincode::deserialize::<StoredBlock>(&value) {
                if storage_unit.block.index != 0 && storage_unit.block.timestamp < cutoff {
                    self.blocks.remove(&key)?;
                    if let Some(blob_hash) = storage_unit.blob_hash {
                        self.cas.remove(blob_hash)?;
                    }
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
