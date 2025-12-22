use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use axion_crypto::{PublicKey, verify_signature};
use std::collections::HashMap;
use sled::Db;

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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum BlockPayload {
    Genesis { message: String },
    Standard {
        tx_count: u32,
        state_root: String,
        zk_proof_root: String,
    },
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
        .expect("Serialization should never fail");
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

pub struct GlobalState {
    pub db: Db,
    pub validators: HashMap<String, u64>,
}

impl GlobalState {
    pub fn load(path: &str) -> Self {
        let db = sled::open(path).expect("Failed to open database");
        let mut validators = HashMap::new();

        for item in db.iter() {
            if let Ok((k, v)) = item {
                if let Ok(did) = String::from_utf8(k.to_vec()) {
                    if let Ok(rw_bytes) = <[u8; 8]>::try_from(v.as_ref()) {
                        let rw = u64::from_be_bytes(rw_bytes);
                        validators.insert(did, rw);
                    }
                }
            }
        }

        Self { db, validators }
    }

    pub fn apply_genesis(&mut self, block: &AxionBlock) {
        self.update_reputation(&block.author_did, 1_000_000);
    }

    pub fn process_block(&mut self, block: &AxionBlock) {
        let current_rw = *self.validators.get(&block.author_did).unwrap_or(&0);
        self.update_reputation(&block.author_did, current_rw + 10);
    }

    fn update_reputation(&mut self, did: &str, new_rw: u64) {
        self.validators.insert(did.to_string(), new_rw);
        let _ = self.db.insert(did, &new_rw.to_be_bytes());
        let _ = self.db.flush();
    }
}
