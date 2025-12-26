use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, Result};
use pqcrypto_dilithium::dilithium5;
use pqcrypto_kyber::kyber1024;
pub use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey,
    SharedSecret as KemSharedSecret,
};
pub use pqcrypto_traits::sign::{
    DetachedSignature as SignSignature, PublicKey as SignPublicKey, SecretKey as SignSecretKey,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

pub mod traits {
    pub use crate::{
        KemCiphertext, KemPublicKey, KemSecretKey, KemSharedSecret, SignPublicKey, SignSecretKey,
        SignSignature,
    };
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Keypair {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

impl Keypair {
    pub fn generate() -> Self {
        let (pk, sk) = dilithium5::keypair();
        Self {
            public: pk.as_bytes().to_vec(),
            secret: sk.as_bytes().to_vec(),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sk = dilithium5::SecretKey::from_bytes(&self.secret)
            .map_err(|_| anyhow!("Crypto Error: Failed to load Dilithium5 Secret Key"))?;
        let signature = dilithium5::detached_sign(message, &sk);
        Ok(signature.as_bytes().to_vec())
    }
}

pub fn verify_signature(pk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> bool {
    if pk_bytes.len() != dilithium5::public_key_bytes()
        || sig_bytes.len() != dilithium5::signature_bytes()
    {
        return false;
    }

    if let (Ok(pk), Ok(sig)) = (
        dilithium5::PublicKey::from_bytes(pk_bytes),
        dilithium5::DetachedSignature::from_bytes(sig_bytes),
    ) {
        dilithium5::verify_detached_signature(&sig, msg, &pk).is_ok()
    } else {
        false
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(pub Vec<u8>);

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    pub fn to_did_hash(&self) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.0);
        format!("did:axion:{}", hex::encode(hasher.finalize()))
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptionKeypair {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

impl EncryptionKeypair {
    pub fn generate() -> Self {
        let (pk, sk) = kyber1024::keypair();
        Self {
            public: pk.as_bytes().to_vec(),
            secret: sk.as_bytes().to_vec(),
        }
    }
}

pub fn hybrid_encrypt(recipient_pubkey: &[u8], data: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let pk = kyber1024::PublicKey::from_bytes(recipient_pubkey)
        .map_err(|_| anyhow!("Security Error: Recipient Public Key is corrupted or invalid"))?;

    let (shared_secret, kem_ciphertext) = kyber1024::encapsulate(&pk);

    let key_bytes = &shared_secret.as_bytes()[..32];
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aes_ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|_| anyhow!("AES Encryption failure: Check data integrity"))?;

    Ok((
        kem_ciphertext.as_bytes().to_vec(),
        nonce_bytes.to_vec(),
        aes_ciphertext,
    ))
}

pub fn hybrid_decrypt(
    recipient_secret: &[u8],
    kem_ct: &[u8],
    nonce: &[u8],
    aes_ct: &[u8],
) -> Result<Vec<u8>> {
    let sk = kyber1024::SecretKey::from_bytes(recipient_secret)
        .map_err(|_| anyhow!("Security Error: Invalid decryption key"))?;

    let ct = kyber1024::Ciphertext::from_bytes(kem_ct)
        .map_err(|_| anyhow!("Security Error: KEM Ciphertext mismatch"))?;

    let shared_secret = kyber1024::decapsulate(&ct, &sk);

    let key_bytes = &shared_secret.as_bytes()[..32];
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce_val = Nonce::from_slice(nonce);

    let plaintext = cipher.decrypt(nonce_val, aes_ct).map_err(|_| {
        anyhow!("Decryption Failed: Data may have been tampered with or incorrect key used")
    })?;

    Ok(plaintext)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IdentityPoW {
    pub nonce: u64,
    pub difficulty: u32,
}

impl IdentityPoW {
    pub fn mint(public_key: &[u8], difficulty: u32) -> Self {
        let mut nonce = 0u64;
        loop {
            let mut hasher = Sha3_256::new();
            hasher.update(public_key);
            hasher.update(nonce.to_le_bytes());
            let result = hasher.finalize();

            if check_difficulty(&result, difficulty) {
                return Self { nonce, difficulty };
            }
            nonce += 1;
        }
    }

    pub fn verify(&self, public_key: &[u8]) -> bool {
        let mut hasher = Sha3_256::new();
        hasher.update(public_key);
        hasher.update(self.nonce.to_le_bytes());
        let result = hasher.finalize();
        check_difficulty(&result, self.difficulty)
    }
}

fn check_difficulty(hash: &[u8], difficulty_bits: u32) -> bool {
    let mut bits_checked = 0;
    for &byte in hash {
        for i in (0..8).rev() {
            if bits_checked >= difficulty_bits {
                return true;
            }
            if (byte >> i) & 1 != 0 {
                return false;
            }
            bits_checked += 1;
        }
    }
    true
}
