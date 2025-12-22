use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as PqPublicKey, SecretKey};
use serde::{Serialize, Deserialize};
use std::fmt;

#[derive(Debug)]
pub enum CryptoError {
    KeyGenerationFailed,
    SigningFailed,
    VerificationFailed,
    InvalidSignatureFormat,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::KeyGenerationFailed => write!(f, "Key generation failed"),
            CryptoError::SigningFailed => write!(f, "Signing failed"),
            CryptoError::VerificationFailed => write!(f, "Verification failed"),
            CryptoError::InvalidSignatureFormat => write!(f, "Invalid signature format"),
        }
    }
}

impl std::error::Error for CryptoError {}

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

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sk = dilithium5::SecretKey::from_bytes(&self.secret)
            .map_err(|_| CryptoError::SigningFailed)?;
        let signature = dilithium5::detached_sign(message, &sk);
        Ok(signature.as_bytes().to_vec())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PublicKey(pub Vec<u8>);

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let pk_result = dilithium5::PublicKey::from_bytes(&self.0);
        let sig_result = dilithium5::DetachedSignature::from_bytes(signature);

        match (pk_result, sig_result) {
            (Ok(pk), Ok(sig)) => {
                dilithium5::verify_detached_signature(&sig, message, &pk).is_ok()
            }
            _ => false,
        }
    }

    pub fn to_did_hash(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(&self.0);
        hex::encode(hasher.finalize())
    }
}

pub fn verify_signature(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> bool {
    let pk = PublicKey::from_bytes(public_key_bytes);
    pk.verify(message, signature_bytes)
}
