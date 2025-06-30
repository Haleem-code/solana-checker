use bs58;
use solana_sdk::{
    pubkey::Pubkey,
    signer::keypair::Keypair,
};
use std::str::FromStr;
use crate::errors::AppError;

pub fn keypair_from_secret(secret_str: &str) -> Result<Keypair, String> {
    let secret_bytes = bs58::decode(secret_str)
        .into_vec()
        .map_err(|_| "Invalid base58 secret key")?;
    
    if secret_bytes.len() != 64 {
        return Err("Invalid secret key length".to_string());
    }

    Keypair::try_from(&secret_bytes[..])
        .map_err(|_| "Invalid secret key format".to_string())
}

pub fn pubkey_from_str(pubkey_str: &str) -> Result<Pubkey, AppError> {
    Pubkey::from_str(pubkey_str)
        .map_err(|e| AppError::InvalidPublicKey(e.to_string()))
}

