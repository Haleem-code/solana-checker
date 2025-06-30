use axum::{
    extract::Json,
    http::StatusCode,
    response::Json as ResponseJson,
};
use base64::{engine::general_purpose, Engine as _};
use bs58;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use solana_sdk::{
    signature::Keypair,
    signature::Signer,
    system_instruction,
};
use spl_token::instruction::{initialize_mint, mint_to, transfer};
use spl_associated_token_account::get_associated_token_address;

use crate::types::*;
use crate::utils::*;

pub async fn generate_keypair() -> ResponseJson<ApiResponse<KeypairData>> {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();

    ResponseJson(ApiResponse::success(KeypairData { pubkey, secret }))
}

pub async fn create_token(
    Json(payload): Json<CreateTokenRequest>,
) -> Result<ResponseJson<ApiResponse<InstructionData>>, StatusCode> {
    let mint_authority = pubkey_from_str(&payload.mint_authority)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let mint = pubkey_from_str(&payload.mint)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let instruction = initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        Some(&mint_authority),
        payload.decimals,
    ).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let accounts = instruction.accounts.iter().map(|acc| AccountInfo {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
        is_writable: acc.is_writable,
    }).collect();

    let instruction_data = InstructionData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: general_purpose::STANDARD.encode(&instruction.data),
    };

    Ok(ResponseJson(ApiResponse::success(instruction_data)))
}

pub async fn mint_token(
    Json(payload): Json<MintTokenRequest>,
) -> Result<ResponseJson<ApiResponse<InstructionData>>, StatusCode> {
    let mint = pubkey_from_str(&payload.mint)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let destination = pubkey_from_str(&payload.destination)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let authority = pubkey_from_str(&payload.authority)
        .map_err(|_| StatusCode::BAD_REQUEST)?;


    let destination_ata = get_associated_token_address(&destination, &mint);

    let instruction = mint_to(
        &spl_token::id(),
        &mint,
        &destination_ata,
        &authority,
        &[],
        payload.amount,
    ).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let accounts = instruction.accounts.iter().map(|acc| AccountInfo {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
        is_writable: acc.is_writable,
    }).collect();

    let instruction_data = InstructionData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: general_purpose::STANDARD.encode(&instruction.data),
    };

    Ok(ResponseJson(ApiResponse::success(instruction_data)))
}

pub async fn sign_message(
    Json(payload): Json<SignMessageRequest>,
) -> Result<ResponseJson<ApiResponse<SignMessageData>>, StatusCode> {
    if payload.message.is_empty() || payload.secret.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let keypair = keypair_from_secret(&payload.secret)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let message_bytes = payload.message.as_bytes();
    
    let signature = keypair.sign_message(message_bytes);
    let signature_b64 = general_purpose::STANDARD.encode(signature);

    let public_key = keypair.pubkey().to_string();

    let data = SignMessageData {
        signature: signature_b64,
        public_key,
        message: payload.message,
    };

    Ok(ResponseJson(ApiResponse::success(data)))
}

pub async fn verify_message(
    Json(payload): Json<VerifyMessageRequest>,
) -> Result<ResponseJson<ApiResponse<VerifyMessageData>>, StatusCode> {
    let pubkey_bytes = bs58::decode(&payload.pubkey)
        .into_vec()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    if pubkey_bytes.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    
    let public_key = match VerifyingKey::from_bytes(
        &pubkey_bytes.try_into().map_err(|_| StatusCode::BAD_REQUEST)?
    ) {
        Ok(key) => key,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    let signature_bytes = general_purpose::STANDARD.decode(&payload.signature)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    if signature_bytes.len() != 64 {
        return Err(StatusCode::BAD_REQUEST);
    }
    
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    let signature = Signature::from_bytes(&signature_array);

    let message_bytes = payload.message.as_bytes();
    let valid = public_key.verify(message_bytes, &signature).is_ok();

    let data = VerifyMessageData {
        valid,
        message: payload.message,
        pubkey: payload.pubkey,
    };

    Ok(ResponseJson(ApiResponse::success(data)))
}

pub async fn send_sol(
    Json(payload): Json<SendSolRequest>,
) -> Result<ResponseJson<ApiResponse<SimpleInstructionData>>, StatusCode> {
    let from = pubkey_from_str(&payload.from)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let to = pubkey_from_str(&payload.to)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Validate inputs
    if payload.lamports == 0 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let instruction = system_instruction::transfer(&from, &to, payload.lamports);

    let accounts = vec![
        instruction.accounts[0].pubkey.to_string(),
        instruction.accounts[1].pubkey.to_string(),
    ];

    let instruction_data = SimpleInstructionData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: general_purpose::STANDARD.encode(&instruction.data),
    };

    Ok(ResponseJson(ApiResponse::success(instruction_data)))
}

pub async fn send_token(
    Json(payload): Json<SendTokenRequest>,
) -> Result<ResponseJson<ApiResponse<TokenInstructionData>>, StatusCode> {
    let destination = pubkey_from_str(&payload.destination)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let mint = pubkey_from_str(&payload.mint)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let owner = pubkey_from_str(&payload.owner)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    if payload.amount == 0 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let source_ata = get_associated_token_address(&owner, &mint);
    let destination_ata = get_associated_token_address(&destination, &mint);

    let instruction = transfer(
        &spl_token::id(),
        &source_ata,
        &destination_ata,
        &owner,
        &[],
        payload.amount,
    ).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let accounts = instruction.accounts.iter().map(|acc| TokenAccountInfo {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
    }).collect();

    let instruction_data = TokenInstructionData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: general_purpose::STANDARD.encode(&instruction.data),
    };

    Ok(ResponseJson(ApiResponse::success(instruction_data)))            
}