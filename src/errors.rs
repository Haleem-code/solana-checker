use axum::{
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;

#[derive(Debug)]
pub enum AppError {
    InvalidPublicKey(String),
    InvalidSecretKey(String),
    InvalidSignature,
    InvalidAmount,
    MissingFields(String),
    TokenError(String),
    InternalError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::InvalidPublicKey(msg) => (StatusCode::BAD_REQUEST, format!("Invalid public key: {}", msg)),
            AppError::InvalidSecretKey(msg) => (StatusCode::BAD_REQUEST, format!("Invalid secret key: {}", msg)),
            AppError::InvalidSignature => (StatusCode::BAD_REQUEST, "Invalid signature".to_string()),
            AppError::InvalidAmount => (StatusCode::BAD_REQUEST, "Invalid amount: must be greater than 0".to_string()),
            AppError::MissingFields(msg) => (StatusCode::BAD_REQUEST, format!("Missing required fields: {}", msg)),
            AppError::TokenError(msg) => (StatusCode::BAD_REQUEST, format!("Token error: {}", msg)),
            AppError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Internal error: {}", msg)),
        };

        let body = Json(json!({
            "success": false,
            "error": error_message
        }));

        (status, body).into_response()
    }
}

impl From<solana_sdk::pubkey::ParsePubkeyError> for AppError {
    fn from(err: solana_sdk::pubkey::ParsePubkeyError) -> Self {
        AppError::InvalidPublicKey(err.to_string())
    }
}


pub fn handle_result<T>(result: Result<T, AppError>) -> Result<Json<crate::types::ApiResponse<T>>, AppError> {
    match result {
        Ok(data) => Ok(Json(crate::types::ApiResponse::success(data))),
        Err(e) => Err(e),
    }
}