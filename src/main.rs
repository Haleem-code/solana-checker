mod errors;
mod handlers;
mod types;
mod utils;

use axum::{routing::post, Router};
use handlers::{
    create_token, generate_keypair, mint_token, send_sol, send_token, sign_message, verify_message,
};

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token));

    
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("0.0.0.0:{}", port);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap();

    println!("Server running on http://{}", addr);
    axum::serve(listener, app).await.unwrap();
}