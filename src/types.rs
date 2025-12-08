//! API response types for YubiKey Signer
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: serde_json::Value,
    pub id: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub result: Value,
    pub id: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignParams {
    pub key_id: String,
    pub msg: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PublicKeyParams {
    pub key_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeysResponse {
    pub keys: Vec<PublicKeyResponse>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PublicKey {
    #[serde(rename = "Secp256r1")]
    pub secp256r1: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyResponse {
    pub key_id: String,
    pub public_key: PublicKey,
    pub sui_address: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureResponse {
    pub signature: String,
}
