use wasm_bindgen::prelude::*;
use crate::{keys::private::PrivateKey, signatures::SignatureWrapper};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct OperationData;

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct Operation(String, OperationData);




#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct Transaction { 
    ref_block_num: u64,
    ref_block_prefix: u64,
    expiration: String,
    operations: Vec<Operation>,
    extensions: Vec<String>,
}

#[wasm_bindgen]
impl Transaction {
    pub fn new(val: JsValue) -> Transaction {
        serde_wasm_bindgen::from_value(val).unwrap()
    }

    pub fn digest_sign(&self, key: &str) -> SignatureWrapper {
        let private = PrivateKey::from_string(key);

        let json_str = serde_json::to_string(&self).unwrap();

        private.sign_message(&json_str)
    }
}



