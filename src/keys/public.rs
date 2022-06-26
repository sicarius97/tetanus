use wasm_bindgen::prelude::*;
use crate::utils::{encode_to_string, EncodeType};

#[wasm_bindgen]
pub struct PublicKey { key: Vec<u8> }

#[wasm_bindgen]
impl PublicKey {
    /// Creates a new public key instance
    pub fn new(key: Vec<u8>) -> PublicKey {
        PublicKey{ key }
    }

    /// Converts a public key to a wif encoded string
    pub fn to_string(&self) -> String {
        assert!(&self.key.len() > &0);

        "STM".to_owned() + &encode_to_string(&self.key, Some(EncodeType::PubKey))
    }
}