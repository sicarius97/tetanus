use wasm_bindgen::prelude::*;
use crate::utils::{encode_to_string, EncodeType};
use crate::types::chain::Chain;

#[wasm_bindgen]
pub struct PublicKey { key: Vec<u8> }

#[wasm_bindgen]
impl PublicKey {
    /// Creates a new public key instance
    pub fn new(key: Vec<u8>) -> PublicKey {
        PublicKey{ key }
    }

    /// Converts a public key to a wif encoded string
    pub fn to_string(&self, chain: Option<Chain>) -> String {
        let prefix = match chain.unwrap_or(Chain::Hive) {
            Chain::Hive => String::from("STM"),
            Chain::Steem => String::from("STM"),
            Chain::Eos => String::from("EOS")
        };
        
        println!("{}", &self.key.len());
        assert!(&self.key.len() > &0);

        prefix + &encode_to_string(self.key.clone(), Some(EncodeType::PubKey))
    }
}