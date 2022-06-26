use k256::{
    ecdsa::{recoverable::Signature as RecoverableSignature, SigningKey, signature::Signer, signature::digest::Digest},
    sha2::{Sha256}
};
use wasm_bindgen::prelude::*;
use crate::signatures::Signature;
use crate::utils::{EncodeType, encode_to_string};

use crate::keys::public::PublicKey;


#[derive(Debug, Clone, PartialEq)]
#[wasm_bindgen]
pub struct PrivateKey{ key: Vec<u8> }
#[wasm_bindgen]
impl PrivateKey {
    /// Creates a new private key instance
    pub fn new(key: Vec<u8>) -> PrivateKey {
        PrivateKey{ key }
    }

    /// Returns a new private key instance by creating a seed with
    /// passed in arguments
    /// ```
    /// use tetanus::keys::private::PrivateKey;
    /// let assert_key: PrivateKey = PrivateKey::new(vec![172, 77, 224, 92, 161, 163, 181, 53, 80, 219, 255, 168, 223, 31, 231, 32, 238, 108, 150, 219, 77, 153, 8, 68, 240, 148, 105, 203, 131, 235, 219, 82]);
    /// let key = PrivateKey::from_login("test", "test", "owner");
    /// assert_eq!(assert_key, key)
    /// ```
    pub fn from_login(username: &str, password: &str, role: &str ) -> PrivateKey {
        let seed = username.to_owned() + &role + &password;
        let hash = Sha256::digest(seed.as_bytes());
        assert!(hash.len() == 32);
        PrivateKey{ key: hash.to_vec() }
    }

    /// Converts the internally stored private key hash buffer to a string representing
    /// the private key wif
    /// 
    /// Assuming a username and password of test and a role of owner
    /// ```
    /// use tetanus::keys::private::PrivateKey;
    /// let test_wif = "5K8AruCpTY6gVeQRMd5UpeuoVR2YheRCjUDAVFrfiahZU4bBccj";
    /// let generated_wif = PrivateKey::from_login("test", "test", "owner").to_string();
    /// assert_eq!(test_wif, generated_wif)
    /// ```
    pub fn to_string(&self) -> String {
        assert!(&self.key.len() > &0);

        encode_to_string(&self.key, Some(EncodeType::Sha256x2))
    }

    /// Returns a public key instance that corresponds to the private key
    /// ```
    /// use tetanus::keys::private::PrivateKey;
    /// let private = PrivateKey::from_login("test", "test", "owner");
    /// let public = private.to_public();
    /// assert_eq!("STM5jixkNBqJXNtX9vy2GjaqpX2d5jXrcjRXgh1WU5fXZhnDJrLM8", public.to_string())
    /// ```
    pub fn to_public(&self) -> PublicKey {
        let private_key = SigningKey::from_bytes(&self.key.as_slice()).unwrap();

        let pub_key = private_key.verifying_key();

        PublicKey::new(pub_key.to_bytes().to_vec())
    }

    /// Takes in a PrivateKey instance and message then returns a signed message
    /// ```
    /// use tetanus::keys::private::PrivateKey;
    /// let message = "helloworld";
    /// let private = PrivateKey::from_login("test", "test", "owner");
    /// let sig = private.sign_message(message);
    /// assert_eq!("28Xrw5WR4Cz1by9kfvjxLCwFvGNatnx99WJmD2wi3zx8QqayWzXZYJQrW3zJzU8f1eJSzWSYDoZHh75txvSmBUQiRN8z3G5", sig.to_string())
    /// ```
    pub fn sign_message(&self, message: &str) -> Signature {
        let private_key = SigningKey::from_bytes(&self.key.as_slice()).unwrap();
        let signature: RecoverableSignature = private_key.sign(message.as_bytes());

        Signature::new(signature.as_ref().to_vec())
    }
}


