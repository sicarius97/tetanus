use wasm_bindgen::prelude::*;
use crate::{utils::{encode_to_string, decode_from_string}, keys::public::PublicKey, types::chain::Chain};
use k256::ecdsa::recoverable::Signature as RecoverableSignature;
use k256::ecdsa::signature::Signature as OtherSignature;

#[derive(Debug, Clone, PartialEq, Default)]
#[wasm_bindgen]
pub struct Signature{ sig: Vec<u8> }

#[wasm_bindgen]
impl Signature {
    /// Creates a new signature instance
    pub fn new(sig: Vec<u8>) -> Signature {
        Signature { sig }
    }

    /// Allows for a base58 string to be decoded into its original buffer
    /// ```
    /// use tetanus::keys::private::PrivateKey;
    /// use tetanus::signatures::Signature;
    /// // Previously encoded string
    /// let sig_string = "28Xrw5WR4Cz1by9kfvjxLCwFvGNatnx99WJmD2wi3zx8QqayWzXZYJQrW3zJzU8f1eJSzWSYDoZHh75txvSmBUQiRN8z3G5".to_string();
    ///
    /// let message = "helloworld";
    /// let private = PrivateKey::from_login("test", "test", "owner");
    /// let sig2 = private.sign_message(message);
    /// assert_eq!(sig_string, sig2.to_string())
    /// ```
    pub fn to_string(&self) -> String {
        let signature = RecoverableSignature::from_bytes(&self.sig).unwrap();
        let sig_string = encode_to_string(signature.as_ref().to_vec(), None);

        sig_string
    }

    /// Allows for a base58 string to be decoded into its original buffer
    /// ```
    /// use tetanus::keys::private::PrivateKey;
    /// use tetanus::signatures::Signature;
    /// // Previously encoded string
    /// let sig_string = "28Xrw5WR4Cz1by9kfvjxLCwFvGNatnx99WJmD2wi3zx8QqayWzXZYJQrW3zJzU8f1eJSzWSYDoZHh75txvSmBUQiRN8z3G5".to_string();
    ///
    /// let message = "helloworld";
    /// let sig = Signature::from_string(sig_string);
    /// let private = PrivateKey::from_login("test", "test", "owner");
    /// let sig2 = private.sign_message(message);
    /// assert_eq!(sig, sig2)
    /// ```
    pub fn from_string(sig: String) -> Signature {
        let signature = decode_from_string(sig, None);

        Signature { sig: signature }
    }

    /// Allows a public key wif to be obtained from a base58 encoded signature string and its original message
    ///```
    /// use tetanus::signatures::Signature;
    /// let sig_string = "28Xrw5WR4Cz1by9kfvjxLCwFvGNatnx99WJmD2wi3zx8QqayWzXZYJQrW3zJzU8f1eJSzWSYDoZHh75txvSmBUQiRN8z3G5".to_string();
    /// let message = "helloworld";
    /// let public_key = Signature::recover_from_string(sig_string, message.to_string(), None);
    /// assert_eq!("STM5jixkNBqJXNtX9vy2GjaqpX2d5jXrcjRXgh1WU5fXZhnDJrLM8", public_key)
    pub fn recover_from_string(sig_string: String, msg: String, chain: Option<Chain>) -> String {
        let sig = decode_from_string(sig_string, None);

        let signature = RecoverableSignature::from_bytes(&sig).unwrap();

        let public_key = signature.recover_verify_key(msg.as_bytes()).unwrap();

        PublicKey::new(public_key.to_bytes().to_vec()).to_string(chain)
    }
}
