use wasm_bindgen::prelude::*;
use crate::{types::signature::{Signature as CanonicalSig}, keys::public::PublicKey, types::chain::Chain};


#[derive(Debug, Clone, PartialEq, Default)]
#[wasm_bindgen]
pub struct SignatureWrapper{ sig: Vec<u8> }

#[wasm_bindgen]
impl SignatureWrapper {
    /// Creates a new signature instance
    pub fn new(sig: Vec<u8>) -> SignatureWrapper {
        SignatureWrapper { sig }
    }

    // Returns a clone of the stored inner signature buffer
    pub fn sig(&self) -> Vec<u8> {
        self.sig.clone()
    }

    /// Allows for a base58 string to be encoded to a legacy wif signature string
    /// ```
    /// use tetanus::keys::private::PrivateKey;
    /// // Previously encoded string
    /// let sig_string = "SIG_K1_JvYLntg1nfTLFTMX9mXGJB95WnbceLKwcvWTc16tVVCX1eCvFKXAtcuRs8xtRqMhH8oHFYAoWUYg8n9iV5nuLxtHojE2eo";
    ///
    /// let message = "helloworld";
    /// let private = PrivateKey::from_login("test", "test", "owner");
    /// let sig2 = private.sign_message(message);
    /// assert_eq!(sig_string.to_string(), sig2.to_string())
    /// ```
    pub fn to_string(&self) -> String {
        let sig = CanonicalSig::from(self);

        sig.to_legacy(Some("SIG_K1_"))
    }

    /// Allows for a base58 string to be decoded into its original buffer from
    /// a legacy wif signature string
    /// ```
    /// use tetanus::keys::private::PrivateKey;
    /// use tetanus::signatures::SignatureWrapper;
    /// // Previously encoded string
    /// let sig_string = "SIG_K1_JvYLntg1nfTLFTMX9mXGJB95WnbceLKwcvWTc16tVVCX1eCvFKXAtcuRs8xtRqMhH8oHFYAoWUYg8n9iV5nuLxtHojE2eo";
    ///
    /// let message = "helloworld";
    /// let sig = SignatureWrapper::from_string(sig_string);
    /// let private = PrivateKey::from_login("test", "test", "owner");
    /// let sig2 = private.sign_message(message);
    /// assert_eq!(sig, sig2)
    /// ```
    pub fn from_string(sig: &str) -> SignatureWrapper {
        let signature = CanonicalSig::from_legacy(&sig, Some("SIG_K1_")).unwrap();

        SignatureWrapper::new(signature.into())
    }

    /// Allows a public key wif to be obtained from a base58 encoded signature string and its original message
    ///```
    /// use tetanus::signatures::SignatureWrapper;
    /// let sig_string = "SIG_K1_JvYLntg1nfTLFTMX9mXGJB95WnbceLKwcvWTc16tVVCX1eCvFKXAtcuRs8xtRqMhH8oHFYAoWUYg8n9iV5nuLxtHojE2eo".to_string();
    /// let message = "helloworld";
    /// let public_key = SignatureWrapper::recover_public(sig_string, message.to_string(), None);
    /// assert_eq!("STM5jixkNBqJXNtX9vy2GjaqpX2d5jXrcjRXgh1WU5fXZhnDJrLM8", public_key)
    pub fn recover_public(sig_string: String, msg: String, chain: Option<Chain>) -> String {
        let sig = CanonicalSig::from_legacy(&sig_string, Some("SIG_K1_")).unwrap();

        let pub_address = sig.recover(msg).unwrap();

        PublicKey::new(pub_address.0.to_vec()).to_string(chain)
    }
}
