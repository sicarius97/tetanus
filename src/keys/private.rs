use k256::{
    ecdsa::{recoverable::Signature as RecoverableSignature, SigningKey, signature::Signer, signature::digest::Digest, signature::DigestSigner},
    FieldBytes
};
use sha2::{Sha256};
use primitive_types::U256;
use wasm_bindgen::prelude::*;
use crate::{signatures::Signature, utils::{decode_from_string, hash_message}};
use crate::utils::{EncodeType, encode_to_string};
use crate::types::signature::{Signature as CanonicalSignature};
use crate::keys::public::PublicKey;
use crate::hash::Sha256Proxy;


#[derive(Debug, Clone, PartialEq)]
#[wasm_bindgen]
pub struct PrivateKey{ key: Vec<u8> }
// #[wasm_bindgen]
impl PrivateKey {
    /// Creates a new private key instance
    pub fn new(key: Vec<u8>) -> PrivateKey {
        assert!(key.len() == 32);
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
        assert!(username.is_ascii());
        assert!(password.is_ascii());
        assert!(role.is_ascii());

        let seed = username.to_owned() + &role + &password;
        let hash = Sha256::digest(seed.as_bytes());
        PrivateKey::new(hash.to_vec())
    }

    /// Takes a legacy wif string representing a key as an argument and returns a new private key instance
    /// ```
    /// use tetanus::keys::private::PrivateKey;
    /// let private_from_string = PrivateKey::from_string("5K8AruCpTY6gVeQRMd5UpeuoVR2YheRCjUDAVFrfiahZU4bBccj");
    /// let test_private = PrivateKey::from_login("test", "test", "owner");
    /// assert_eq!(private_from_string, test_private)
    /// ```
    pub fn from_string(wif: &str) -> PrivateKey {
        let hash = decode_from_string(wif.to_string(), Some(EncodeType::Sha256x2));

        PrivateKey::new(hash)
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

        encode_to_string(self.key.clone(), Some(EncodeType::Sha256x2))
    }

    /// Returns a public key instance that corresponds to the private key
    /// ```
    /// use tetanus::keys::private::PrivateKey;
    /// let private = PrivateKey::from_login("test", "test", "owner");
    /// let public = private.to_public();
    /// assert_eq!("STM5jixkNBqJXNtX9vy2GjaqpX2d5jXrcjRXgh1WU5fXZhnDJrLM8", public.to_string(None))
    /// ```
    pub fn to_public(&self) -> PublicKey {
        let private_key = SigningKey::from_bytes(&self.key.as_slice()).unwrap();

        let pub_key = private_key.verifying_key();

        println!("{:?}", pub_key.to_bytes().len());

        PublicKey::new(pub_key.to_bytes().to_vec())
    }

    // Canonically sign message
    pub fn sign_message_canonical(&self, message: &str) -> CanonicalSignature {
        let private_key = SigningKey::from_bytes(&self.key.as_slice()).unwrap();
        let hashed_message = hash_message(message);

        let sig: RecoverableSignature = private_key.sign_digest(Sha256Proxy::from(hashed_message));

        let v = u8::from(sig.recovery_id()) as u64 + 31;

        let r_bytes: FieldBytes = sig.r().into();
        let s_bytes: FieldBytes = sig.s().into();
        let r = U256::from_big_endian(r_bytes.as_slice());
        let s = U256::from_big_endian(s_bytes.as_slice());

        CanonicalSignature { r, s, v }
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
        println!("{:?}", &signature.recovery_id());

        Signature::new(signature.as_ref().to_vec())
    }
}



#[cfg(test)]
mod test {
    use crate::keys::private::*;
    use sha2::{Sha256, Digest};
    use quickcheck::quickcheck;
    use quickcheck::TestResult;

    quickcheck! {
        fn prop(key_buffer: Vec<u8>) -> TestResult {
            if key_buffer.len() != 32 {
                return TestResult::discard()
            }
            TestResult::from_bool(PrivateKey{ key: key_buffer.clone() } == PrivateKey::new(key_buffer))
        }
    }

    quickcheck! {
        fn prop_login_inputs(user: String, pass: String, role: String) -> TestResult {

            if !user.is_ascii() || !pass.is_ascii() || !role.is_ascii() {
                return TestResult::discard()
            }

            let hash = Sha256::digest((user.clone() + &pass + &role).as_bytes());
            let priv1 = PrivateKey::new(hash.to_vec());
            
            TestResult::from_bool(priv1 == PrivateKey::from_login(&user, &pass, &role))
        }
    }

}



