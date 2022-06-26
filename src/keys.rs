use k256::{
    ecdsa::{recoverable::Signature as RecoverableSignature, SigningKey, signature::Signer, signature::digest::Digest, Signature},
    sha2::{Sha256}
};
use wasm_bindgen::prelude::*;



#[derive(Debug, Clone, PartialEq)]
#[wasm_bindgen]
pub struct PrivateKey{ key: Vec<u8> }

impl PrivateKey {
    /// Creates a new private key instance
    pub fn new(key: Vec<u8>) -> PrivateKey {
        PrivateKey{ key }
    }

    /// Returns a new private key instance by creating a seed with
    /// passed in arguments
    /// ```
    /// use tetanus::keys::PrivateKey;
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
    /// use tetanus::keys::PrivateKey;
    /// let test_wif = "5K8AruCpTY6gVeQRMd5UpeuoVR2YheRCjUDAVFrfiahZU4bBccj";
    /// let generated_wif = PrivateKey::from_login("test", "test", "owner").to_string();
    /// assert_eq!(test_wif, generated_wif)
    /// ```
    pub fn to_string(&self) -> String {
        assert!(&self.key.len() > &0);
        let network_id: &[u8] = &[0x80];
        let key_vec = [network_id, &self.key].concat();

        let checksum = Sha256::digest(Sha256::digest(&key_vec).as_slice());

        let with_checksum = [key_vec, checksum[0..4].to_vec()].concat();

        let wif_string = bs58::encode(with_checksum).into_string();

        wif_string
    }
    /// Takes in a PrivateKey instance and message then returns a signed message
    /// ```
    /// use tetanus::keys::PrivateKey;
    /// use tetanus::signatures::sig_to_string;
    /// let message = "test";
    /// let private = PrivateKey::from_login("test", "test", "owner");
    /// let sig = private.sign_message(message);
    /// let sig_string = sig_to_string(sig);
    /// assert_eq!("SIG_K1_KBGSFJZW39Q3Y7Gn1bW2yjDycWYKXpfFgoGEzzrT8dFuQiwuvj3jcXxThrxuZJg7AdsZVSKro7eFZz4N6f9i6Uzb6d5rza", sig_string)
    /// ```
    pub fn sign_message(&self, message: &str) -> RecoverableSignature {
        let private_key = SigningKey::from_bytes(&self.key.as_slice()).unwrap();
        let signature: Signature = private_key.sign(message.as_bytes());

        let rec_signature = RecoverableSignature::new(&signature, k256::ecdsa::recoverable::Id::new(u8::from(0)).unwrap()).unwrap();

        rec_signature
    }
}
