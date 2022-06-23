use k256::sha2::{Sha256, Digest};
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
        let hash = Sha256::digest(seed);
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

        let checksum = Sha256::digest(Sha256::digest(&key_vec));

        let with_checksum = [key_vec, checksum[0..4].to_vec()].concat();

        let wif_string = bs58::encode(with_checksum).into_string();

        wif_string
    }
}
