use k256::ecdsa::signature::Signature as OtherSignature;
use::ripemd::{Ripemd160, Digest};
use::k256::ecdsa::recoverable::Signature as RecoverableSignature;
use wasm_bindgen::prelude::*;

fn decode_from_string(sig: String) -> RecoverableSignature {
    let decoded_buffer = bs58::decode(sig).into_vec().unwrap();

    let sig_buffer = &decoded_buffer[0..&decoded_buffer.len() - 4];
    let checksum = &decoded_buffer[&decoded_buffer.len() - 4..];
    assert!(sig_buffer.len() == 65);
    assert!(checksum.len() == 4);

    let signature = RecoverableSignature::from_bytes(sig_buffer).unwrap();

    signature
    
}

fn encode_to_string(sig: RecoverableSignature) -> String {
    let check_bytes = b"K1";
    let sig_buffer = sig.as_ref();
    assert!(sig_buffer.len() == 65);

    let check = [sig_buffer, check_bytes].concat();

    let mut hasher = Ripemd160::new();

    hasher.update(check);

    let result = hasher.finalize();

    let checksum = &result[0..4];

    let encoded_string = bs58::encode([sig_buffer, checksum].concat()).into_string();

    return encoded_string
}

#[derive(Debug, Clone, PartialEq)]
#[wasm_bindgen]
pub struct Signature{ sig: Vec<u8> }

#[wasm_bindgen]
impl Signature {
    pub fn new(sig: Vec<u8>) -> Signature {
        Signature { sig }
    }

    pub fn to_string(&self) -> String {
        let signature = RecoverableSignature::from_bytes(&self.sig).unwrap();
        let sig_string = encode_to_string(signature);

        println!("{:?}", &self.sig);

        sig_string
    }

    /// Allows for a base58 string to be decoded into its original buffer
    /// ```
    /// use tetanus::keys::PrivateKey;
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
        let signature = decode_from_string(sig);

        let signature2 = Signature { sig: signature.as_ref().to_vec() };

        println!("{:?}", signature2);

        signature2
    }
}
