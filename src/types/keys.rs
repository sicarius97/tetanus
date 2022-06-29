use std::fmt;

use k256::ecdsa::VerifyingKey;

#[derive(Debug, PartialEq, Eq)]
pub struct PublicAddress(pub [u8; 33]);

impl fmt::Display for PublicAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sig: [u8; 33] = self.into();
        write!(f, "{:?}", bs58::encode(sig).into_string())
    }
}

impl From<&PublicAddress> for [u8; 33] {
    fn from(key: &PublicAddress) -> [u8; 33] {
        key.into()
    }
}

impl From<k256::elliptic_curve::PublicKey<k256::Secp256k1>> for PublicAddress {
    fn from(key: k256::elliptic_curve::PublicKey<k256::Secp256k1>) -> Self {
       let verify: VerifyingKey = key.into();
       Self(verify.to_bytes().into())
    }
}

pub struct PrivateAddress(pub [u8; 32]);