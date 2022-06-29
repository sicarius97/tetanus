use primitive_types::{H256, U256};
use crate::utils::{hash_message, encode_to_string, decode_from_string};
use crate::types::keys::PublicAddress;
use crate::signatures::SignatureWrapper;
use k256::{
    ecdsa::{
        recoverable::{Id as RecoveryId, Signature as RecoverableSignature},
        Error as K256SignatureError, Signature as K256Signature,
    },
    elliptic_curve::consts::U32,
    PublicKey as K256PublicKey,
};
use generic_array::GenericArray;
use std::{convert::TryFrom, fmt};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub struct Signature{ pub r: U256, pub s: U256, pub v: u64 }

/// An error involving a signature.
#[derive(Debug, Error)]
pub enum SignatureError {
    /// Invalid length, secp256k1 signatures are 65 bytes
    #[error("invalid signature length, got {0}, expected 65")]
    InvalidLength(usize),
    /// When parsing a signature from string to hex
    /* 
    #[error(transparent)]
    DecodingError(#[from] hex::FromHexError),
    */
    /// Thrown when signature verification failed (i.e. when the address that
    /// produced the signature did not match the expected address)
    #[error("Signature verification failed. Expected {0}, got {1}")]
    VerificationError(PublicAddress, PublicAddress),
    /// Internal error during signature recovery
    #[error(transparent)]
    K256Error(#[from] K256SignatureError),
    /// Error in recovering public key from signature
    #[error("Public key recovery error")]
    RecoveryError,
}

/// Recovery message data.
///
/// The message data can either be a binary message that is first hashed
/// according to EIP-191 and then recovered based on the signature or a
/// precomputed hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryMessage {
    /// Message bytes
    Data(Vec<u8>),
    /// Message hash
    Hash(H256),
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sig = self.to_legacy(None);
        write!(f, "{}", sig)
    }
}

impl Signature {
    /// Verifies that signature on `message` was produced by `PublicKey`
    pub fn verify<M, A>(&self, message: M, public: A) -> Result<(), SignatureError>
    where
        M: Into<RecoveryMessage>,
        A: Into<PublicAddress>,
    {
        let public: PublicAddress = public.into();
        let recovered = self.recover(message)?;
        if recovered != public {
            return Err(SignatureError::VerificationError(public, recovered))
        }

        Ok(())
    }

    /// Recovers the Ethereum address which was used to sign the given message.
    ///
    /// Recovery signature data uses 'Electrum' notation, this means the `v`
    /// value is expected to be either `27` or `28`.
    pub fn recover<M>(&self, message: M) -> Result<PublicAddress, SignatureError>
    where
        M: Into<RecoveryMessage>,
    {
        let message = message.into();
        let message_hash = match message {
            RecoveryMessage::Data(ref message) => hash_message(message),
            RecoveryMessage::Hash(hash) => hash,
        };

        let (recoverable_sig, _recovery_id) = self.as_signature()?;
        let verify_key =
            recoverable_sig.recover_verify_key_from_digest_bytes(message_hash.as_ref().into())?;

        let public_key: PublicAddress = K256PublicKey::from(&verify_key).into();
        Ok(public_key)
    }

    /// Retrieves the recovery signature.
    fn as_signature(&self) -> Result<(RecoverableSignature, RecoveryId), SignatureError> {
        let recovery_id = self.recovery_id()?;
        let signature = {
            let mut r_bytes = [0u8; 32];
            let mut s_bytes = [0u8; 32];
            self.r.to_big_endian(&mut r_bytes);
            self.s.to_big_endian(&mut s_bytes);
            let gar: &GenericArray<u8, U32> = GenericArray::from_slice(&r_bytes);
            let gas: &GenericArray<u8, U32> = GenericArray::from_slice(&s_bytes);
            let sig = K256Signature::from_scalars(*gar, *gas)?;
            RecoverableSignature::new(&sig, recovery_id)?
        };

        Ok((signature, recovery_id))
    }

    /// Retrieve the recovery ID.
    pub fn recovery_id(&self) -> Result<RecoveryId, SignatureError> {
        let standard_v = normalize_recovery_id(self.v);
        Ok(RecoveryId::new(standard_v)?)
    }

    pub fn from_legacy(sig: &str, prefix: Option<&str>) -> Result<Signature, SignatureError> {
        let sig_string = sig.strip_prefix(prefix.unwrap_or("SIG_K1_")).unwrap_or(sig);

        let mut decoded_sig = decode_from_string(sig_string.to_string(), None);
        decoded_sig.rotate_left(1);

        Ok(Signature::try_from(decoded_sig.as_slice())?)
    }

    /// Returns a legacy base58 string compatible with eosio-ecc,
    /// dhive, hivejs, etc
    pub fn to_legacy(&self, prefix: Option<&str>) -> String {
        let prefix = prefix.unwrap_or("");
        // let signature = RecoverableSignature::from_bytes(&self.sig).unwrap();
        let mut current_buff = self.to_vec();
        current_buff.rotate_right(1);
        let sig_string = encode_to_string(current_buff, None);

        prefix.to_owned() + &sig_string
    }

    /// Copies and serializes `self` into a new `Vec` with the recovery id included
    #[allow(clippy::wrong_self_convention)]
    pub fn to_vec(&self) -> Vec<u8> {
        self.into()
    }
}

fn normalize_recovery_id(v: u64) -> u8 {
    match v {
        0 => 0,
        1 => 1,
        31 => 0,
        32 => 1,
        v if v >= 35 => ((v - 1) % 2) as _,
        _ => 4,
    }
}

impl<'a> TryFrom<&'a [u8]> for Signature {
    type Error = SignatureError;

    /// Parses a raw signature which is expected to be 65 bytes long where
    /// the first 32 bytes is the `r` value, the second 32 bytes the `s` value
    /// and the final byte is the `v` value in 'Electrum' notation.
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 65 {
            return Err(SignatureError::InvalidLength(bytes.len()))
        }

        let v = bytes[64];
        let r = U256::from_big_endian(&bytes[0..32]);
        let s = U256::from_big_endian(&bytes[32..64]);

        Ok(Signature { r, s, v: v.into() })
    }
}
/* 
impl FromStr for Signature {
    type Err = SignatureError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s)?;
        Signature::try_from(&bytes[..])
    }
}
*/

impl From<&Signature> for [u8; 65] {
    fn from(src: &Signature) -> [u8; 65] {
        let mut sig = [0u8; 65];
        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        src.r.to_big_endian(&mut r_bytes);
        src.s.to_big_endian(&mut s_bytes);
        sig[..32].copy_from_slice(&r_bytes);
        sig[32..64].copy_from_slice(&s_bytes);
        // TODO: What if we try to serialize a signature where
        // the `v` is not normalized?
        sig[64] = src.v as u8;
        sig
    }
}

impl From<Signature> for [u8; 65] {
    fn from(src: Signature) -> [u8; 65] {
        <[u8; 65]>::from(&src)
    }
}

impl From<&Signature> for Vec<u8> {
    fn from(src: &Signature) -> Vec<u8> {
        <[u8; 65]>::from(src).to_vec()
    }
}

impl From<Signature> for Vec<u8> {
    fn from(src: Signature) -> Vec<u8> {
        <[u8; 65]>::from(&src).to_vec()
    }
}

impl From<&SignatureWrapper> for Signature {
    fn from(src: &SignatureWrapper) -> Signature {
        Signature::try_from(src.sig().as_slice()).unwrap()
    }
}

impl From<&[u8]> for RecoveryMessage {
    fn from(s: &[u8]) -> Self {
        s.to_owned().into()
    }
}

impl From<Vec<u8>> for RecoveryMessage {
    fn from(s: Vec<u8>) -> Self {
        RecoveryMessage::Data(s)
    }
}

impl From<&str> for RecoveryMessage {
    fn from(s: &str) -> Self {
        s.as_bytes().to_owned().into()
    }
}

impl From<String> for RecoveryMessage {
    fn from(s: String) -> Self {
        RecoveryMessage::Data(s.into_bytes())
    }
}

impl From<[u8; 32]> for RecoveryMessage {
    fn from(hash: [u8; 32]) -> Self {
        H256(hash).into()
    }
}

impl From<H256> for RecoveryMessage {
    fn from(hash: H256) -> Self {
        RecoveryMessage::Hash(hash)
    }
}