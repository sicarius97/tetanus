use::sha2::{Sha256, Digest as OtherDigest};
use primitive_types::H256;
use::ripemd::{Ripemd160, Digest};

#[derive(Debug, PartialEq)]
pub enum EncodeType {
    K1,
    Sha256x2,
    PubKey,
}

pub fn hash_message<S>(message: S) -> H256
where
    S: AsRef<[u8]>,
{
    let message = message.as_ref();

    sha256(message).into()
}

pub fn sha256<S>(bytes: S) -> [u8; 32]
where
    S: AsRef<[u8]>,
{
    Sha256::digest(bytes.as_ref()).into()
}

pub fn decode_from_string(input: String, encoding: Option<EncodeType>) -> Vec<u8> {
    let encode_type = encoding.unwrap_or(EncodeType::K1);
    let decoded_buffer = bs58::decode(input).into_vec().unwrap();

    if encode_type == EncodeType::PubKey {
        let key_buffer = &decoded_buffer[0..&decoded_buffer.len() - 4];
        let checksum = &decoded_buffer[&decoded_buffer.len() - 4..];

        assert!(key_buffer.len() == 32);
        assert!(checksum.len() == 4);

        key_buffer.to_vec()

    } else if encode_type == EncodeType::Sha256x2 {
        let key_buffer_with_network = &decoded_buffer[0..&decoded_buffer.len() - 4];
        let checksum = &decoded_buffer[&decoded_buffer.len() - 4..];
        let network_id = &key_buffer_with_network[..1];
        let key_buffer = &key_buffer_with_network[1..];

        assert!(checksum.len() == 4);
        assert!(key_buffer.len() == 32);
        assert!(network_id == &[0x80]);

        key_buffer.to_vec()

    } else {
        let sig_buffer = &decoded_buffer[0..&decoded_buffer.len() - 4];
        let checksum = &decoded_buffer[&decoded_buffer.len() - 4..];
        assert!(sig_buffer.len() == 65);
        assert!(checksum.len() == 4);

        sig_buffer.to_vec()
    }
}

pub fn encode_to_string(buffer: Vec<u8>, encoding: Option<EncodeType>) -> String {
    let encode_type = encoding.unwrap_or(EncodeType::K1);

    if encode_type == EncodeType::PubKey {
        let mut hasher = Ripemd160::new();

        hasher.update(buffer.clone());

        let hash = hasher.finalize();

        let input = [buffer, hash[0..4].to_vec()].concat();

        bs58::encode(input).into_string()

    } else if encode_type == EncodeType::Sha256x2 {
        let network_id: &[u8] = &[0x80];
        let key_vec = [network_id, &buffer].concat();

        let checksum = Sha256::digest(Sha256::digest(&key_vec).as_slice());

        let with_checksum = [key_vec, checksum[0..4].to_vec()].concat();

        return bs58::encode(with_checksum).into_string();
    } else {
        let check_bytes = b"K1";

        let check = [buffer.clone(), check_bytes.to_vec()].concat();

        let mut hasher = Ripemd160::new();

        hasher.update(check);

        let result = hasher.finalize();

        let checksum = &result[0..4];

        let encoded_string = bs58::encode([buffer, checksum.to_vec()].concat()).into_string();

        return encoded_string
    }
}