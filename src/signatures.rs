use::ripemd::{Ripemd160, Digest};
use::k256::ecdsa::recoverable::Signature;

pub fn sig_to_string(sig: Signature) -> String {
    let check_bytes = b"K1";
    let sig_buffer = [&[u8::from(31)], sig.r().to_bytes().as_slice(), sig.s().to_bytes().as_slice()].concat();
    let sig_buffer2 = sig_buffer.clone();
    assert!(sig_buffer.len() == 65);

    let check = [sig_buffer, check_bytes.to_vec()].concat();

    let mut hasher = Ripemd160::new();

    hasher.update(check);

    let result = hasher.finalize();

    let checksum = &result[0..4];

    let encoded_string = bs58::encode([sig_buffer2, checksum.to_vec()].concat()).into_string();

    return "SIG_K1_".to_owned() + &encoded_string
}
