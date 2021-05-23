use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;

//Computes a MAC of the given message

pub fn authenticate(key: &[u8], message: &[u8]) -> Vec<u8> {
    // Create alias for HMAC-SHA256
    type HmacSha256 = Hmac<Sha256>;

    // Create HMAC-SHA256 instance which implements `Mac` trait
    let mut mac = HmacSha256::new_varkey(key).unwrap();
    mac.update(&message);

    let result = mac.finalize();

    let code_bytes = result.into_bytes();
    code_bytes.to_vec()
}

pub fn verify(key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    // Create alias for HMAC-SHA256
    type HmacSha256 = Hmac<Sha256>;

    // Create HMAC-SHA256 instance which implements `Mac` trait
    let mut mac = HmacSha256::new_varkey(key).unwrap();
    mac.update(&message);

    // `verify` will return `Ok(())` if code is correct, `Err(MacError)` otherwise
    match mac.verify(signature) {
        Ok(()) => true,
        Err(_e) => false,
    }
}
