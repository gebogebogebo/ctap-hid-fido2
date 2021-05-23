//use hmac::{Hmac, Mac, NewMac};
//use sha2::Sha256;

pub struct PinToken {
    pub signing_key: ring::hmac::SigningKey,
    pub key: Vec<u8>,
}

impl PinToken {
    pub fn new(data: &[u8]) -> PinToken {
        PinToken {
            signing_key: ring::hmac::SigningKey::new(&ring::digest::SHA256, &data),
            key: data.to_vec(),
        }
    }

    pub fn authenticate_v1(&self, data: &[u8]) -> [u8; 16] {
        let signature = ring::hmac::sign(&self.signing_key, &data);
        let mut out = [0; 16];
        out.copy_from_slice(&signature.as_ref()[0..16]);
        out
    }

}
