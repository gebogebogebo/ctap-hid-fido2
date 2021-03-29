//use crate::util;

// v1
use ring;

// v2
use sha2::Sha256;
use hmac::{Hmac, Mac, NewMac};

pub struct PinToken {
    pub signing_key : ring::hmac::SigningKey,
    pub key :Vec<u8>,
}

impl PinToken {
    pub fn authenticate_v1(&self, data: &[u8]) -> [u8; 16] {
        let signature = ring::hmac::sign(&self.signing_key, &data);
        let mut out = [0; 16];
        out.copy_from_slice(&signature.as_ref()[0..16]);
        out
    }

    pub fn authenticate_v2(&self, message: &[u8],firstbyte: usize) -> Vec<u8> {
        // Create alias for HMAC-SHA256
        type HmacSha256 = Hmac<Sha256>;

        // Create HMAC-SHA256 instance which implements `Mac` trait
        let mut mac = HmacSha256::new_varkey(&self.key)
            .expect("HMAC can take key of any size");
        mac.update(&message);

        // `result` has type `Output` which is a thin wrapper around array of
        // bytes for providing constant time equality check
        let result = mac.finalize();

        // To get underlying array use `into_bytes` method, but be careful, since
        // incorrect use of the code value may permit timing attacks which defeat
        // the security provided by the `Output`
        let code_bytes = result.into_bytes();
        code_bytes.to_vec()[0..firstbyte].to_vec()
        //println!("- ret({:02})    = {:?}", ret.len(),util::to_hex_str(&ret));
    }
}
