use ring::hmac;

pub struct PinToken(pub hmac::SigningKey);

impl PinToken {
    pub fn auth(&self, data: &[u8]) -> [u8; 16] {
        let signature = hmac::sign(&self.0, &data);
        let mut out = [0; 16];
        out.copy_from_slice(&signature.as_ref()[0..16]);
        out
    }
}
