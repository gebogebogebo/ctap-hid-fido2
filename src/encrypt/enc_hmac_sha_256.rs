use ring::hmac;

pub fn authenticate(key: &[u8], message: &[u8]) -> Vec<u8> {
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key.as_ref());
    let tag = hmac::sign(&hmac_key, message);
    tag.as_ref().to_vec()
}
