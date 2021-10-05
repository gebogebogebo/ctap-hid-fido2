use crypto::sha2::Sha256;
use crypto::hmac::Hmac;
use crypto::mac::Mac;

pub fn authenticate(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut hmac = Hmac::new(Sha256::new(), key);
    hmac.input(message);
    let result = hmac.result();
    result.code().into()
}