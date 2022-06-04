use crate::encrypt::cose::CoseKey;
use crate::util;
use serde_cbor::Value;
use std::fmt;

#[derive(Debug, Default, Clone)]
pub struct PublicKey {
    pub pem: String,
    pub der: Vec<u8>,
}
impl PublicKey {
    pub fn new(cbor: &Value) -> Self {
        let cose_key = CoseKey::new(cbor).unwrap();

        let mut cose_public_key = PublicKey::default();
        cose_public_key.der = cose_key.to_public_key_der();
        cose_public_key.pem = util::convert_to_publickey_pem(&cose_public_key.der);
        cose_public_key
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(der : {} , pem : {})",
            util::to_hex_str(&self.der),
            self.pem
        )
    }
}
