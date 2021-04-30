/*!
PublicKey
*/

use crate::cose;
use crate::util;
use serde_cbor::Value;
use std::fmt;

#[derive(Debug, Default, Clone)]
pub struct PublicKey {
    pub pem: String,
    pub der: Vec<u8>,
}
impl PublicKey {
    pub fn get(self: &mut PublicKey, cbor: &Value) -> Self {
        let mut ret = self.clone();
        let cose_key = cose::CoseKey::decode(cbor).unwrap();
        ret.der = cose_key.convert_to_publickey_der();
        ret.pem = util::convert_to_publickey_pem(&ret.der);

        ret
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
