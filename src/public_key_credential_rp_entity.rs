/*!
PublicKeyCredentialRpEntity
*/

use crate::util;
use serde_cbor::Value;
use std::fmt;

#[derive(Debug, Default, Clone)]
pub struct PublicKeyCredentialRpEntity {
    pub id: String,
    pub name: String,
}
impl PublicKeyCredentialRpEntity {
    pub fn get_id(self: &mut PublicKeyCredentialRpEntity, cbor: &Value) -> Self {
        let mut ret = self.clone();
        ret.id = util::cbor_get_string_from_map(cbor, "id").unwrap_or_default();
        ret
    }
    pub fn get_name(self: &mut PublicKeyCredentialRpEntity, cbor: &Value) -> Self {
        let mut ret = self.clone();
        ret.name = util::cbor_get_string_from_map(cbor, "name").unwrap_or_default();
        ret
    }
}
impl fmt::Display for PublicKeyCredentialRpEntity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(id : {} , name : {})", self.id, self.name)
    }
}
