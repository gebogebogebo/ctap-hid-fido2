use crate::util_ciborium;
use anyhow::Result;
use ciborium::value::Value;
use std::fmt;

#[derive(Debug, Default, Clone)]
pub struct PublicKeyCredentialRpEntity {
    pub id: String,
    pub name: String,
}
impl PublicKeyCredentialRpEntity {
    pub fn get_id(self: &mut PublicKeyCredentialRpEntity, cbor: &Value) -> Result<Self> {
        let mut ret = self.clone();
        ret.id = util_ciborium::cbor_get_string_from_map(cbor, "id")?;
        Ok(ret)
    }

    pub fn get_name(self: &mut PublicKeyCredentialRpEntity, cbor: &Value) -> Result<Self> {
        let mut ret = self.clone();
        ret.name = util_ciborium::cbor_get_string_from_map(cbor, "name")?;
        Ok(ret)
    }
}
impl fmt::Display for PublicKeyCredentialRpEntity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(id : {} , name : {})", self.id, self.name)
    }
}
