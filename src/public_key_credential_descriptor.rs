use crate::{util, util_ciborium};
use std::fmt;
use ciborium::value::Value;
use anyhow::Result;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct PublicKeyCredentialDescriptor {
    pub id: Vec<u8>,
    pub ctype: String,
}
impl PublicKeyCredentialDescriptor {
    pub fn get_id(self: &mut PublicKeyCredentialDescriptor, cbor: &Value) -> Result<Self> {
        let mut ret = self.clone();
        ret.id = util_ciborium::cbor_get_bytes_from_map(cbor, "id")?;
        Ok(ret)
    }
    
    pub fn get_type(self: &mut PublicKeyCredentialDescriptor, cbor: &Value) -> Result<Self> {
        let mut ret = self.clone();
        ret.ctype = util_ciborium::cbor_get_string_from_map(cbor, "type")?;
        Ok(ret)
    }
}
impl fmt::Display for PublicKeyCredentialDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(id : {} , type : {})",
            util::to_hex_str(&self.id),
            self.ctype
        )
    }
}
