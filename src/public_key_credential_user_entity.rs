use crate::{util, util_ciborium};
use std::fmt;
use ciborium::value::Value;
use anyhow::Result;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct PublicKeyCredentialUserEntity {
    pub id: Vec<u8>,
    pub name: String,
    pub display_name: String,
}
impl PublicKeyCredentialUserEntity {
    pub fn new(
        id: Option<&[u8]>,
        name: Option<&str>,
        display_name: Option<&str>,
    ) -> PublicKeyCredentialUserEntity {
        let mut ret = PublicKeyCredentialUserEntity::default();
        if let Some(v) = id {
            ret.id = v.to_vec();
        }
        if let Some(v) = name {
            ret.name = v.to_string();
        }
        if let Some(v) = display_name {
            ret.display_name = v.to_string();
        }
        ret
    }
    pub fn get_id(self: &mut PublicKeyCredentialUserEntity, cbor: &Value) -> Result<Self> {
        let mut ret = self.clone();
        ret.id = util_ciborium::cbor_get_bytes_from_map(cbor, "id")?;
        Ok(ret)
    }
    
    pub fn get_name(self: &mut PublicKeyCredentialUserEntity, cbor: &Value) -> Result<Self> {
        let mut ret = self.clone();
        ret.name = util_ciborium::cbor_get_string_from_map(cbor, "name")?;
        Ok(ret)
    }
    
    pub fn get_display_name(self: &mut PublicKeyCredentialUserEntity, cbor: &Value) -> Result<Self> {
        let mut ret = self.clone();
        ret.display_name = util_ciborium::cbor_get_string_from_map(cbor, "displayName")?;
        Ok(ret)
    }
}
impl fmt::Display for PublicKeyCredentialUserEntity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(id : {} , name : {} , display_name : {})",
            util::to_hex_str(&self.id),
            self.name,
            self.display_name
        )
    }
}
