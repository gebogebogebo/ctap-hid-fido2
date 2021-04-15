use crate::cose;
use crate::util;
use serde_cbor::Value;
use std::fmt;

#[derive(Debug, Default, Clone)]
pub struct CredsMetadata {
    pub existing_resident_credentials_count: u32,
    pub max_possible_remaining_resident_credentials_count: u32,
    pub public_key_credential_rp_entity: PublicKeyCredentialRpEntity,
    pub rpid_hash: Vec<u8>,
    pub total_rps: u32,
    pub public_key_credential_user_entity: PublicKeyCredentialUserEntity,
    pub public_key_credential_descriptor: PublicKeyCredentialDescriptor,
    pub public_key: PublicKey,
    pub total_credentials: u32,
    pub cred_protect: u32,
    pub large_blob_key: Vec<u8>,
}

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

#[derive(Debug, Default, Clone)]
pub struct PublicKeyCredentialUserEntity {
    pub id: Vec<u8>,
    pub name: String,
    pub display_name: String,
}
impl PublicKeyCredentialUserEntity {
    pub fn get_id(self: &mut PublicKeyCredentialUserEntity, cbor: &Value) -> Self {
        let mut ret = self.clone();
        ret.id = util::cbor_get_bytes_from_map(cbor, "id").unwrap_or_default();
        ret
    }
    pub fn get_name(self: &mut PublicKeyCredentialUserEntity, cbor: &Value) -> Self {
        let mut ret = self.clone();
        ret.name = util::cbor_get_string_from_map(cbor, "name").unwrap_or_default();
        ret
    }
    pub fn get_display_name(self: &mut PublicKeyCredentialUserEntity, cbor: &Value) -> Self {
        let mut ret = self.clone();
        ret.display_name = util::cbor_get_string_from_map(cbor, "displayName").unwrap_or_default();
        ret
    }
}
impl fmt::Display for PublicKeyCredentialUserEntity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(id : {} , name : {} , display_name : {})", util::to_hex_str(&self.id), self.name, self.display_name)
    }
}

#[derive(Debug, Default, Clone)]
pub struct PublicKeyCredentialDescriptor {
    pub id: Vec<u8>,
    pub ctype: String,
}
impl PublicKeyCredentialDescriptor {
    pub fn get_id(self: &mut PublicKeyCredentialDescriptor, cbor: &Value) -> Self {
        let mut ret = self.clone();
        ret.id = util::cbor_get_bytes_from_map(cbor, "id").unwrap_or_default();
        ret
    }
    pub fn get_type(self: &mut PublicKeyCredentialDescriptor, cbor: &Value) -> Self {
        let mut ret = self.clone();
        ret.ctype = util::cbor_get_string_from_map(cbor, "type").unwrap_or_default();
        ret
    }
}
impl fmt::Display for PublicKeyCredentialDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(id : {} , type : {})", util::to_hex_str(&self.id), self.ctype)
    }
}

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
        ret.pem =
            util::convert_to_publickey_pem(&ret.der);

        ret
    }
}
impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(der : {} , pem : {})", util::to_hex_str(&self.der), self.pem)
    }
}

#[derive(Debug, Default, Clone)]
pub struct CredentialsCount {
    pub existing_resident_credentials_count: u32,
    pub max_possible_remaining_resident_credentials_count: u32,
}
impl CredentialsCount {
    pub fn new(meta: &CredsMetadata) -> CredentialsCount {
        let mut ret = CredentialsCount::default();
        ret.existing_resident_credentials_count = meta.existing_resident_credentials_count;
        ret.max_possible_remaining_resident_credentials_count =
            meta.max_possible_remaining_resident_credentials_count;
        ret
    }
}
impl fmt::Display for CredentialsCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "- existing_resident_credentials_count = {}\n- max_possible_remaining_resident_credentials_count = {}", self.existing_resident_credentials_count, self.max_possible_remaining_resident_credentials_count)
    }
}

#[derive(Debug, Default, Clone)]
pub struct Rp {
    pub public_key_credential_rp_entity: PublicKeyCredentialRpEntity,
    pub rpid_hash: Vec<u8>,
}
impl Rp {
    pub fn new(meta: &CredsMetadata) -> Rp {
        let mut ret = Rp::default();
        ret.public_key_credential_rp_entity = meta.public_key_credential_rp_entity.clone();
        ret.rpid_hash = meta.rpid_hash.to_vec();
        ret
    }
}
impl fmt::Display for Rp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tmp1 = format!("- public_key_credential_rp_entity = ");
        let tmp2 = format!("- rpid_hash({:02})                   = ",self.rpid_hash.len());
        write!(
            f,
            "{}{}\n{}{}",
            tmp1,
            self.public_key_credential_rp_entity,
            tmp2,
            util::to_hex_str(&self.rpid_hash)
        )
    }
}

#[derive(Debug, Default, Clone)]
pub struct Credential {
    pub public_key_credential_user_entity: PublicKeyCredentialUserEntity,
    pub public_key_credential_descriptor: PublicKeyCredentialDescriptor,
    pub public_key: PublicKey,
}
impl Credential {
    pub fn new(meta: &CredsMetadata) -> Credential {
        let mut ret = Credential::default();
        ret.public_key_credential_user_entity = meta.public_key_credential_user_entity.clone();
        ret.public_key_credential_descriptor = meta.public_key_credential_descriptor.clone();
        ret.public_key = meta.public_key.clone();
        ret
    }
}
impl fmt::Display for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tmp1 = "- public_key_credential_user_entity = ";
        let tmp2 = "- public_key_credential_descriptor  = ";
        let tmp3 = "- public_key                        = ";
        write!(
            f,
            "{}{}\n{}{}\n{}{}",
            tmp1,
            self.public_key_credential_user_entity,
            tmp2,
            self.public_key_credential_descriptor,
            tmp3,
            self.public_key
        )
    }
}
