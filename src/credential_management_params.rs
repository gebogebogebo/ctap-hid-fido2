
use crate::util;
use serde_cbor::Value;
use crate::cose;

#[derive(Debug, Default, Clone)]
pub struct PublicKeyCredentialRpEntity{
    pub id: String,
    pub name: String,
}
impl PublicKeyCredentialRpEntity {
    pub fn get_id(self: &mut PublicKeyCredentialRpEntity, cbor: &Value) -> Self{
        let mut ret = self.clone();
        ret.id = util::cbor_get_string_from_map(cbor,"id").unwrap_or_default();
        ret
    }
    pub fn get_name(self: &mut PublicKeyCredentialRpEntity, cbor: &Value) -> Self{
        let mut ret = self.clone();
        ret.name = util::cbor_get_string_from_map(cbor,"name").unwrap_or_default();
        ret
    }
}

#[derive(Debug, Default, Clone)]
pub struct PublicKeyCredentialUserEntity{
    pub id: Vec<u8>,
    pub name: String,
    pub display_name: String,
}
impl PublicKeyCredentialUserEntity {
    pub fn get_id(self: &mut PublicKeyCredentialUserEntity, cbor: &Value) -> Self{
        let mut ret = self.clone();
        ret.id = util::cbor_get_bytes_from_map(cbor,"id").unwrap_or_default();
        ret
    }
    pub fn get_name(self: &mut PublicKeyCredentialUserEntity, cbor: &Value) -> Self{
        let mut ret = self.clone();
        ret.name = util::cbor_get_string_from_map(cbor,"name").unwrap_or_default();
        ret
    }
    pub fn get_display_name(self: &mut PublicKeyCredentialUserEntity, cbor: &Value) -> Self{
        let mut ret = self.clone();
        ret.display_name = util::cbor_get_string_from_map(cbor,"displayName").unwrap_or_default();
        ret
    }
}

#[derive(Debug, Default, Clone)]
pub struct PublicKeyCredentialDescriptor{
    pub credential_id: Vec<u8>,
    pub credential_type: String,
}
impl PublicKeyCredentialDescriptor {
    pub fn get_id(self: &mut PublicKeyCredentialDescriptor, cbor: &Value) -> Self{
        let mut ret = self.clone();
        ret.credential_id = util::cbor_get_bytes_from_map(cbor,"id").unwrap_or_default();
        ret
    }
    pub fn get_name(self: &mut PublicKeyCredentialDescriptor, cbor: &Value) -> Self{
        let mut ret = self.clone();
        ret.credential_type = util::cbor_get_string_from_map(cbor,"type").unwrap_or_default();
        ret
    }
}

#[derive(Debug, Default, Clone)]
pub struct PublicKey{
    pub credential_publickey_pem: String,
    pub credential_publickey_der: Vec<u8>,
}
impl PublicKey {
    pub fn get(self: &mut PublicKey, cbor: &Value) -> Self{
        let mut ret = self.clone();
        let cose_key = cose::CoseKey::decode(cbor).unwrap();
        ret.credential_publickey_der = cose_key.convert_to_publickey_der();
        ret.credential_publickey_pem =
            util::convert_to_publickey_pem(&ret.credential_publickey_der);
    
        ret
    }
}

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
}
impl CredsMetadata {
    #[allow(dead_code)]
    pub fn print(self: &CredsMetadata, title: &str) {
        println!("{}", title);
        println!("- existing_resident_credentials_count               = {:?}", self.existing_resident_credentials_count);
        println!("- max_possible_remaining_resident_credentials_count = {:?}", self.max_possible_remaining_resident_credentials_count);
        println!("- rp.id                                             = {:?}", self.public_key_credential_rp_entity.id);
        println!("- rp.name                                           = {:?}", self.public_key_credential_rp_entity.name);
        println!("- rpid_hash                                         = {:?}", util::to_hex_str(&self.rpid_hash));
        println!("- rp.total_rps                                      = {:?}", self.total_rps);
    }
}
