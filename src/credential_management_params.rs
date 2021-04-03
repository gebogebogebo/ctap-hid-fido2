
use crate::util;

#[derive(Debug, Default, Clone)]
pub struct PublicKeyCredentialRpEntity{
    pub id: String,
    pub name: String,
}

#[derive(Debug, Default, Clone)]
pub struct PublicKeyCredentialUserEntity{
    pub id: Vec<u8>,
    pub name: String,
    pub display_name: String,
}

#[derive(Debug, Default, Clone)]
pub struct PublicKeyCredentialDescriptor{
    pub credential_id: Vec<u8>,
    pub credential_type: String,
}

#[derive(Debug, Default, Clone)]
pub struct PublicKey{
    pub credential_publickey_pem: String,
    pub credential_publickey_der: Vec<u8>,
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
