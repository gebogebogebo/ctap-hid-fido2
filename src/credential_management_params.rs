
use crate::util;

#[derive(Debug, Default)]
pub struct PublicKeyCredentialRpEntity{
    pub id: String,
    pub name: String,
}

#[derive(Debug, Default)]
pub struct CredsMetadata {
    pub existing_resident_credentials_count: u32,
    pub max_possible_remaining_resident_credentials_count: u32,
    pub rp: PublicKeyCredentialRpEntity,
    pub rpid_hash: Vec<u8>,
    pub total_rps: u32,
}
impl CredsMetadata {
    #[allow(dead_code)]
    pub fn print(self: &CredsMetadata, title: &str) {
        println!("{}", title);
        println!("- existing_resident_credentials_count               = {:?}", self.existing_resident_credentials_count);
        println!("- max_possible_remaining_resident_credentials_count = {:?}", self.max_possible_remaining_resident_credentials_count);
        println!("- rp.id                                             = {:?}", self.rp.id);
        println!("- rp.name                                           = {:?}", self.rp.name);
        println!("- rpid_hash                                         = {:?}", util::to_hex_str(&self.rpid_hash));
        println!("- rp.total_rps                                      = {:?}", self.total_rps);
    }
}
