/*!
get_assertion API parameters()
*/

use crate::util;

/// Assertion Object
#[derive(Debug, Default)]
pub struct Assertion {
    pub rpid_hash: Vec<u8>,
    pub flags_user_present_result: bool,
    pub flags_user_verified_result: bool,
    pub flags_attested_credential_data_included: bool,
    pub flags_extension_data_included: bool,

    pub sign_count: u32,
    pub aaguid: Vec<u8>,

    pub number_of_credentials: i32,

    pub signature: Vec<u8>,
    pub user_id: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,

    pub credential_id: Vec<u8>,
}

impl Assertion{
    #[allow(dead_code)]
    pub fn print(self: &Assertion, title: &str) {
        println!("{}", title);
        println!("authenticatorGetAssertion (0x02)");
        println!("- rpid_hash({:02})                          = {:?}", self.rpid_hash.len(),util::to_hex_str(&self.rpid_hash));
        println!("- flags_user_present_result               = {:?}", self.flags_user_present_result);
        println!("- flags_user_verified_result              = {:?}", self.flags_user_verified_result);
        println!("- flags_attested_credential_data_included = {:?}", self.flags_attested_credential_data_included);
        println!("- flags_extensiondata_included            = {:?}", self.flags_extension_data_included);
        println!("- sign_count                              = {:?}", self.sign_count);
        println!("- aaguid({:02})                              = {:?}", self.aaguid.len(),util::to_hex_str(&self.aaguid));
        println!("- number_of_credentials                   = {:?}", self.number_of_credentials);
        println!("- signature({:02})                           = {:?}", self.signature.len(),util::to_hex_str(&self.signature));
        println!("- user_id({:02})                             = {:?}", self.user_id.len(),util::to_hex_str(&self.user_id));
        println!("- user_name                               = {:?}", self.user_name);
        println!("- user_display_name                       = {:?}", self.user_display_name);
        println!("- credential_id({:02})                       = {:?}", self.credential_id.len(),util::to_hex_str(&self.credential_id));
    }
}