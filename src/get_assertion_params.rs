/*!
get_assertion API parameters
*/

use crate::util;
use std::fmt;
use serde_cbor::Value;

/// Assertion Object
#[derive(Debug, Default, Clone)]
pub struct Assertion {
    pub rpid_hash: Vec<u8>,

    pub flags_user_present_result: bool,
    pub flags_user_verified_result: bool,
    pub flags_attested_credential_data_included: bool,
    pub flags_extension_data_included: bool,

    pub sign_count: u32,

    pub number_of_credentials: i32,

    pub signature: Vec<u8>,

    pub user: PublicKeyCredentialUserEntity,

    pub credential_id: Vec<u8>,

    pub auth_data: Vec<u8>,
}

impl Assertion {
    #[allow(dead_code)]
    pub fn print(self: &Assertion, title: &str) {
        if util::is_debug() == false {
            return;
        }

        println!("{}", title);
        println!(
            "- rpid_hash({:02})                          = {:?}",
            self.rpid_hash.len(),
            util::to_hex_str(&self.rpid_hash)
        );
        println!(
            "- flags_user_present_result               = {:?}",
            self.flags_user_present_result
        );
        println!(
            "- flags_user_verified_result              = {:?}",
            self.flags_user_verified_result
        );
        println!(
            "- flags_attested_credential_data_included = {:?}",
            self.flags_attested_credential_data_included
        );
        println!(
            "- flags_extensiondata_included            = {:?}",
            self.flags_extension_data_included
        );
        println!(
            "- sign_count                              = {:?}",
            self.sign_count
        );
        println!(
            "- number_of_credentials                   = {:?}",
            self.number_of_credentials
        );
        println!(
            "- signature({:02})                           = {:?}",
            self.signature.len(),
            util::to_hex_str(&self.signature)
        );
        println!("- user = {}",self.user);
        println!(
            "- credential_id({:02})                       = {:?}",
            self.credential_id.len(),
            util::to_hex_str(&self.credential_id)
        );
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
        write!(
            f,
            "(id : {} , name : {} , display_name : {})",
            util::to_hex_str(&self.id),
            self.name,
            self.display_name
        )
    }
}
