/*!
get_assertion API parameters
*/

use crate::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use crate::util;
use std::fmt;

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

impl fmt::Display for Assertion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tmp1 = format!(
            "- rpid_hash({:02})                           = ",
            self.rpid_hash.len(),
        );
        let tmp2 = format!("- flags_user_present_result               = ");
        let tmp3 = format!("- flags_user_verified_result              = ");
        let tmp4 = format!("- flags_attested_credential_data_included = ");
        let tmp5 = format!("- flags_extension_data_included           = ");
        let tmp6 = format!("- sign_count                              = ");
        let tmp7 = format!("- number_of_credentials                   = ");
        let tmp8 = format!(
            "- signature({:02})                           = ",
            self.signature.len(),
        );
        let tmp9 = format!("- user                                    = ");
        let tmpa = format!(
            "- credential_id({:02})                       = ",
            self.credential_id.len(),
        );

        write!(
            f,
            "{}{}\n{}{}\n{}{}\n{}{}\n{}{}\n{}{}\n{}{}\n{}{}\n{}{}\n{}{}",
            tmp1,
            util::to_hex_str(&self.rpid_hash),
            tmp2,
            self.flags_user_present_result,
            tmp3,
            self.flags_user_verified_result,
            tmp4,
            self.flags_attested_credential_data_included,
            tmp5,
            self.flags_extension_data_included,
            tmp6,
            self.sign_count,
            tmp7,
            self.number_of_credentials,
            tmp8,
            util::to_hex_str(&self.signature),
            tmp9,
            self.user,
            tmpa,
            util::to_hex_str(&self.credential_id),
        )
    }
}
