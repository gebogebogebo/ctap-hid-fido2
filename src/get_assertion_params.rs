/*!
get_assertion API parameters
*/

use crate::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use crate::str_buf::StrBuf;
use std::fmt;
use strum_macros::AsRefStr;

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
        let mut strbuf = StrBuf::new(42);
        strbuf
            .appenh("- rpid_hash", &self.rpid_hash)
            .append(
                "- flags_user_present_result",
                &self.flags_user_present_result,
            )
            .append(
                "- flags_user_verified_result",
                &self.flags_user_verified_result,
            )
            .append(
                "- flags_attested_credential_data_included",
                &self.flags_attested_credential_data_included,
            )
            .append(
                "- flags_extension_data_included",
                &self.flags_extension_data_included,
            )
            .append("- sign_count", &self.sign_count)
            .append("- number_of_credentials", &self.number_of_credentials)
            .appenh("- signature", &self.signature)
            .append("- user", &self.user)
            .appenh("- credential_id", &self.credential_id);
        write!(f, "{}", strbuf.build())
    }
}

#[derive(Debug, Clone, strum_macros::ToString, AsRefStr)]
pub enum Extension {
    #[strum(serialize = "hmac-secret")]
    HmacSecret(Option<[u8; 32]>),
}
