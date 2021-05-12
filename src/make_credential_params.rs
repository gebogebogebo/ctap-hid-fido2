/*!
make_credential API parameters
*/

use crate::public_key::PublicKey;
use crate::public_key_credential_descriptor::PublicKeyCredentialDescriptor;
use crate::util;
use std::fmt;
use crate::credential_management_params::CredentialProtectionPolicy;

/// Attestation Object
/// [https://www.w3.org/TR/webauthn/#sctn-attestation](https://www.w3.org/TR/webauthn/#sctn-attestation)
#[derive(Debug, Default)]
pub struct Attestation {
    pub fmt: String,
    pub rpid_hash: Vec<u8>,
    pub flags_user_present_result: bool,
    pub flags_user_verified_result: bool,
    pub flags_attested_credential_data_included: bool,
    pub flags_extension_data_included: bool,
    pub sign_count: u32,
    pub aaguid: Vec<u8>,
    pub credential_descriptor: PublicKeyCredentialDescriptor,
    pub credential_publickey: PublicKey,
    pub auth_data: Vec<u8>,

    pub attstmt_alg: i32,
    pub attstmt_sig: Vec<u8>,
    pub attstmt_x5c: Vec<Vec<u8>>,
}

impl fmt::Display for Attestation {
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
        let tmp7 = format!(
            "- aaguid({:02})                              = ",
            self.aaguid.len(),
        );
        let tmp8 = format!("- credential_descriptor                   = ");
        let tmp9 = format!("- credential_publickey                    = ");
        let tmpa = format!("- attstmt_alg                             = ");
        let tmpb = format!(
            "- attstmt_sig({:02})                         = ",
            self.attstmt_sig.len(),
        );
        let tmpc = format!("- attstmt_x5c_num                         = ");
        //let tmpd = format!(
        //    "- attstmt_x5c({:02})                         = ",
        //    self.attstmt_x5c.len(),
        //);

        write!(
            f,
            "{}{}\n{}{}\n{}{}\n{}{}\n{}{}\n{}{}\n{}{}\n{}{}\n{}{}\n{}{}\n{}{}\n{}{}",
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
            util::to_hex_str(&self.aaguid),
            tmp8,
            self.credential_descriptor,
            tmp9,
            self.credential_publickey,
            tmpa,
            self.attstmt_alg,
            tmpb,
            util::to_hex_str(&self.attstmt_sig),
            tmpc,
            self.attstmt_x5c.len(),
            //tmpd,
            //util::to_hex_str(&self.attstmt_x5c[0]),
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Extension {
    CredProtect(CredentialProtectionPolicy),        // credProtect 0x01
    CredBlob(Vec<u8>),          //  "credBlob": Byte String containing the credBlob value
    MinPinLength(bool),         // "minPinLength": true
    HmacSecret(bool),
}
/*
impl From<String> for Extensions {
    fn from(from: String) -> Extensions {
        if from == "hmac-secret"{
            Extensions::HmacSecret(true)
        }else{
            Extensions::HmacSecret(false)
        }
    }
}
*/
// PEND 結局いらないかも
impl From<Extension> for String {
    fn from(from: Extension) -> String {
        if let Extension::HmacSecret(_) = from {
            "hmac-secret".to_string()
        } else {
            "".to_string()
        }
    }
}
