/*!
make_credential API parameters()
*/

use crate::util;

#[derive(Debug, Default)]
pub struct RkParam {
    pub user_id: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
}

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
    pub credential_id: Vec<u8>,
    pub credential_publickey: String,
    pub credential_publickey_byte: Vec<u8>,
    pub authdata: Vec<u8>,

    pub attstmt_alg: i32,
    pub attstmt_sig: Vec<u8>,
    pub attstmt_x5c: Vec<Vec<u8>>,
}

impl Attestation {
    #[allow(dead_code)]
    pub fn print(self: &Attestation, title: &str) {
        println!("{}", title);
        println!("- fmt                                     = {:?}", self.fmt);
        println!(
            "- rpid_hash({:02})                           = {:?}",
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
            "- aaguid({:02})                              = {:?}",
            self.aaguid.len(),
            util::to_hex_str(&self.aaguid)
        );
        println!(
            "- credential_id({:02})                       = {:?}",
            self.credential_id.len(),
            util::to_hex_str(&self.credential_id)
        );
        println!(
            "- attstmt_alg                             = {:?}",
            self.attstmt_alg
        );
        println!(
            "- attstmt_sig({:02})                         = {:?}",
            self.attstmt_sig.len(),
            util::to_hex_str(&self.attstmt_sig)
        );

        println!(
            "- attstmt_x5c_num                         = {:02}",
            self.attstmt_x5c.len()
        );

        for x in &self.attstmt_x5c{
            println!(
                "- attstmt_x5c({:04})                       = {:?}",
                x.len(),
                util::to_hex_str(x)
            );
    
        }
        
    }
}
