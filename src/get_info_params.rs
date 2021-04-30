/*!
get_info API parameters
*/

use crate::util;
use std::fmt;

#[derive(Debug, Default)]
pub struct Info {
    // CTAP 2.0
    pub versions: Vec<String>,
    pub extensions: Vec<String>,
    pub aaguid: Vec<u8>,
    pub options: Vec<(String, bool)>,
    pub max_msg_size: i32,
    //pub pin_protocols: Vec<i32>,
    // CTAP 2.1
    pub pin_uv_auth_protocols: Vec<u32>,
    pub max_credential_count_in_list: u32,
    pub max_credential_id_length: u32,
    pub transports: Vec<String>,
    pub algorithms: Vec<(String, String)>,
}

impl fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tmp1 = format!("- versions                      = ");
        let tmp2 = format!("- extensions                    = ");
        let tmp3 = format!("- aaguid({:02})                    = ", self.aaguid.len());
        let tmp4 = format!("- options                       = ");
        let tmp5 = format!("- max_msg_size                  = ");
        let tmp6 = format!("- pin_uv_auth_protocols         = ");
        let tmp7 = format!("- max_credential_count_in_list  = ");
        let tmp8 = format!("- max_credential_id_length      = ");
        let tmp9 = format!("- transports                    = ");
        let tmpa = format!("- algorithms                    = ");

        write!(
            f,
            "{}{:?}\n{}{:?}\n{}{}\n{}{:?}\n{}{:?}\n{}{:?}\n{}{:?}\n{}{:?}\n{}{:?}\n{}{:?}",
            tmp1,
            self.versions,
            tmp2,
            self.extensions,
            tmp3,
            util::to_hex_str(&self.aaguid),
            tmp4,
            self.options,
            tmp5,
            self.max_msg_size,
            tmp6,
            self.pin_uv_auth_protocols,
            tmp7,
            self.max_credential_count_in_list,
            tmp8,
            self.max_credential_id_length,
            tmp9,
            self.transports,
            tmpa,
            self.algorithms,
        )
    }
}
