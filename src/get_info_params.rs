/*!
get_info API parameters
*/

use std::fmt;
use crate::str_buf::StrBuf;

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
        let mut strbuf = StrBuf::new(30);
        strbuf
            .append("- versions", &format!("{:?}",self.versions))
            .append("- extensions", &format!("{:?}",self.extensions))
            .appenh("- aaguid",&self.aaguid)
            .append("- options", &format!("{:?}",self.options))
            .append("- max_msg_size", &self.max_msg_size)
            .append("- pin_uv_auth_protocols", &format!("{:?}",self.pin_uv_auth_protocols))
            .append("- max_credential_count_in_list", &self.max_credential_count_in_list)
            .append("- max_credential_id_length", &self.max_credential_id_length)
            .append("- transports", &format!("{:?}",self.transports))
            .append("- algorithms", &format!("{:?}",self.algorithms));
        write!(f, "{}", strbuf.build())
    }
}
