/*!
get_info API parameters
*/

use crate::str_buf::StrBuf;
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
    pub max_serialized_large_blob_array: u32,
    pub force_pin_change: bool,
    pub min_pin_length: u32,
    pub firmware_version: u32,
    pub max_cred_blob_length: u32,
    pub max_rpids_for_set_min_pin_length: u32,
    pub preferred_platform_uv_attempts: u32,
    pub uv_modality: u32,
    pub remaining_discoverable_credentials: u32,
}

impl fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut strbuf = StrBuf::new(36);
        strbuf
            .append("- versions", &format!("{:?}", self.versions))
            .append("- extensions", &format!("{:?}", self.extensions))
            .appenh("- aaguid", &self.aaguid)
            .append("- options", &format!("{:?}", self.options))
            .append("- max_msg_size", &self.max_msg_size)
            .append(
                "- pin_uv_auth_protocols",
                &format!("{:?}", self.pin_uv_auth_protocols),
            )
            .append(
                "- max_credential_count_in_list",
                &self.max_credential_count_in_list,
            )
            .append("- max_credential_id_length", &self.max_credential_id_length)
            .append("- transports", &format!("{:?}", self.transports))
            .append("- algorithms", &format!("{:?}", self.algorithms))
            .append(
                "- max_serialized_large_blob_array",
                &format!("{:?}", self.max_serialized_large_blob_array),
            )
            .append(
                "- force_pin_change",
                &format!("{:?}", self.force_pin_change),
            )
            .append("- min_pin_length", &format!("{:?}", self.min_pin_length))
            .append(
                "- firmware_version",
                &format!("{:?}", self.firmware_version),
            )
            .append(
                "- max_cred_blob_length",
                &format!("{:?}", self.max_cred_blob_length),
            )
            .append(
                "- max_rpids_for_set_min_pin_length",
                &format!("{:?}", self.max_rpids_for_set_min_pin_length),
            )
            .append(
                "- preferred_platform_uv_attempts",
                &format!("{:?}", self.preferred_platform_uv_attempts),
            )
            .append("- uv_modality", &format!("{:?}", self.uv_modality))
            .append(
                "- remaining_discoverable_credentials",
                &format!("{:?}", self.remaining_discoverable_credentials),
            );

        write!(f, "{}", strbuf.build())
    }
}
