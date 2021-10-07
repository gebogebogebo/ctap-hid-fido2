use crate::ctaphid;
use crate::get_info_command;
use crate::get_info_params;
use crate::get_info_response;
use crate::util;
use crate::FidoKeyHid;
use crate::HidParam;
use anyhow::{anyhow, Error, Result};

pub fn get_info(hid_params: &[HidParam]) -> Result<get_info_params::Info, String> {
    let device = FidoKeyHid::new(hid_params)?;
    let cid = ctaphid::ctaphid_init(&device)?;

    let send_payload = get_info_command::create_payload();
    if util::is_debug() {
        println!(
            "- get_info({:02})    = {:?}",
            send_payload.len(),
            util::to_hex_str(&send_payload)
        );
    }

    let response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload)?;
    if util::is_debug() {
        println!(
            "- response_cbor({:02})    = {:?}",
            response_cbor.len(),
            util::to_hex_str(&response_cbor)
        );
    }

    let info = get_info_response::parse_cbor(&response_cbor)?;
    Ok(info)
}

pub fn get_info_u2f(hid_params: &[HidParam]) -> Result<String> {
    let device = FidoKeyHid::new(hid_params).map_err(Error::msg)?;
    let cid = ctaphid::ctaphid_init(&device).map_err(Error::msg)?;

    let _data: Vec<u8> = Vec::new();

    // CTAP1_INS.Version = 3
    match ctaphid::send_apdu(&device, &cid, 0, 3, 0, 0, &_data) {
        Ok(result) => {
            let version: String = String::from_utf8(result).unwrap();
            Ok(version)
        }
        Err(error) => Err(anyhow!(error)),
    }
}
