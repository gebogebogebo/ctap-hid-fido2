
use crate::FidoKeyHid;
use crate::HidParam;
use crate::ctaphid;
use crate::util;
use crate::get_info_command;
use crate::get_info_response;

pub fn get_info(hid_params: &[HidParam]) -> Result<Vec<(String, String)>, String> {
    let device = FidoKeyHid::new(hid_params)?;
    let cid = ctaphid::ctaphid_init(&device)?;

    let send_payload = get_info_command::create_payload();
    //println!("{}",util::to_hex_str(&send_payload));

    let response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload)?;

    let info = get_info_response::parse_cbor(&response_cbor)?;
    //info.print("Debug");

    let mut result: Vec<(String, String)> = vec![];

    for i in info.versions {
        result.push(("versions".to_string(), i));
    }
    for i in info.extensions {
        result.push(("extensions".to_string(), i));
    }
    result.push(("aaguid".to_string(), util::to_hex_str(&info.aaguid)));

    for i in info.options {
        result.push((format!("options-{}", i.0), i.1.to_string()));
    }

    result.push(("max_msg_size".to_string(), info.max_msg_size.to_string()));

    for i in info.pin_uv_auth_protocols {
        result.push(("pin_uv_auth_protocols".to_string(), i.to_string()));
    }

    result.push((
        "max_credential_count_in_list".to_string(),
        info.max_credential_count_in_list.to_string(),
    ));
    result.push((
        "max_credential_id_length".to_string(),
        info.max_credential_id_length.to_string(),
    ));
    for i in info.algorithms {
        result.push((format!("algorithms-{}", i.0), i.1.to_string()));
    }

    Ok(result)
}
