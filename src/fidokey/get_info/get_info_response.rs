use super::get_info_params;
use crate::util_ciborium;
use anyhow::Result;

pub fn parse_cbor(bytes: &[u8]) -> Result<get_info_params::Info> {
    let mut info = get_info_params::Info::default();

    let maps2 = util_ciborium::cbor_bytes_to_map(bytes)?;
    for (key, val) in &maps2 {
        if util_ciborium::is_integer(key) {
            match util_ciborium::integer_to_i64(&key)? {
                0x01 => info.versions = util_ciborium::cbor_value_to_vec_string(val)?,
                0x02 => info.extensions = util_ciborium::cbor_value_to_vec_string(val)?,
                0x03 => info.aaguid = util_ciborium::cbor_value_to_vec_u8(val)?,
                0x04 => {
                    if util_ciborium::is_map(val) {
                        let xs = util_ciborium::extract_map_ref(val).expect("Expected a Map Value");
                        for (key, val) in xs {
                            let a = util_ciborium::cbor_value_to_str(key)?;
                            let b = util_ciborium::cbor_value_to_bool(val)?;
                            info.options.push((a.to_string(), b));
                        }
                    }
                },
                0x05 => info.max_msg_size = util_ciborium::cbor_value_to_num(val)?,
                0x06 => {
                    if util_ciborium::is_array(val) {
                        let xs = util_ciborium::extract_array_ref(val).expect("Expected a Array Value");
                        for x in xs {
                            info.pin_uv_auth_protocols.push(util_ciborium::cbor_value_to_num(x)?);
                        }
                    }
                },
                0x07 => info.max_credential_count_in_list = util_ciborium::cbor_value_to_num(val)?,
                0x08 => info.max_credential_id_length = util_ciborium::cbor_value_to_num(val)?,
                0x09 => info.transports = util_ciborium::cbor_value_to_vec_string(val)?,
                0x0A => {
                    if util_ciborium::is_array(val) {
                        let xs = util_ciborium::extract_array_ref(val).expect("Expected a Array Value");
                        for x in xs {
                            if util_ciborium::is_map(x) {
                                let n = util_ciborium::extract_map_ref(x).expect("Expected a Map Value");
                                for (key, val) in n {
                                    let setkey = util_ciborium::cbor_value_to_str(key)?;

                                    let setval = if util_ciborium::is_integer(val) {
                                        let q:i64 = util_ciborium::cbor_value_to_num(val)?;
                                        q.to_string()
                                    } else if util_ciborium::is_text(val) {
                                        util_ciborium::cbor_value_to_str(val)?
                                    } else {
                                        "".to_string()
                                    };
                                    info.algorithms.push((setkey, setval));
                                }
                            }
                        }
                    }
                },
                0x0B => info.max_serialized_large_blob_array = util_ciborium::cbor_value_to_num(val)?,
                0x0C => info.force_pin_change = util_ciborium::cbor_value_to_bool(val)?,
                0x0D => info.min_pin_length = util_ciborium::cbor_value_to_num(val)?,
                0x0E => info.firmware_version = util_ciborium::cbor_value_to_num(val)?,
                0x0F => info.max_cred_blob_length = util_ciborium::cbor_value_to_num(val)?,
                0x10 => info.max_rpids_for_set_min_pin_length = util_ciborium::cbor_value_to_num(val)?,
                0x11 => info.preferred_platform_uv_attempts = util_ciborium::cbor_value_to_num(val)?,
                0x12 => info.uv_modality = util_ciborium::cbor_value_to_num(val)?,
                0x14 => info.remaining_discoverable_credentials = util_ciborium::cbor_value_to_num(val)?,
                _ => println!("parse_cbor_member - unknown info {:?}", val),
            }
        }
    }
    
    Ok(info)
}
