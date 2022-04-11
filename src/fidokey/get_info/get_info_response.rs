use super::get_info_params;
use crate::util;
use serde_cbor::Value;

pub fn parse_cbor(bytes: &[u8]) -> Result<get_info_params::Info, String> {
    let mut info = get_info_params::Info::default();
    let maps = util::cbor_bytes_to_map(bytes)?;
    for (key, val) in &maps {
        if let Value::Integer(member) = key {
            match member {
                0x01 => info.versions = util::cbor_value_to_vec_string(val)?,
                0x02 => info.extensions = util::cbor_value_to_vec_string(val)?,
                0x03 => info.aaguid = util::cbor_value_to_vec_u8(val)?,
                0x04 => {
                    if let Value::Map(xs) = val {
                        for (key, val) in xs {
                            if let Value::Text(s) = key {
                                if let Value::Bool(b) = val {
                                    info.options.push((s.to_string(), *b));
                                }
                            }
                        }
                    }
                }
                0x05 => info.max_msg_size = util::cbor_value_to_num(val)?,
                0x06 => {
                    if let Value::Array(xs) = val {
                        for x in xs {
                            info.pin_uv_auth_protocols.push(util::cbor_value_to_num(x)?);
                        }
                    }
                }
                0x07 => info.max_credential_count_in_list = util::cbor_value_to_num(val)?,
                0x08 => info.max_credential_id_length = util::cbor_value_to_num(val)?,
                0x09 => info.transports = util::cbor_value_to_vec_string(val)?,
                0x0A => {
                    if let Value::Array(xs) = val {
                        for x in xs {
                            if let Value::Map(n) = x {
                                for (key, val) in n {
                                    let setkey = {
                                        if let Value::Text(keystr) = key {
                                            keystr.to_string()
                                        } else {
                                            "".to_string()
                                        }
                                    };

                                    let setval = {
                                        if let Value::Text(valstr) = val {
                                            valstr.to_string()
                                        } else if let Value::Integer(valint) = val {
                                            valint.to_string()
                                        } else {
                                            "".to_string()
                                        }
                                    };

                                    info.algorithms.push((setkey, setval));
                                }
                            }
                        }
                    }
                }
                0x0B => info.max_serialized_large_blob_array = util::cbor_value_to_num(val)?,
                0x0C => info.force_pin_change = util::cbor_value_to_bool(val)?,
                0x0D => info.min_pin_length = util::cbor_value_to_num(val)?,
                0x0E => info.firmware_version = util::cbor_value_to_num(val)?,
                0x0F => info.max_cred_blob_length = util::cbor_value_to_num(val)?,
                0x10 => info.max_rpids_for_set_min_pin_length = util::cbor_value_to_num(val)?,
                0x11 => info.preferred_platform_uv_attempts = util::cbor_value_to_num(val)?,
                0x12 => info.uv_modality = util::cbor_value_to_num(val)?,
                0x14 => info.remaining_discoverable_credentials = util::cbor_value_to_num(val)?,
                _ => println!("parse_cbor_member - unknown info {:?}", member),
            }
        }
    }
    Ok(info)
}
