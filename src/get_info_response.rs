use crate::util;
use crate::get_info_params;
use num::NumCast;
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
                _ => println!("parse_cbor_member - unknown info {:?}", member),
            }
        }
    }
    Ok(info)
}
