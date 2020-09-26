use crate::util;
use num::NumCast;
use serde_cbor::Value;

pub struct Info {
    pub versions: Vec<String>,
    pub extensions: Vec<String>,
    pub aaguid: Vec<u8>,
    pub options: Vec<(String, bool)>,
    pub max_msg_size: i32,
    pub pin_protocols: Vec<i32>,
}

fn parse_cbor_member(member: i128, val: &Value, info: &mut Info) {
    match member {
        1 => info.versions = util::cbor_value_to_vec_string(val).unwrap(),
        2 => info.extensions = util::cbor_value_to_vec_string(val).unwrap(),
        3 => info.aaguid = util::cbor_value_to_vec_u8(val).unwrap(),
        4 => {
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
        5 => info.max_msg_size = util::cbor_value_to_i32(val).unwrap(),
        6 => {
            if let Value::Array(xs) = val {
                for x in xs {
                    if let Value::Integer(v) = x {
                        info.pin_protocols.push(NumCast::from(*v).unwrap());
                    }
                }
            }
        }
        _ => println!("- anything error"),
    }
}

pub fn parse_cbor(bytes: &[u8]) -> Result<Info, String> {
    let cbor = serde_cbor::from_slice(bytes).unwrap();

    let mut info = Info {
        versions: [].to_vec(),
        extensions: [].to_vec(),
        aaguid: b"".to_vec(),
        options: [].to_vec(),
        max_msg_size: 0,
        pin_protocols: [].to_vec(),
    };

    if let Value::Map(n) = cbor {
        for (key, val) in &n {
            if let Value::Integer(member) = key {
                parse_cbor_member(*member, val, &mut info);
            }
        }
        Ok(info)
    } else {
        Err(String::from("parse error!"))
    }
}
