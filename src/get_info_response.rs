use crate::util;
use num::NumCast;
use serde_cbor::Value;

#[derive(Debug, Default)]
pub struct Info {
    pub versions: Vec<String>,
    pub extensions: Vec<String>,
    pub aaguid: Vec<u8>,
    pub options: Vec<(String, bool)>,
    pub max_msg_size: i32,
    pub pin_protocols: Vec<i32>,
}

impl Info {
    #[allow(dead_code)]
    pub fn print(self: &Info, title: &str) {
        println!("{}", title);
        println!("- versions      = {:?}", self.versions);
        println!("- extensions    = {:?}", self.extensions);
        println!(
            "- aaguid({:?})    = {:?}",
            self.aaguid.len(),
            util::to_hex_str(&self.aaguid)
        );
        println!("- options       = {:?}", self.options);
        println!("- max_msg_size  = {:?}", self.max_msg_size);
        println!("- pin_protocols = {:?}", self.pin_protocols);
    }
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
        5 => info.max_msg_size = util::cbor_cast_value(val).unwrap(),
        6 => {
            if let Value::Array(xs) = val {
                for x in xs {
                    if let Value::Integer(v) = x {
                        info.pin_protocols.push(NumCast::from(*v).unwrap());
                    }
                }
            }
        }
        _ => println!("parse_cbor_member - unknown info {:?}", member),
    }
}

pub fn parse_cbor(bytes: &[u8]) -> Result<Info, String> {
    let mut info = Info::default();

    let cbor = serde_cbor::from_slice(bytes).unwrap();
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
