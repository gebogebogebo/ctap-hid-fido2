use crate::util;
use num::NumCast;
use serde_cbor::Value;

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
        println!("- pin_uv_auth_protocols = {:?}", self.pin_uv_auth_protocols);
        println!("- max_credential_count_in_list = {:?}", self.max_credential_count_in_list);
        println!("- max_credential_id_length = {:?}", self.max_credential_id_length);
        println!("- algorithms    = {:?}", self.algorithms);

        println!("");
    }
}

fn parse_cbor_member(member: i128, val: &Value, info: &mut Info) {

    match member {
        0x01 => info.versions = util::cbor_value_to_vec_string(val).unwrap(),
        0x02 => info.extensions = util::cbor_value_to_vec_string(val).unwrap(),
        0x03 => info.aaguid = util::cbor_value_to_vec_u8(val).unwrap(),
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
        0x05 => info.max_msg_size = util::cbor_cast_value(val).unwrap(),
        0x06 => {
            if let Value::Array(xs) = val {
                for x in xs {
                    if let Value::Integer(v) = x {
                        info.pin_uv_auth_protocols.push(NumCast::from(*v).unwrap());
                    }
                }
            }
        }
        0x07 => info.max_credential_count_in_list = util::cbor_cast_value(val).unwrap(),
        0x08 => info.max_credential_id_length = util::cbor_cast_value(val).unwrap(),
        0x09 => info.transports = util::cbor_value_to_vec_string(val).unwrap(),
        0x0A => {
            if let Value::Array(xs) = val {
                for x in xs {
                    if let Value::Map(n) = x {
                        for (key, val) in n {

                            let setkey = {
                                if let Value::Text(keystr) = key {
                                    keystr.to_string()
                                } else{
                                    "".to_string()
                                }
                            };
                            
                            let setval = {
                                if let Value::Text(valstr) = val {
                                    valstr.to_string()
                                }else if let Value::Integer(valint) = val {
                                    valint.to_string()
                                }else{
                                    "".to_string()
                                }
                            };

                            info.algorithms.push((setkey,setval));
                        }
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
