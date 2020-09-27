use crate::util;
use num::NumCast;
use serde_cbor::Value;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct CoseKey {
    pub key_type: u16,
    pub algorithm: i32,
    pub parameters: HashMap<i16, Value>,
}

impl CoseKey {
    #[allow(dead_code)]
    pub fn print(self: &CoseKey, title: &str) {
        println!("{}", title);
        println!("- kty       = {:?}", self.key_type);
        println!("- alg       = {:?}", self.algorithm);
        if let Some(Value::Integer(intval)) = self.parameters.get(&-1) {
            println!("- crv       = {:?}", intval);
        }
        if let Some(Value::Bytes(bytes)) = self.parameters.get(&-2) {
            println!(
                "- x({:02})     = {:?}",
                bytes.len(),
                util::to_hex_str(bytes)
            );
        }
        if let Some(Value::Bytes(bytes)) = self.parameters.get(&-3) {
            println!(
                "- y({:02})     = {:?}",
                bytes.len(),
                util::to_hex_str(bytes)
            );
        }
    }

    pub fn decode(cbor: &Value) -> Result<Self, String> {
        let mut cose = CoseKey::default();

        if let Value::Map(xs) = cbor {
            for (key, val) in xs {
                // debug
                //util::cbor_value_print(val);

                if let Value::Integer(member) = key {
                    match member {
                        1 => cose.key_type = util::cbor_cast_value(val).unwrap(),
                        3 => cose.algorithm = util::cbor_cast_value(val).unwrap(),
                        -1 => {
                            //println!("member = {:?} , val = {:?}",member,val);
                            cose.parameters.insert(
                                NumCast::from(*member).unwrap(),
                                Value::Integer(util::cbor_cast_value(val).unwrap()),
                            );
                        }
                        -2 | -3 => {
                            //println!("member = {:?} , val = {:?}",member,val);
                            cose.parameters.insert(
                                NumCast::from(*member).unwrap(),
                                Value::Bytes(util::cbor_value_to_vec_u8(val).unwrap()),
                            );
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(cose)
    }
}
