use crate::cose::CoseKey;
use crate::util;
use serde_cbor::Value;

#[derive(Default)]
pub struct Pin {
    pub retries: i32,
    pub uv_retries: i32,
}

pub fn parse_cbor_client_pin_get_pin_token(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let cbor: Value = serde_cbor::from_slice(bytes).unwrap();

    if let Value::Map(n) = cbor {
        // 最初の要素を取得
        let (key, val) = n.iter().next().unwrap();
        if let Value::Integer(member) = key {
            if *member == 2 {
                return Ok(util::cbor_value_to_vec_u8(val).unwrap());
            }
        }
    }
    Err("parse_cbor_client_pin_get_pin_token error".into())
}

pub fn parse_cbor_client_pin_get_keyagreement(bytes: &[u8]) -> Result<CoseKey, String> {
    let cbor: Value = serde_cbor::from_slice(bytes).unwrap();

    if let Value::Map(n) = cbor {
        // 最初の要素を取得
        let (key, val) = n.iter().next().unwrap();
        if let Value::Integer(member) = key {
            if *member == 1 {
                return Ok(CoseKey::new(val).unwrap());
            }
        }
    }
    Err("parse_cbor_client_pin_get_keyagreement error".into())
}

pub fn parse_cbor_client_pin_get_retries(bytes: &[u8]) -> Result<Pin, String> {
    // deserialize to a serde_cbor::Value
    let cbor: Value = serde_cbor::from_slice(bytes).unwrap();

    let mut pin = Pin::default();

    if let Value::Map(n) = cbor {
        for (key, val) in &n {
            if let Value::Integer(member) = key {
                match member {
                    3 => pin.retries = util::cbor_value_to_num(val)?,
                    5 => pin.uv_retries = util::cbor_value_to_num(val)?,
                    _ => println!("- anything error"),
                }
            }
        }
        Ok(pin)
    } else {
        Err("parse_cbor_client_pin_get_retries error".into())
    }
}
