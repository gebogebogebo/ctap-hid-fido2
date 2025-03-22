use crate::encrypt::cose::CoseKey;
use crate::util;
use anyhow::{anyhow, Result};
use serde_cbor::Value;
use crate::util_ciborium;

#[derive(Default)]
pub struct Pin {
    pub retries: i32,
    pub uv_retries: i32,
}

pub fn parse_cbor_client_pin_get_pin_token(bytes: &[u8]) -> Result<Vec<u8>> {
    let map = util_ciborium::cbor_bytes_to_map(bytes)?;
    for (key, val) in &map {
        if !util_ciborium::is_integer(key) {
            continue;
        }
        match util_ciborium::integer_to_i64(key)? {
            0x02 => {
                return Ok(util_ciborium::cbor_value_to_vec_u8(val)?);
            },
            _ => println!("parse_cbor_member - unknown info {:?}", val),
        }
    }
    Err(anyhow!("parse_cbor_client_pin_get_pin_token error"))
}

pub fn parse_cbor_client_pin_get_keyagreement(bytes: &[u8]) -> Result<CoseKey> {
    let cbor: Value = serde_cbor::from_slice(bytes)?;

    if let Value::Map(n) = cbor {
        // 最初の要素を取得
        let (key, val) = n.iter().next().unwrap();
        if let Value::Integer(member) = key {
            if *member == 1 {
                return Ok(CoseKey::new(val).unwrap());
            }
        }
    }
    Err(anyhow!("parse_cbor_client_pin_get_keyagreement error"))
}

pub fn parse_cbor_client_pin_get_retries(bytes: &[u8]) -> Result<Pin> {
    // deserialize to a serde_cbor::Value
    let cbor: Value = serde_cbor::from_slice(bytes)?;

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
        Err(anyhow!("parse_cbor_client_pin_get_retries error"))
    }
}
