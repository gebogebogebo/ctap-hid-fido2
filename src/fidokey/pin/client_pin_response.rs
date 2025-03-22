use crate::encrypt::cose::CoseKey;
use anyhow::{anyhow, Result};
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
    let map = util_ciborium::cbor_bytes_to_map(bytes)?;
        
    for (key, val) in &map {
        if !util_ciborium::is_integer(key) {
            continue;
        }
        match util_ciborium::integer_to_i64(key)? {
            0x01 => {
                return Ok(CoseKey::new_for_ciborium(val)?);
            },
            _ => println!("parse_cbor_member - unknown info {:?}", val),
        }
    }

    Err(anyhow!("parse_cbor_client_pin_get_keyagreement error"))
}

pub fn parse_cbor_client_pin_get_retries(bytes: &[u8]) -> Result<Pin> {
    let map = util_ciborium::cbor_bytes_to_map(bytes)?;
    let mut pin = Pin::default();

    for (key, val) in &map {
        if !util_ciborium::is_integer(key) {
            continue;
        }
        
        match util_ciborium::integer_to_i64(key)? {
            0x03 => pin.retries = util_ciborium::cbor_value_to_num(val)?,
            0x05 => pin.uv_retries = util_ciborium::cbor_value_to_num(val)?,
            _ => println!("- unknown field in pin retries response"),
        }
    }
    
    Ok(pin)
}
