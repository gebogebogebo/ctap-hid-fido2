use crate::str_buf::StrBuf;
use anyhow::{anyhow, Result};
use num::NumCast;
use ring::digest;
use serde_cbor::Value;
use std::collections::BTreeMap;
use base64::{Engine as _, engine::general_purpose};

pub fn to_hex_str(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut acc, n| {
        acc.push_str(&format!("{:02X}", n));
        acc
    })
}

pub fn to_str_hex(hexstr: &str) -> Vec<u8> {
    hex::decode(hexstr).unwrap_or_default()
}

pub fn print_typename<T>(_: T) {
    println!("{}", std::any::type_name::<T>());
}

#[allow(dead_code)]
pub(crate) fn debugp(title: &str, bytes: &[u8]) {
    println!("{}", StrBuf::bufh(title, bytes));
}

// for cbor
pub(crate) fn cbor_get_string_from_map(cbor_map: &Value, get_key: &str) -> Result<String> {
    if let Value::Map(xs) = cbor_map {
        for (key, val) in xs {
            if let Value::Text(s) = key {
                if s == get_key {
                    if let Value::Text(v) = val {
                        return Ok(v.to_string());
                    }
                }
            } else if let Value::Integer(s) = key {
                if s.to_string() == get_key {
                    if let Value::Text(v) = val {
                        return Ok(v.to_string());
                    }
                }
            }
        }
        Ok("".to_string())
    } else {
        Err(anyhow!("Cast Error : Value is not a Map."))
    }
}

pub(crate) fn cbor_get_bytes_from_map(cbor_map: &Value, get_key: &str) -> Result<Vec<u8>> {
    if let Value::Map(xs) = cbor_map {
        for (key, val) in xs {
            if let Value::Text(s) = key {
                if s == get_key {
                    return cbor_value_to_vec_u8(val);
                }
            } else if let Value::Integer(s) = key {
                if s.to_string() == get_key {
                    return cbor_value_to_vec_u8(val);
                }
            }
        }
        Ok(vec![])
    } else {
        Err(anyhow!("Cast Error : Value is not a Map."))
    }
}

pub(crate) fn cbor_value_to_num<T: NumCast>(value: &Value) -> Result<T> {
    if let Value::Integer(x) = value {
        Ok(NumCast::from(*x).ok_or(anyhow!("err"))?)
    } else {
        Err(anyhow!("Cast Error : Value is not a Integer."))
    }
}

#[allow(dead_code)]
pub(crate) fn cbor_value_to_vec_u8(value: &Value) -> Result<Vec<u8>> {
    if let Value::Bytes(xs) = value {
        Ok(xs.to_vec())
    } else {
        Err(anyhow!("Cast Error : Value is not a Bytes."))
    }
}

#[allow(dead_code)]
pub(crate) fn cbor_value_to_str(value: &Value) -> Result<String> {
    if let Value::Text(s) = value {
        Ok(s.to_string())
    } else {
        Err(anyhow!("Cast Error : Value is not a Text."))
    }
}

pub(crate) fn cbor_value_to_bool(value: &Value) -> Result<bool> {
    if let Value::Bool(v) = value {
        Ok(*v)
    } else {
        Err(anyhow!("Cast Error : Value is not a Bool."))
    }
}

#[allow(dead_code)]
pub(crate) fn cbor_value_to_vec_string(value: &Value) -> Result<Vec<String>> {
    if let Value::Array(x) = value {
        let mut strings = [].to_vec();
        for ver in x {
            if let Value::Text(s) = ver {
                strings.push(s.to_string());
            }
        }
        Ok(strings)
    } else {
        Err(anyhow!("Cast Error : Value is not Array."))
    }
}

pub(crate) fn cbor_value_to_vec_bytes(value: &Value) -> Result<Vec<Vec<u8>>> {
    if let Value::Array(xs) = value {
        let mut bytes = [].to_vec();
        for x in xs {
            if let Value::Bytes(b) = x {
                bytes.push(b.to_vec());
            }
        }
        Ok(bytes)
    } else {
        Err(anyhow!("Cast Error : Value is not Array."))
    }
}

pub(crate) fn cbor_bytes_to_map(bytes: &[u8]) -> Result<BTreeMap<Value, Value>> {
    if bytes.is_empty() {
        return Ok(BTreeMap::new());
    }
    match serde_cbor::from_slice(bytes) {
        Ok(cbor) => {
            if let Value::Map(n) = cbor {
                Ok(n)
            } else {
                Err(anyhow!("parse error 2"))
            }
        }
        Err(_) => Err(anyhow!("parse error 1")),
    }
}

#[allow(dead_code)]
pub(crate) fn cbor_value_print(value: &Value) {
    match value {
        Value::Bytes(s) => print_typename(s),
        Value::Text(s) => print_typename(s),
        Value::Integer(s) => print_typename(s),
        Value::Map(s) => print_typename(s),
        Value::Array(s) => print_typename(s),
        _ => println!("unknown Value type"),
    };
}

pub(crate) fn create_clientdata_hash(challenge: Vec<u8>) -> Vec<u8> {
    // sha256
    let hasher = digest::digest(&digest::SHA256, &challenge);
    hasher.as_ref().to_vec()
}

#[allow(dead_code)]
pub(crate) fn convert_to_publickey_pem(public_key_der: &[u8]) -> String {
    let mut tmp = vec![];

    if public_key_der.is_empty() {
        return "".to_string();
    }

    // 0.metadata(26byte)
    let meta_header = hex::decode("3059301306072a8648ce3d020106082a8648ce3d030107034200").unwrap();
    tmp.append(&mut meta_header.to_vec());

    tmp.append(&mut public_key_der.to_vec());

    // 1.encode Base64
    let base64_str = general_purpose::STANDARD_NO_PAD.encode(tmp);

    // 2. /n　every 64 characters
    let pem_base = {
        let mut pem_base = "".to_string();
        let mut counter = 0;
        for c in base64_str.chars() {
            pem_base = pem_base + &c.to_string();
            if counter == 64 - 1 {
                pem_base += "\n";
                counter = 0;
            } else {
                counter += 1;
            }
        }
        pem_base + "\n"
    };

    // 3. Header and footer
    "-----BEGIN PUBLIC KEY-----\n".to_string() + &pem_base + "-----END PUBLIC KEY-----"
}
