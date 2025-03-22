use anyhow::{anyhow, Result};
use std::io::Cursor;
use ciborium::value::Value;
use num::NumCast;

#[allow(dead_code)]
pub(crate) fn cbor_bytes_to_map(bytes: &[u8]) -> Result<Vec<(Value, Value)>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }

    match ciborium::de::from_reader(Cursor::new(bytes)) {
        Ok(value) => {
            if let Value::Map(map_entries) = value {
                Ok(map_entries)
            } else {
                Err(anyhow!("ciborium parse error: Value is not a Map"))
            }
        },
        Err(_) => Err(anyhow!("ciborium parse error")),
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

#[allow(dead_code)]
pub(crate) fn cbor_value_to_num<T: NumCast>(value: &Value) -> Result<T> {
    if let Value::Integer(_) = value {
        let ival = integer_to_i64(value)?;
        Ok(NumCast::from(ival).ok_or_else(|| anyhow!("Error casting i64 to target type"))?)
    } else {
        Err(anyhow!("Cast Error: Value is not an Integer."))
    }
}

#[allow(dead_code)]
pub(crate) fn cbor_value_to_bool(value: &Value) -> Result<bool> {
    if let Value::Bool(b) = value {
        Ok(*b)
    } else {
        Err(anyhow!("Cast Error: Value is not a Bool."))
    }
}

#[allow(dead_code)]
pub(crate) fn cbor_value_to_vec_u8(value: &Value) -> Result<Vec<u8>> {
    if let Value::Bytes(bytes) = value {
        Ok(bytes.clone())
    } else {
        Err(anyhow!("Cast Error: Value is not Bytes."))
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

#[allow(dead_code)]
pub(crate) fn is_integer(value: &Value) -> bool {
    matches!(value, Value::Integer(_))
}

pub(crate) fn is_text(value: &Value) -> bool {
    matches!(value, Value::Text(_))
}

#[allow(dead_code)]
pub(crate) fn is_map(value: &Value) -> bool {
    matches!(value, Value::Map(_))
}

#[allow(dead_code)]
pub(crate) fn is_array(value: &Value) -> bool {
    matches!(value, Value::Array(_))
}

#[allow(dead_code)]
pub(crate) fn integer_to_i64(value: &Value) -> Result<i64> {
    if let Value::Integer(n) = value {
        i64::try_from(*n).map_err(|_| anyhow!("Integer value too large for i64"))
    } else {
        Err(anyhow!("Value is not an Integer"))
    }
}

#[allow(dead_code)]
pub(crate) fn extract_map_ref(value: &Value) -> Result<&Vec<(Value, Value)>> {
    if let Value::Map(map) = value {
        Ok(map)
    } else {
        Err(anyhow!("Value is not a Map"))
    }
}

#[allow(dead_code)]
pub(crate) fn extract_array_ref(value: &Value) -> Result<&Vec<Value>> {
    if let Value::Array(array) = value {
        Ok(array)
    } else {
        Err(anyhow!("Value is not an Array"))
    }
}
