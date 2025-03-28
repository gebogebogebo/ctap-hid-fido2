use anyhow::{anyhow, Result};
use std::io::Cursor;
use ciborium::value::Value;
use num::NumCast;
use std::collections::BTreeMap;

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
pub(crate) fn cbor_value_to_vec_bytes(value: &Value) -> Result<Vec<Vec<u8>>> {
    if let Value::Array(values) = value {
        let mut result = Vec::new();
        for item in values {
            if let Value::Bytes(bytes) = item {
                result.push(bytes.clone());
            } else {
                return Err(anyhow!("Cast Error: Array item is not Bytes"));
            }
        }
        Ok(result)
    } else {
        Err(anyhow!("Cast Error: Value is not an Array"))
    }
}

#[allow(dead_code)]
pub(crate) fn is_integer(value: &Value) -> bool {
    matches!(value, Value::Integer(_))
}

#[allow(dead_code)]
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
pub(crate) fn is_bytes(value: &Value) -> bool {
    matches!(value, Value::Bytes(_))
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
pub(crate) fn cbor_get_bytes_from_map(cbor_map: &Value, get_key: &str) -> Result<Vec<u8>> {
    if let Value::Map(map) = cbor_map {
        for (key, val) in map {
            if let Value::Text(key_text) = key {
                if key_text == get_key {
                    return cbor_value_to_vec_u8(val);
                }
            }
        }
    }
    Ok(Vec::new()) // キーが見つからない場合は空の配列を返す
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

// TODO 最終的には削除する
// serde_cbor::Value を ciborium::value::Value に変換する
#[allow(dead_code)]
pub(crate) fn serde_to_ciborium(serde_value: serde_cbor::Value) -> Result<Value> {
    // serde_cbor::Value を CBOR のバイト列にシリアライズ
    let bytes = serde_cbor::to_vec(&serde_value)?;
    // バイト列から ciborium::value::Value にデシリアライズ
    let cib_value: Value = ciborium::de::from_reader(bytes.as_slice())?;
    Ok(cib_value)
}

// ciborium::value::Value を serde_cbor::Value に変換する
#[allow(dead_code)]
pub fn ciborium_to_serde(cib_value: Value) -> Result<serde_cbor::Value> {
    // ciborium の Value をバイト列にシリアライズ
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&cib_value, &mut bytes)?;
    // シリアライズしたバイト列から serde_cbor の Value にデシリアライズ
    let serde_value: serde_cbor::Value = serde_cbor::from_slice(&bytes)?;
    Ok(serde_value)
}

#[allow(dead_code)]
pub fn ciborium_to_serde_vec(map: Vec<(Value, Value)>) -> Result<Vec<(serde_cbor::Value, serde_cbor::Value)>> {
    let mut result = Vec::new();
    for (key, value) in map {
        let serde_key = ciborium_to_serde(key)?;
        let serde_value = ciborium_to_serde(value)?;
        result.push((serde_key, serde_value));
    }
    Ok(result)
}

#[allow(dead_code)]
pub fn vec_to_btree_map(vec: Vec<(Value, Value)>) -> Result<BTreeMap<serde_cbor::Value, serde_cbor::Value>> {
    let serde_vec = ciborium_to_serde_vec(vec)?;
    Ok(serde_vec.into_iter().collect::<BTreeMap<_, _>>())
}

// TODO 最終的には削除する
