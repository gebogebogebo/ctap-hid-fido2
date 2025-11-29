use anyhow::Result;
use ciborium::value::Value;

/// Common payload creation function
///
/// # Arguments
///
/// * `map` - Vector of key-value pairs used as a CBOR map
/// * `command` - Command byte to prepend
///
/// # Returns
///
/// Byte sequence of serialized payload
pub fn to_payload(map: Vec<(Value, Value)>, command: u8) -> Result<Vec<u8>> {
    let cbor = Value::Map(map);
    let mut payload = [command].to_vec();
    let mut serialized = Vec::new();
    ciborium::ser::into_writer(&cbor, &mut serialized)?;
    payload.append(&mut serialized);
    Ok(payload)
}
