use anyhow::Result;
use ciborium::value::Value;

/// 共通のペイロード作成関数
/// 
/// # Arguments
///
/// * `map` - CBORマップとして使用するキーと値のペアのベクタ
/// * `command` - 先頭に付加するコマンドバイト
///
/// # Returns
///
/// シリアライズされたペイロードのバイト列
pub fn to_payload(map: Vec<(Value, Value)>, command: u8) -> Result<Vec<u8>> {
    let cbor = Value::Map(map);
    let mut payload = [command].to_vec();
    let mut serialized = Vec::new();
    ciborium::ser::into_writer(&cbor, &mut serialized)?;
    payload.append(&mut serialized);
    Ok(payload)
}
