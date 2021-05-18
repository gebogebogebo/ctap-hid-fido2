use crate::cose;
use crate::ctapdef;
use serde_cbor::to_vec;
use serde_cbor::Value;
use std::collections::BTreeMap;

#[allow(dead_code)]
pub enum SubCommand {
    GetRetries = 0x01,
    GetKeyAgreement = 0x02,
    SetPin = 0x03,
    ChangePin = 0x04,
    GetPinToken = 0x05,
}

fn create_payload_get_keyagreement() -> Vec<u8> {
    // 0x01 : pinProtocol
    let pin_prot = Value::Integer(1);

    // 0x02 : subCommand
    let sub_cmd = Value::Integer(SubCommand::GetKeyAgreement as i128);

    // create cbor
    let mut map = BTreeMap::new();
    map.insert(Value::Integer(0x01), pin_prot);
    map.insert(Value::Integer(0x02), sub_cmd);
    let cbor = Value::Map(map);

    // Command - authenticatorClientPIN (0x06)
    let mut payload = [ctapdef::AUTHENTICATOR_CLIENT_PIN].to_vec();
    payload.append(&mut to_vec(&cbor).unwrap());
    payload
}

fn create_payload_get_retries() -> Vec<u8> {
    // 0x01 : pinProtocol
    let pin_prot = Value::Integer(1);

    // 0x02 : subCommand
    let sub_cmd = Value::Integer(SubCommand::GetRetries as i128);

    // create cbor
    let mut map = BTreeMap::new();
    map.insert(Value::Integer(0x01), pin_prot);
    map.insert(Value::Integer(0x02), sub_cmd);
    let cbor = Value::Map(map);

    // Command - authenticatorClientPIN (0x06)
    let mut payload = [ctapdef::AUTHENTICATOR_CLIENT_PIN].to_vec();
    payload.append(&mut to_vec(&cbor).unwrap());
    payload
}

pub fn create_payload_get_pin_token(
    key_agreement: &cose::CoseKey,
    pin_hash_enc: Vec<u8>,
) -> Vec<u8> {
    // 0x01 : pinProtocol
    let pin_prot = Value::Integer(1);

    // 0x02 : subCommand
    let sub_cmd = Value::Integer(SubCommand::GetPinToken as i128);

    // 0x03:keyAgreement : COSE_Key
    let mut ka_val = BTreeMap::new();
    ka_val.insert(
        Value::Integer(1),
        Value::Integer(key_agreement.key_type.into()),
    );
    ka_val.insert(
        Value::Integer(3),
        Value::Integer(key_agreement.algorithm.into()),
    );
    if let Value::Integer(ival) = key_agreement.parameters.get(&-1).unwrap() {
        ka_val.insert(Value::Integer(-1), Value::Integer(*ival));
    }
    if let Value::Bytes(bval) = key_agreement.parameters.get(&-2).unwrap() {
        ka_val.insert(Value::Integer(-2), Value::Bytes(bval.to_vec()));
    }
    if let Value::Bytes(bval) = key_agreement.parameters.get(&-3).unwrap() {
        ka_val.insert(Value::Integer(-3), Value::Bytes(bval.to_vec()));
    }
    let ka = Value::Map(ka_val);

    // 0x06:pinHashEnc
    let pin_hash_enc_val = Value::Bytes(pin_hash_enc);

    // create cbor
    let mut map = BTreeMap::new();
    map.insert(Value::Integer(0x01), pin_prot);
    map.insert(Value::Integer(0x02), sub_cmd);
    map.insert(Value::Integer(0x03), ka);
    map.insert(Value::Integer(0x06), pin_hash_enc_val);
    let cbor = Value::Map(map);

    // Command - authenticatorClientPIN (0x06)
    let mut payload = [0x06].to_vec();
    payload.append(&mut to_vec(&cbor).unwrap());
    payload
}

pub fn create_payload(sub_command: SubCommand) -> Result<Vec<u8>, String> {
    match sub_command {
        SubCommand::GetRetries => Ok(create_payload_get_retries()),
        SubCommand::ChangePin => Err(String::from("Not Supported")),
        SubCommand::GetKeyAgreement => Ok(create_payload_get_keyagreement()),
        SubCommand::GetPinToken => Err(String::from("Not Supported")),
        SubCommand::SetPin => Err(String::from("Not Supported")),
    }
}
