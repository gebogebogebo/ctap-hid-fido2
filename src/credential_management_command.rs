use crate::ctapdef;
use serde_cbor::to_vec;
use serde_cbor::Value;
use std::collections::BTreeMap;

#[allow(dead_code)]
pub enum SubCommand {
    GetCredsMetadata = 0x01,
    EnumerateRPsBegin = 0x02,
    EnumerateRPsGetNextRP = 0x03,
    EnumerateCredentialsBegin = 0x04,
    EnumerateCredentialsGetNextCredential = 0x05,
    DeleteCredential = 0x06,
    UpdateUserInformation = 0x07,
}

pub fn create_payload_get_creds_metadata(param_pin_auth: Vec<u8>) -> Vec<u8> {
    // subCommand
    let sub_cmd = Value::Integer(SubCommand::GetCredsMetadata as i128);

    // pinProtocol
    let pin_protocol = Value::Integer(1);

    // pinAuth
    let pin_auth = {
        if param_pin_auth.len() > 0 {
            Some(Value::Bytes(param_pin_auth))
        } else {
            None
        }
    };

    // create cbor
    let mut map = BTreeMap::new();
    map.insert(Value::Integer(0x01), sub_cmd);
    if let Some(x) = pin_auth {
        map.insert(Value::Integer(0x03), pin_protocol);
        map.insert(Value::Integer(0x04), x);
    }
    let cbor = Value::Map(map);

    let mut payload = [ctapdef::AUTHENTICATOR_CREDENTIAL_MANAGEMENT].to_vec();
    payload.append(&mut to_vec(&cbor).unwrap());
    payload
}
