use crate::ctapdef;
use serde_cbor::to_vec;
use serde_cbor::Value;
use std::collections::BTreeMap;

#[allow(dead_code)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum SubCommand {
    GetCredsMetadata = 0x01,
    EnumerateRPsBegin = 0x02,
    EnumerateRPsGetNextRP = 0x03,
    EnumerateCredentialsBegin = 0x04,
    EnumerateCredentialsGetNextCredential = 0x05,
    DeleteCredential = 0x06,
    UpdateUserInformation = 0x07,
}

pub fn create_payload(
    param_pin_auth: Vec<u8>,
    sub_command: SubCommand,
) -> Vec<u8> {

    let mut map = BTreeMap::new();
    
    // subCommand(0x01)
    {
        let sub_cmd = Value::Integer(sub_command as i128);
        map.insert(Value::Integer(0x01), sub_cmd);
    }

    // subCommandParams(0x02)
    if sub_command == SubCommand::EnumerateCredentialsBegin || sub_command == SubCommand::EnumerateCredentialsGetNextCredential{
        // subCommandParams (0x02): Map containing following parameters
        // rpIDHash (0x01): RPID SHA-256 hash.
    }

    // pinProtocol(0x03)
    {
        let pin_protocol = Value::Integer(1);
        map.insert(Value::Integer(0x03), pin_protocol);
    }

    // pinUvAuthParam(0x04)
    if param_pin_auth.len() > 0 {
        let pin_auth = Value::Bytes(param_pin_auth);
        map.insert(Value::Integer(0x04), pin_auth);
    }

    // create cbor
    let cbor = Value::Map(map);

    // create payload
    let mut payload = [ctapdef::AUTHENTICATOR_CREDENTIAL_MANAGEMENT].to_vec();
    payload.append(&mut to_vec(&cbor).unwrap());
    payload
}

