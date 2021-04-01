use serde_cbor::to_vec;
use serde_cbor::Value;
use std::collections::BTreeMap;
use crate::ctapdef;
use crate::pintoken;

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
    pin_token: pintoken::PinToken,
    sub_command: SubCommand,
) -> Vec<u8> {

    // pinUvAuthParam (0x04): authenticate(pinUvAuthToken, getCredsMetadata (0x01)).
    // First 16 bytes of HMAC-SHA-256 of contents using pinUvAuthToken.
    // 
    // pinUvAuthParam (0x04): authenticate(pinUvAuthToken, 
    // enumerateCredentialsBegin (0x04) || subCommandParams).
    let param_pin_auth = pin_token.authenticate_v2(&vec![sub_command as u8],16);
    //println!("- pin_auth({:02})    = {:?}", pin_auth.len(),util::to_hex_str(&pin_auth));

    //let pin_auth = pin_token.sign(&util::create_clientdata_hash(challenge));
    //println!("- pin_auth({:02})    = {:?}", pin_auth.len(),util::to_hex_str(&pin_auth));

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

