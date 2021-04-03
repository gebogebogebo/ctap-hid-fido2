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
    sub_command_params: Vec<u8>,
) -> Vec<u8> {

    let mut map = BTreeMap::new();
    
    // subCommand(0x01)
    {
        let sub_cmd = Value::Integer(sub_command as i128);
        map.insert(Value::Integer(0x01), sub_cmd);
    }

    // subCommandParams (0x02): Map containing following parameters
    let mut sub_command_params_cbor = Vec::new();
    if sub_command == SubCommand::EnumerateCredentialsBegin || sub_command == SubCommand::EnumerateCredentialsGetNextCredential{
        // rpIDHash (0x01): RPID SHA-256 hash.
        let mut param = BTreeMap::new();
        param.insert(Value::Integer(0x01), Value::Bytes(sub_command_params.to_vec()));
        let val = Value::Map(param);
        map.insert(Value::Integer(0x02), val.clone());

        sub_command_params_cbor = to_vec(&val).unwrap();
    } else if sub_command == SubCommand::DeleteCredential {
        // credentialId (0x02): PublicKeyCredentialDescriptor of the credential to be deleted.
        let mut param = BTreeMap::new();

        //let mut aaa = BTreeMap::new();

        let mut credential_id = BTreeMap::new();
        credential_id.insert(Value::Text("id".to_string()), Value::Bytes(sub_command_params.to_vec()));
        credential_id.insert(Value::Text("type".to_string()), Value::Text("public-key".to_string()));    

        //aaa.insert(Value::Integer(0x07),Value::Bytes(to_vec(&credential_id).unwrap()));
        
        param.insert(Value::Integer(0x02), Value::Map(credential_id));
        //param.insert(Value::Integer(0x02), Value::Bytes(to_vec(&aaa).unwrap()));

        let val = Value::Map(param);
        map.insert(Value::Integer(0x02), val.clone());

        sub_command_params_cbor = to_vec(&val).unwrap();

    }

    // pinProtocol(0x03)
    {
        let pin_protocol = Value::Integer(1);
        map.insert(Value::Integer(0x03), pin_protocol);
    }

    // pinUvAuthParam(0x04)
    {
        // pinUvAuthParam (0x04): authenticate(pinUvAuthToken, getCredsMetadata (0x01)).
        // First 16 bytes of HMAC-SHA-256 of contents using pinUvAuthToken.
        // 
        // pinUvAuthParam (0x04): authenticate(pinUvAuthToken, 
        // enumerateCredentialsBegin (0x04) || subCommandParams).
        let mut message = vec![sub_command as u8];
        message.append(&mut sub_command_params_cbor.to_vec());
        let param_pin_auth = pin_token.authenticate_v2(&message,16);
        //println!("- pin_auth({:02})    = {:?}", pin_auth.len(),util::to_hex_str(&pin_auth));

        //let pin_auth = pin_token.sign(&util::create_clientdata_hash(challenge));
        //println!("- pin_auth({:02})    = {:?}", pin_auth.len(),util::to_hex_str(&pin_auth));
        
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

