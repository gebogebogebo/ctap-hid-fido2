#[allow(unused_imports)]
use crate::util;

use crate::credential_management_params;
use crate::ctapdef;
use crate::pintoken;
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
    pin_token: pintoken::PinToken,
    sub_command: SubCommand,
    rpid_hash: Option<Vec<u8>>,
    pkcd: Option<credential_management_params::PublicKeyCredentialDescriptor>,
    pkcue: Option<credential_management_params::PublicKeyCredentialUserEntity>,
) -> Vec<u8> {
    let mut map = BTreeMap::new();

    // subCommand(0x01)
    {
        let sub_cmd = Value::Integer(sub_command as i128);
        map.insert(Value::Integer(0x01), sub_cmd);
    }

    // subCommandParams (0x02): Map containing following parameters
    let mut sub_command_params_cbor = Vec::new();
    if need_sub_command_param(sub_command) {
        let value = match sub_command {
            SubCommand::EnumerateCredentialsBegin
            | SubCommand::EnumerateCredentialsGetNextCredential => {
                // rpIDHash (0x01): RPID SHA-256 hash.
                let param = create_rpid_hash(rpid_hash.unwrap());
                map.insert(Value::Integer(0x02), param.clone());
                Some(param)
            }
            SubCommand::DeleteCredential | SubCommand::UpdateUserInformation => {
                // credentialId (0x02): PublicKeyCredentialDescriptor of the credential to be deleted or updated.
                let param = create_public_key_credential_descriptor(pkcd.unwrap());

                if sub_command == SubCommand::UpdateUserInformation {
                    // user (0x03)        : a PublicKeyCredentialUserEntity with the updated information.
                    let pkcuee = pkcue.unwrap();
                    let mut user = BTreeMap::new();
                    user.insert(
                        Value::Text("id".to_string()),
                        Value::Bytes(pkcuee.id.to_vec()),
                    );
                    user.insert(
                        Value::Text("name".to_string()),
                        Value::Text(pkcuee.name.to_string()),
                    );
                    user.insert(
                        Value::Text("displayName".to_string()),
                        Value::Text(pkcuee.display_name.to_string()),
                    );
                    //param.insert(Value::Integer(0x03), Value::Map(user));
                }

                map.insert(Value::Integer(0x02), param.clone());
                Some(param)
            }
            _ => (None),
        };
        if let Some(v) = value {
            sub_command_params_cbor = to_vec(&v).unwrap();
        }
    }

    // pinProtocol(0x03)
    {
        let pin_protocol = Value::Integer(1);
        map.insert(Value::Integer(0x03), pin_protocol);
    }

    // pinUvAuthParam(0x04)
    {
        // pinUvAuthParam (0x04): authenticate(pinUvAuthToken, getCredsMetadata (0x01)).
        //                          First 16 bytes of HMAC-SHA-256 of contents using pinUvAuthToken.
        // pinUvAuthParam (0x04): authenticate(pinUvAuthToken,
        //                          enumerateCredentialsBegin (0x04) || subCommandParams).
        let mut message = vec![sub_command as u8];
        message.append(&mut sub_command_params_cbor.to_vec());
        let param_pin_auth = pin_token.authenticate_v2(&message, 16);
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

fn need_sub_command_param(sub_command: SubCommand) -> bool {
    sub_command == SubCommand::EnumerateCredentialsBegin
        || sub_command == SubCommand::EnumerateCredentialsGetNextCredential
        || sub_command == SubCommand::DeleteCredential
        || sub_command == SubCommand::UpdateUserInformation
}

fn create_rpid_hash(rpid_hash: Vec<u8>) -> Value {
    let mut param = BTreeMap::new();
    param.insert(Value::Integer(0x01), Value::Bytes(rpid_hash));
    Value::Map(param)
}

fn create_public_key_credential_descriptor(
    in_param: credential_management_params::PublicKeyCredentialDescriptor,
) -> Value {
    let mut map = BTreeMap::new();
    map.insert(
        Value::Text("id".to_string()),
        Value::Bytes(in_param.credential_id),
    );
    map.insert(
        Value::Text("type".to_string()),
        Value::Text(in_param.credential_type),
    );

    let mut param = BTreeMap::new();
    param.insert(Value::Integer(0x02), Value::Map(map));
    Value::Map(param)
}
