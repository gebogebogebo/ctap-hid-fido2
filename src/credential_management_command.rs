#[allow(unused_imports)]
use crate::util;

use crate::ctapdef;
use crate::pintoken;
use crate::public_key_credential_descriptor::PublicKeyCredentialDescriptor;
use crate::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use serde_cbor::to_vec;
use serde_cbor::Value;
use std::collections::BTreeMap;
use crate::enc_hmac_sha_256;

#[allow(dead_code)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum SubCommand {
    GetCredsMetadata = 0x01,
    EnumerateRPsBegin = 0x02,
    EnumerateRPsGetNextRp = 0x03,
    EnumerateCredentialsBegin = 0x04,
    EnumerateCredentialsGetNextCredential = 0x05,
    DeleteCredential = 0x06,
    UpdateUserInformation = 0x07,
}

/*
fn parse_test(cbor:Value){
    if let Value::Map(n) = cbor {
        for (key, val) in n {
            if let Value::Integer(member) = key {
                match member {
                    0x02 => {
                        if let Value::Map(nn) = val {
                            for (key2, val2) in nn {
                                if let Value::Integer(member2) = key2 {
                                    match member2 {
                                        0x02 => {
                                            let a = 0;
                                        },
                                        0x03 => {
                                            let id = util::cbor_get_bytes_from_map(&val2, "id");
                                            let name = util::cbor_get_string_from_map(&val2,"name");
                                            let dname = util::cbor_get_string_from_map(&val2,"displayName");
                                            let a = 0;
                                        },
                                        _ => (),
                                    }
                                }
                            }
                        }
                    },
                    _ => (),
                }
            }
        }
    }
}
*/

pub fn create_payload(
    pin_token: Option<pintoken::PinToken>,
    sub_command: SubCommand,
    rpid_hash: Option<Vec<u8>>,
    pkcd: Option<PublicKeyCredentialDescriptor>,
    pkcue: Option<PublicKeyCredentialUserEntity>,
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
                let param;
                if sub_command == SubCommand::UpdateUserInformation {
                    param =
                        create_public_key_credential_descriptor_pend(pkcd.unwrap(), pkcue.unwrap());
                } else {
                    // credentialId (0x02): PublicKeyCredentialDescriptor of the credential to be deleted or updated.
                    param = create_public_key_credential_descriptor(pkcd.unwrap());
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

    if let Some(pin_token) = pin_token {
        // pinProtocol(0x03)
        let pin_protocol = Value::Integer(1);
        map.insert(Value::Integer(0x03), pin_protocol);

        // pinUvAuthParam (0x04):
        // - authenticate(pinUvAuthToken, getCredsMetadata (0x01)).
        // - authenticate(pinUvAuthToken, enumerateCredentialsBegin (0x04) || subCommandParams).
        // -- First 16 bytes of HMAC-SHA-256 of contents using pinUvAuthToken.
        let mut message = vec![sub_command as u8];
        message.append(&mut sub_command_params_cbor.to_vec());

        let sig = enc_hmac_sha_256::authenticate(&pin_token.key, &message);
        let pin_uv_auth_param = sig[0..16].to_vec();

        map.insert(Value::Integer(0x04), Value::Bytes(pin_uv_auth_param));
    }

    // create cbor
    let cbor = Value::Map(map);

    //parse_test(cbor.clone());

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

fn create_public_key_credential_descriptor(in_param: PublicKeyCredentialDescriptor) -> Value {
    let mut map = BTreeMap::new();
    map.insert(Value::Text("id".to_string()), Value::Bytes(in_param.id));
    map.insert(Value::Text("type".to_string()), Value::Text(in_param.ctype));

    let mut param = BTreeMap::new();
    param.insert(Value::Integer(0x02), Value::Map(map));
    Value::Map(param)
}

fn create_public_key_credential_descriptor_pend(
    in_param: PublicKeyCredentialDescriptor,
    pkcuee: PublicKeyCredentialUserEntity,
) -> Value {
    let mut param = BTreeMap::new();
    {
        let mut map = BTreeMap::new();
        map.insert(Value::Text("id".to_string()), Value::Bytes(in_param.id));
        map.insert(Value::Text("type".to_string()), Value::Text(in_param.ctype));
        param.insert(Value::Integer(0x02), Value::Map(map));
    }

    {
        let mut user = BTreeMap::new();
        user.insert(Value::Text("id".to_string()), Value::Bytes(pkcuee.id));
        user.insert(Value::Text("name".to_string()), Value::Text(pkcuee.name));
        user.insert(
            Value::Text("displayName".to_string()),
            Value::Text(pkcuee.display_name),
        );
        param.insert(Value::Integer(0x03), Value::Map(user));
    }

    Value::Map(param)
}
