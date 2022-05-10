use super::super::sub_command_base::SubCommandBase;
use crate::{ctapdef, encrypt::enc_hmac_sha_256, pintoken};
use crate::public_key_credential_descriptor::PublicKeyCredentialDescriptor;
use crate::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use anyhow::Result;
use serde_cbor::{to_vec, Value};
use std::collections::BTreeMap;
use strum_macros::EnumProperty;

#[derive(Debug, Copy, Clone, PartialEq, EnumProperty)]
pub enum SubCommand {
    #[strum(props(SubCommandId = "1"))]
    GetCredsMetadata,
    #[strum(props(SubCommandId = "2"))]
    EnumerateRPsBegin,
    #[strum(props(SubCommandId = "3"))]
    EnumerateRPsGetNextRp,
    #[strum(props(SubCommandId = "4"))]
    EnumerateCredentialsBegin,
    #[strum(props(SubCommandId = "5"))]
    EnumerateCredentialsGetNextCredential,
    #[strum(props(SubCommandId = "6"))]
    DeleteCredential,
    #[strum(props(SubCommandId = "7"))]
    UpdateUserInformation,
}
impl SubCommandBase for SubCommand {
    fn has_param(&self) -> bool {
        matches!(
            self,
            SubCommand::EnumerateCredentialsBegin
            | SubCommand::EnumerateCredentialsGetNextCredential
            | SubCommand::DeleteCredential
            | SubCommand::UpdateUserInformation
            )
    }
}

pub fn create_payload(
    pin_token: Option<pintoken::PinToken>,
    sub_command: SubCommand,
    rpid_hash: Option<Vec<u8>>,
    pkcd: Option<PublicKeyCredentialDescriptor>,
    pkcue: Option<PublicKeyCredentialUserEntity>,
    use_pre_credential_management: bool,
) -> Result<Vec<u8>> {
    let mut map = BTreeMap::new();

    // subCommand(0x01)
    {
        let sub_cmd = Value::Integer(sub_command.id()? as i128);
        map.insert(Value::Integer(0x01), sub_cmd);
    }

    // subCommandParams (0x02): Map containing following parameters
    let mut sub_command_params_cbor = Vec::new();
    if sub_command.has_param() {
        let value = match sub_command {
            SubCommand::EnumerateCredentialsBegin
            | SubCommand::EnumerateCredentialsGetNextCredential => {
                // rpIDHash (0x01): RPID SHA-256 hash.
                let param = create_rpid_hash(rpid_hash.unwrap());
                map.insert(Value::Integer(0x02), param.clone());
                Some(param)
            }
            SubCommand::DeleteCredential | SubCommand::UpdateUserInformation => {
                let param = if sub_command == SubCommand::UpdateUserInformation {
                    create_public_key_credential_descriptor_pend(pkcd.unwrap(), pkcue.unwrap())
                } else {
                    // credentialId (0x02): PublicKeyCredentialDescriptor of the credential to be deleted or updated.
                    create_public_key_credential_descriptor(pkcd.unwrap())
                };

                map.insert(Value::Integer(0x02), param.clone());
                Some(param)
            }
            _ => (None),
        };
        if let Some(v) = value {
            sub_command_params_cbor = to_vec(&v)?;
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
        let mut message = vec![sub_command.id()?];
        message.append(&mut sub_command_params_cbor.to_vec());

        let sig = enc_hmac_sha_256::authenticate(&pin_token.key, &message);
        let pin_uv_auth_param = sig[0..16].to_vec();

        map.insert(Value::Integer(0x04), Value::Bytes(pin_uv_auth_param));
    }

    // create cbor
    let cbor = Value::Map(map);

    // create payload
    let mut payload = if use_pre_credential_management {
        [ctapdef::AUTHENTICATOR_CREDENTIAL_MANAGEMENT_P].to_vec()
    } else {
        [ctapdef::AUTHENTICATOR_CREDENTIAL_MANAGEMENT].to_vec()
    };

    payload.append(&mut to_vec(&cbor)?);
    Ok(payload)
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
