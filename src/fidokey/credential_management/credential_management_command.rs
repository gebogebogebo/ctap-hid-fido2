use super::super::sub_command_base::SubCommandBase;
use crate::public_key_credential_descriptor::PublicKeyCredentialDescriptor;
use crate::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use crate::{ctapdef, encrypt::enc_hmac_sha_256, pintoken};
use anyhow::Result;
use serde_cbor::{to_vec, Value};
use std::collections::BTreeMap;
use strum_macros::EnumProperty;

fn vec_to_btree_map(vec: Vec<(Value, Value)>) -> BTreeMap<Value, Value> {
    let mut map = BTreeMap::new();
    for (key, value) in vec {
        map.insert(key, value);
    }
    map
}

#[derive(Debug, Clone, PartialEq, EnumProperty)]
pub enum SubCommand {
    #[strum(props(SubCommandId = "1"))]
    GetCredsMetadata,
    #[strum(props(SubCommandId = "2"))]
    EnumerateRPsBegin,
    #[strum(props(SubCommandId = "3"))]
    EnumerateRPsGetNextRp,
    #[strum(props(SubCommandId = "4"))]
    EnumerateCredentialsBegin(Vec<u8>),
    #[strum(props(SubCommandId = "5"))]
    EnumerateCredentialsGetNextCredential(Vec<u8>),
    #[strum(props(SubCommandId = "6"))]
    DeleteCredential(PublicKeyCredentialDescriptor),
    #[strum(props(SubCommandId = "7"))]
    UpdateUserInformation(PublicKeyCredentialDescriptor, PublicKeyCredentialUserEntity),
}
impl SubCommandBase for SubCommand {
    fn has_param(&self) -> bool {
        matches!(
            self,
            SubCommand::EnumerateCredentialsBegin(_)
                | SubCommand::EnumerateCredentialsGetNextCredential(_)
                | SubCommand::DeleteCredential(_)
                | SubCommand::UpdateUserInformation(_, _)
        )
    }
}

pub fn create_payload(
    pin_token: Option<pintoken::PinToken>,
    sub_command: SubCommand,
    use_pre_credential_management: bool,
) -> Result<Vec<u8>> {
    let mut map = Vec::new();

    // subCommand(0x01)
    {
        let sub_cmd = Value::Integer(sub_command.id()? as i128);
        map.push((Value::Integer(0x01), sub_cmd));
    }

    // subCommandParams (0x02): Map containing following parameters
    let mut sub_command_params_cbor = Vec::new();
    if sub_command.has_param() {
        let param = match sub_command {
            SubCommand::EnumerateCredentialsBegin(ref rpid_hash)
            | SubCommand::EnumerateCredentialsGetNextCredential(ref rpid_hash) => {
                // rpIDHash (0x01): RPID SHA-256 hash.
                Some(create_rpid_hash(rpid_hash))
            }
            SubCommand::UpdateUserInformation(ref pkcd, ref pkcue) => {
                Some(create_public_key_credential_descriptor_pend(pkcd, pkcue))
            }
            SubCommand::DeleteCredential(ref pkcd) => {
                // credentialId (0x02): PublicKeyCredentialDescriptor of the credential to be deleted or updated.
                Some(create_public_key_credential_descriptor(pkcd))
            }
            _ => None,
        };
        if let Some(param) = param {
            map.push((Value::Integer(0x02), param.clone()));
            sub_command_params_cbor = to_vec(&param)?;
        }
    }

    if let Some(pin_token) = pin_token {
        // pinProtocol(0x03)
        let pin_protocol = Value::Integer(1);
        map.push((Value::Integer(0x03), pin_protocol));

        // pinUvAuthParam (0x04):
        // - authenticate(pinUvAuthToken, getCredsMetadata (0x01)).
        // - authenticate(pinUvAuthToken, enumerateCredentialsBegin (0x04) || subCommandParams).
        // -- First 16 bytes of HMAC-SHA-256 of contents using pinUvAuthToken.
        let mut message = vec![sub_command.id()?];
        message.append(&mut sub_command_params_cbor.to_vec());

        let sig = enc_hmac_sha_256::authenticate(&pin_token.key, &message);
        let pin_uv_auth_param = sig[0..16].to_vec();

        map.push((Value::Integer(0x04), Value::Bytes(pin_uv_auth_param)));
    }

    // create cbor
    let btree_map = vec_to_btree_map(map);
    let cbor = Value::Map(btree_map);

    // create payload
    let mut payload = if use_pre_credential_management {
        [ctapdef::AUTHENTICATOR_CREDENTIAL_MANAGEMENT_P].to_vec()
    } else {
        [ctapdef::AUTHENTICATOR_CREDENTIAL_MANAGEMENT].to_vec()
    };

    payload.append(&mut to_vec(&cbor)?);
    Ok(payload)
}

fn create_rpid_hash(rpid_hash: &[u8]) -> Value {
    let mut param = Vec::new();
    param.push((Value::Integer(0x01), Value::Bytes(rpid_hash.to_vec())));
    let btree_param = vec_to_btree_map(param);
    Value::Map(btree_param)
}

fn create_public_key_credential_descriptor(in_param: &PublicKeyCredentialDescriptor) -> Value {
    let mut map = Vec::new();
    map.push((
        Value::Text("id".to_string()),
        Value::Bytes(in_param.id.clone()),
    ));
    map.push((
        Value::Text("type".to_string()),
        Value::Text(in_param.ctype.clone()),
    ));

    let mut param = Vec::new();
    let btree_map = vec_to_btree_map(map);
    param.push((Value::Integer(0x02), Value::Map(btree_map)));
    let btree_param = vec_to_btree_map(param);
    Value::Map(btree_param)
}

fn create_public_key_credential_descriptor_pend(
    in_param: &PublicKeyCredentialDescriptor,
    pkcue: &PublicKeyCredentialUserEntity,
) -> Value {
    let mut param = Vec::new();
    {
        let mut map = Vec::new();
        map.push((
            Value::Text("id".to_string()),
            Value::Bytes(in_param.id.clone()),
        ));
        map.push((
            Value::Text("type".to_string()),
            Value::Text(in_param.ctype.clone()),
        ));
        let btree_map = vec_to_btree_map(map);
        param.push((Value::Integer(0x02), Value::Map(btree_map)));
    }

    {
        let mut user = Vec::new();
        user.push((
            Value::Text("id".to_string()),
            Value::Bytes(pkcue.id.clone()),
        ));
        user.push((
            Value::Text("name".to_string()),
            Value::Text(pkcue.name.to_string()),
        ));
        user.push((
            Value::Text("displayName".to_string()),
            Value::Text(pkcue.display_name.to_string()),
        ));
        let btree_user = vec_to_btree_map(user);
        param.push((Value::Integer(0x03), Value::Map(btree_user)));
    }

    let btree_param = vec_to_btree_map(param);
    Value::Map(btree_param)
}
