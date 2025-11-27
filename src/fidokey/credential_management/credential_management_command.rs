use super::super::sub_command_base::SubCommandBase;
use crate::public_key_credential_descriptor::PublicKeyCredentialDescriptor;
use crate::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use crate::util_ciborium::ToValue;
use crate::{ctapdef, encrypt::enc_hmac_sha_256, fidokey::common, pintoken};
use anyhow::Result;
use ciborium::value::Value;
use strum_macros::EnumProperty;

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
    pin_protocol_version: u8,
) -> Result<Vec<u8>> {
    let mut map = Vec::new();

    // subCommand(0x01)
    let sub_cmd_id = sub_command.id()? as i64;
    map.push((0x01.to_value(), sub_cmd_id.to_value()));

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
            map.push((0x02.to_value(), param.clone()));

            // Serialize parameters to CBOR
            ciborium::ser::into_writer(&param, &mut sub_command_params_cbor)?;
        }
    }

    if let Some(pin_token) = pin_token {
        // pinProtocol(0x03)
        map.push((0x03.to_value(), pin_protocol_version.to_value()));

        // pinUvAuthParam (0x04):
        // - authenticate(pinUvAuthToken, getCredsMetadata (0x01)).
        // - authenticate(pinUvAuthToken, enumerateCredentialsBegin (0x04) || subCommandParams).
        // -- First 16 bytes of HMAC-SHA-256 of contents using pinUvAuthToken.
        let mut message = vec![sub_command.id()?];
        message.append(&mut sub_command_params_cbor.to_vec());

        let sig = enc_hmac_sha_256::authenticate(&pin_token.key, &message);
        let pin_uv_auth_param = sig[0..16].to_vec();

        map.push((0x04.to_value(), pin_uv_auth_param.to_value()));
    }

    // Generate command payload
    let command_byte = if use_pre_credential_management {
        ctapdef::AUTHENTICATOR_CREDENTIAL_MANAGEMENT_P
    } else {
        ctapdef::AUTHENTICATOR_CREDENTIAL_MANAGEMENT
    };

    // Use common::to_payload for serialization
    common::to_payload(map, command_byte)
}

fn create_rpid_hash(rpid_hash: &[u8]) -> Value {
    let param = vec![(0x01.to_value(), rpid_hash.to_vec().to_value())];
    param.to_value()
}

fn create_public_key_credential_descriptor(in_param: &PublicKeyCredentialDescriptor) -> Value {
    let map = vec![
        ("id".to_value(), in_param.id.clone().to_value()),
        ("type".to_value(), in_param.ctype.clone().to_value()),
    ];

    let param = vec![(0x02.to_value(), map.to_value())];
    param.to_value()
}

fn create_public_key_credential_descriptor_pend(
    in_param: &PublicKeyCredentialDescriptor,
    pkcue: &PublicKeyCredentialUserEntity,
) -> Value {
    let map = vec![
        ("id".to_value(), in_param.id.clone().to_value()),
        ("type".to_value(), in_param.ctype.clone().to_value()),
    ];

    let user = vec![
        ("id".to_value(), pkcue.id.clone().to_value()),
        ("name".to_value(), pkcue.name.to_string().to_value()),
        (
            "displayName".to_value(),
            pkcue.display_name.to_string().to_value(),
        ),
    ];

    let param = vec![
        (0x02.to_value(), map.to_value()),
        (0x03.to_value(), user.to_value()),
    ];

    param.to_value()
}
