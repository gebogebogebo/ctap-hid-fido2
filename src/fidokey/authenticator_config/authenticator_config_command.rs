use super::super::sub_command_base::SubCommandBase;
use crate::util_ciborium::ToValue;
use crate::{ctapdef, encrypt::enc_hmac_sha_256, fidokey::common, pintoken};

use anyhow::Result;
use ciborium::value::Value;
use strum_macros::EnumProperty;

#[derive(Debug, Clone, PartialEq, EnumProperty)]
pub enum SubCommand {
    #[strum(props(SubCommandId = "2"))]
    ToggleAlwaysUv,
    #[strum(props(SubCommandId = "3"))]
    SetMinPinLength(u8),
    #[strum(props(SubCommandId = "3"))]
    SetMinPinLengthRpIds(Vec<String>),
    #[strum(props(SubCommandId = "3"))]
    ForceChangePin,
}

impl SubCommandBase for SubCommand {
    fn has_param(&self) -> bool {
        matches!(
            self,
            SubCommand::SetMinPinLength(_)
                | SubCommand::SetMinPinLengthRpIds(_)
                | SubCommand::ForceChangePin
        )
    }
}

pub fn create_payload(
    pin_token: pintoken::PinToken,
    sub_command: SubCommand,
    pin_protocol_version: u8,
) -> Result<Vec<u8>> {
    // 0x01: subCommand
    let sub_cmd_id = sub_command.id()? as i32;

    // 0x02: subCommandParams (only if needed)
    let sub_command_params = create_sub_command_params(&sub_command)?;

    // 0x04: pinUvAuthParam
    let pin_uv_auth_param =
        create_pin_uv_auth_param(&pin_token, &sub_command, &sub_command_params.1)?;

    // Create CBOR map
    let mut auth_config = vec![
        (0x01.to_value(), sub_cmd_id.to_value()),
        (0x03.to_value(), pin_protocol_version.to_value()),
        (0x04.to_value(), pin_uv_auth_param.to_value()),
    ];

    // Add subcommand parameters only if available
    if let Some(param_map) = sub_command_params.0 {
        auth_config.push((0x02.to_value(), param_map));
    }

    // Generate payload
    common::to_payload(auth_config, ctapdef::AUTHENTICATOR_CONFIG)
}

/// Generate subcommand parameters
///
/// Returns: (Optional CBOR map value, serialized byte array)
fn create_sub_command_params(sub_command: &SubCommand) -> Result<(Option<Value>, Vec<u8>)> {
    if !sub_command.has_param() {
        return Ok((None, Vec::new()));
    }

    let param_vec = match sub_command {
        SubCommand::SetMinPinLength(new_min_pin_length) => {
            // 0x01:newMinPINLength
            vec![(0x01.to_value(), new_min_pin_length.to_value())]
        }
        SubCommand::SetMinPinLengthRpIds(rpids) => {
            // 0x02:minPinLengthRPIDs
            let rpids_values: Vec<Value> = rpids.iter().map(|id| id.to_value()).collect();
            vec![(0x02.to_value(), rpids_values.to_value())]
        }
        SubCommand::ForceChangePin => {
            // 0x03:ForceChangePin
            vec![(0x03.to_value(), true.to_value())]
        }
        _ => vec![],
    };

    if param_vec.is_empty() {
        return Ok((None, Vec::new()));
    }

    let param_map = param_vec.to_value();

    // Serialize to get byte array
    let mut cbor_data = Vec::new();
    ciborium::ser::into_writer(&param_map, &mut cbor_data)?;

    Ok((Some(param_map), cbor_data))
}

/// Create PIN/UV authentication parameters from PIN token and authentication parameters
fn create_pin_uv_auth_param(
    pin_token: &pintoken::PinToken,
    sub_command: &SubCommand,
    sub_command_params_cbor: &[u8],
) -> Result<Vec<u8>> {
    // pinUvAuthParam (0x04)
    // - authenticate(pinUvAuthToken, 32×0xff || 0x0d || uint8(subCommand) || subCommandParams).
    // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorConfig
    let mut message = vec![0xff; 32];
    message.append(&mut vec![0x0d]);
    message.append(&mut vec![sub_command.id()?]);
    message.append(&mut sub_command_params_cbor.to_vec());

    let sig = enc_hmac_sha_256::authenticate(&pin_token.key, &message);
    Ok(sig[0..16].to_vec())
}
