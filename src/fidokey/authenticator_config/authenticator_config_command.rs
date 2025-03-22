use super::super::sub_command_base::SubCommandBase;
use crate::{ctapdef, encrypt::enc_hmac_sha_256, pintoken, util::vec_to_btree_map};

use anyhow::Result;
use serde_cbor::{to_vec, Value};
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

pub fn create_payload(pin_token: pintoken::PinToken, sub_command: SubCommand) -> Result<Vec<u8>> {
    // create cbor
    let mut map = Vec::new();

    // 0x01: subCommand
    map.push((
        Value::Integer(0x01),
        Value::Integer(sub_command.id()? as i128),
    ));

    // subCommandParams (0x02): Map containing following parameters
    let mut sub_command_params_cbor = Vec::new();
    if sub_command.has_param() {
        let param = match sub_command.clone() {
            SubCommand::SetMinPinLength(new_min_pin_length) => {
                // 0x01:newMinPINLength
                let param_vec = vec![
                    (Value::Integer(0x01), Value::Integer(new_min_pin_length as i128))
                ];
                let param_btree = vec_to_btree_map(param_vec);
                Some(param_btree)
            }
            SubCommand::SetMinPinLengthRpIds(rpids) => {
                // 0x02:minPinLengthRPIDs
                let param_vec = vec![
                    (Value::Integer(0x02), Value::Array(rpids.iter().cloned().map(Value::Text).collect()))
                ];
                let param_btree = vec_to_btree_map(param_vec);
                Some(param_btree)
            }
            SubCommand::ForceChangePin => {
                // 0x03:ForceChangePin
                let param_vec = vec![(Value::Integer(0x03), Value::Bool(true))];
                let param_btree = vec_to_btree_map(param_vec);
                Some(param_btree)
            }
            _ => None,
        };
        if let Some(param) = param {
            map.push((Value::Integer(0x02), Value::Map(param.clone())));
            sub_command_params_cbor = to_vec(&param)?;
        }
    }

    // 0x03: pinProtocol
    map.push((Value::Integer(0x03), Value::Integer(1)));

    // 0x04: pinUvAuthParam
    let pin_uv_auth_param = {
        // pinUvAuthParam (0x04)
        // - authenticate(pinUvAuthToken, 32×0xff || 0x0d || uint8(subCommand) || subCommandParams).
        // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorConfig
        let mut message = vec![0xff; 32];
        message.append(&mut vec![0x0d]);
        message.append(&mut vec![sub_command.id()?]);
        message.append(&mut sub_command_params_cbor);

        let sig = enc_hmac_sha_256::authenticate(&pin_token.key, &message);
        sig[0..16].to_vec()
    };
    map.push((
        Value::Integer(0x04),
        Value::Bytes(pin_uv_auth_param.to_vec()),
    ));

    // CBOR
    let cbor = Value::Map(vec_to_btree_map(map));
    let mut payload = [ctapdef::AUTHENTICATOR_CONFIG].to_vec();
    payload.append(&mut to_vec(&cbor)?);
    Ok(payload)
}
