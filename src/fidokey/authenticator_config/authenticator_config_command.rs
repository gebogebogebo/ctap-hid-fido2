use super::super::sub_command_base::SubCommandBase;
use crate::{ctapdef, encrypt::enc_hmac_sha_256, pintoken, fidokey::common};
use crate::util_ciborium::ToValue;

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

pub fn create_payload(pin_token: pintoken::PinToken, sub_command: SubCommand) -> Result<Vec<u8>> {
    // create cbor
    let mut map = Vec::new();

    // 0x01: subCommand
    let key1: i32 = 1;
    let sub_cmd_id: i32 = sub_command.id()? as i32;
    map.push((key1.to_value(), sub_cmd_id.to_value()));

    // subCommandParams (0x02): Map containing following parameters
    let mut sub_command_params_cbor = Vec::new();
    if sub_command.has_param() {
        let param_vec = match sub_command.clone() {
            SubCommand::SetMinPinLength(new_min_pin_length) => {
                // 0x01:newMinPINLength
                let key1: i32 = 1;
                vec![(key1.to_value(), new_min_pin_length.to_value())]
            }
            SubCommand::SetMinPinLengthRpIds(rpids) => {
                // 0x02:minPinLengthRPIDs
                let key2: i32 = 2;
                // RPIDsの配列を作成
                let rpids_values: Vec<Value> = rpids.iter().map(|id| id.to_value()).collect();
                vec![(key2.to_value(), rpids_values.to_value())]
            }
            SubCommand::ForceChangePin => {
                // 0x03:ForceChangePin
                let key3: i32 = 3;
                vec![(key3.to_value(), true.to_value())]
            }
            _ => vec![],
        };

        if !param_vec.is_empty() {
            let key2: i32 = 2;
            let param_map = param_vec.to_value();
            map.push((key2.to_value(), param_map.clone()));
            
            // シリアライズ
            let mut cbor_data = Vec::new();
            ciborium::ser::into_writer(&param_map, &mut cbor_data)?;
            sub_command_params_cbor = cbor_data;
        }
    }

    // 0x03: pinProtocol
    let key3: i32 = 3;
    let pin_protocol: i32 = 1;
    map.push((key3.to_value(), pin_protocol.to_value()));

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
    
    let key4: i32 = 4;
    map.push((key4.to_value(), pin_uv_auth_param.to_value()));

    // common::to_payload関数を使ってペイロードを生成
    common::to_payload(map, ctapdef::AUTHENTICATOR_CONFIG)
}
