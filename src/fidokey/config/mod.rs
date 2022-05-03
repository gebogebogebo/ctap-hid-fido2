use crate::{ctapdef, ctaphid, pintoken};

use super::pin::Permission::AuthenticatorConfiguration;
use super::FidoKeyHid;

use crate::encrypt::enc_hmac_sha_256;
use anyhow::{anyhow, Error, Result};
use serde_cbor::to_vec;
use serde_cbor::Value;
use std::collections::BTreeMap;

/// The subcommand for setting configurations on a hardware token.
#[allow(dead_code)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum SubCommand {
    EnableEnterpriseAttestation = 0x01,
    ToggleAlwaysUv = 0x02,
    SetMinPinLength = 0x03,
    VendorPrototype = 0x04,
}

fn create_payload(
    pin_token: pintoken::PinToken,
    sub_command: SubCommand,
    new_min_pin_length: Option<u8>,
) -> Vec<u8> {
    // create cbor
    let mut map = BTreeMap::new();

    // 0x01: subCommand
    map.insert(Value::Integer(0x01), Value::Integer(sub_command as i128));

    // subCommandParams (0x02): Map containing following parameters
    let mut sub_command_params_cbor = Vec::new();
    if need_sub_command_param(sub_command) {
        let value = match sub_command {
            SubCommand::SetMinPinLength => {
                let mut param = BTreeMap::new();
                // 0x01:newMinPINLength
                param.insert(
                    Value::Integer(0x01),
                    Value::Integer(new_min_pin_length.unwrap() as i128),
                );
                map.insert(Value::Integer(0x02), Value::Map(param.clone()));
                Some(param)
            }
            _ => (None),
        };
        if let Some(v) = value {
            sub_command_params_cbor = to_vec(&v).unwrap();
        }
    }

    // 0x03: pinProtocol
    map.insert(Value::Integer(0x03), Value::Integer(1));

    // 0x04: pinUvAuthParam
    let pin_uv_auth_param = {
        // pinUvAuthParam (0x04)
        // - authenticate(pinUvAuthToken, 32×0xff || 0x0d || uint8(subCommand) || subCommandParams).
        // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorConfig
        let mut message = vec![0xff; 32];
        message.append(&mut vec![0x0d]);
        message.append(&mut vec![sub_command as u8]);
        message.append(&mut sub_command_params_cbor);

        let sig = enc_hmac_sha_256::authenticate(&pin_token.key, &message);
        let pin_auth = sig[0..16].to_vec();
        pin_auth
    };
    map.insert(
        Value::Integer(0x04),
        Value::Bytes(pin_uv_auth_param.to_vec()),
    );

    // CBOR
    let cbor = Value::Map(map);
    let mut payload = [ctapdef::AUTHENTICATOR_CONFIG].to_vec();
    payload.append(&mut to_vec(&cbor).unwrap());
    payload
}

fn need_sub_command_param(sub_command: SubCommand) -> bool {
    sub_command == SubCommand::SetMinPinLength
}

impl FidoKeyHid {
    /// Get Config (CTAP 2.1)
    pub fn toggle_always_uv(&self, pin: Option<&str>) -> Result<String> {
        self.config(pin, SubCommand::ToggleAlwaysUv, None)
    }

    pub fn set_min_pin_length(&self, new_min_pin_length: u8, pin: Option<&str>) -> Result<String> {
        self.config(pin, SubCommand::SetMinPinLength, Some(new_min_pin_length))
    }

    fn config(
        &self,
        pin: Option<&str>,
        sub_command: SubCommand,
        new_min_pin_length: Option<u8>,
    ) -> Result<String> {
        let pin = if let Some(v) = pin {
            v
        } else {
            return Err(anyhow!("need PIN."));
        };

        let cid = ctaphid::ctaphid_init(self).map_err(Error::msg)?;

        // get pintoken
        let pin_token =
            self.get_pinuv_auth_token_with_permission(&cid, pin, AuthenticatorConfiguration)?;

        let send_payload = create_payload(pin_token, sub_command, new_min_pin_length);
        let _response_cbor =
            ctaphid::ctaphid_cbor(self, &cid, &send_payload).map_err(Error::msg)?;
        Ok("".to_string())
    }
}
