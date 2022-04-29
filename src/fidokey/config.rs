use crate::{ctapdef, ctaphid};

use super::FidoKeyHid;

use anyhow::{Error, Result};
use serde_cbor::to_vec;
use serde_cbor::Value;
use std::collections::BTreeMap;
use crate::encrypt::enc_hmac_sha_256;

/// The subcommand for setting configurations on a hardware token.
#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
pub enum SubCommand {
    EnableEnterpriseAttestation = 0x01,
    ToggleAlwaysUv = 0x02,
    SetMinPinLength = 0x03,
    VendorPrototype = 0x04,
}

fn create_payload(sub_command: SubCommand,pin_auth: &[u8]) -> Vec<u8> {

    // create cbor
    let mut map = BTreeMap::new();

    // 0x01: subCommand
    map.insert(Value::Integer(0x01), Value::Integer(sub_command as i128));

    // 0x03: pinProtocol
    map.insert(Value::Integer(0x03), Value::Integer(1));

    // 0x04: pinUvAuthParam
    map.insert(Value::Integer(0x04), Value::Bytes(pin_auth.to_vec()));

    let cbor = Value::Map(map);

    let mut payload = [ctapdef::AUTHENTICATOR_CONFIG].to_vec();
    payload.append(&mut to_vec(&cbor).unwrap());
    payload
}

impl FidoKeyHid {

    /// Get Config (CTAP 2.1)
    pub fn config(&self, pin: Option<&str>) -> Result<String> {
        let cid = ctaphid::ctaphid_init(self).map_err(Error::msg)?;

        // TODO
        let sub_command = SubCommand::ToggleAlwaysUv;

        // get pintoken & create pin auth
        let pin_auth = if let Some(pin) = pin {
            if !pin.is_empty() {
                let pin_token = self.get_pin_token(&cid, pin)?;
                // let pin_token = self.get_pinuv_auth_token_with_permission(cid, pin, super::pin::Permission::Acfg)?;

                // pinUvAuthParam (0x04): the result of calling
                // authenticate(pinUvAuthToken, 32×0xff || 0x0d || uint8(subCommand) || subCommandParams).
                let mut message = vec![0xff; 32];
                message.append(&mut vec![0x0d]);
                message.append(&mut vec![sub_command as u8]);

                let sig = enc_hmac_sha_256::authenticate(&pin_token.key, &message);
                let pin_auth = sig[0..16].to_vec();
                pin_auth
            } else {
                vec![]
            }
        } else {
            vec![]
        };


        let send_payload = create_payload(sub_command, &pin_auth);
        let _response_cbor =
            ctaphid::ctaphid_cbor(self, &cid, &send_payload).map_err(Error::msg)?;
        Ok("".to_string())
    }
}
