mod authenticator_config_command;

use super::{pin::Permission::AuthenticatorConfiguration, FidoKeyHid};

use crate::ctaphid;

use anyhow::{anyhow, Error, Result};
use authenticator_config_command::SubCommand;

impl FidoKeyHid {
    pub fn toggle_always_uv(&self, pin: Option<&str>) -> Result<()> {
        self.config(pin, SubCommand::ToggleAlwaysUv)
    }

    pub fn set_min_pin_length(&self, new_min_pin_length: u8, pin: Option<&str>) -> Result<()> {
        self.config(pin, SubCommand::SetMinPinLength(new_min_pin_length))
    }

    pub fn set_min_pin_length_rpids(&self, rpids: Vec<String>, pin: Option<&str>) -> Result<()> {
        self.config(pin, SubCommand::SetMinPinLengthRpIds(rpids))
    }

    fn config(
        &self,
        pin: Option<&str>,
        sub_command: SubCommand,
    ) -> Result<()> {
        let pin = if let Some(v) = pin {
            v
        } else {
            return Err(anyhow!("need PIN."));
        };

        let cid = ctaphid::ctaphid_init(self).map_err(Error::msg)?;

        // get pintoken
        let pin_token =
            self.get_pinuv_auth_token_with_permission(&cid, pin, AuthenticatorConfiguration)?;

        let send_payload = authenticator_config_command::create_payload(
            pin_token,
            sub_command,
        )?;
        let _response_cbor =
            ctaphid::ctaphid_cbor(self, &cid, &send_payload).map_err(Error::msg)?;
        Ok(())
    }
}
