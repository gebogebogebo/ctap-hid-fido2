mod authenticator_config_command;

use super::{pin::Permission::AuthenticatorConfiguration, FidoKeyHid};
#[cfg(feature = "tokio")]use super::FidoKeyHidAsync;

use crate::ctaphid;

use anyhow::{anyhow, Result};
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

    pub fn force_change_pin(&self, pin: Option<&str>) -> Result<()> {
        self.config(pin, SubCommand::ForceChangePin)
    }

    fn config(&self, pin: Option<&str>, sub_command: SubCommand) -> Result<()> {
        let pin = if let Some(v) = pin {
            v
        } else {
            return Err(anyhow!("need PIN."));
        };

        // get pintoken
        let pin_token =
            self.get_pinuv_auth_token_with_permission(pin, AuthenticatorConfiguration)?;

        let send_payload = authenticator_config_command::create_payload(pin_token, sub_command)?;
        let _response_cbor = ctaphid::ctaphid_cbor(self, &send_payload)?;
        Ok(())
    }
}


#[cfg(feature = "tokio")]impl FidoKeyHidAsync {
    pub async fn toggle_always_uv(&self, pin: Option<&str>) -> Result<()> {
        self.config(pin, SubCommand::ToggleAlwaysUv).await
    }

    pub async fn set_min_pin_length(&self, new_min_pin_length: u8, pin: Option<&str>) -> Result<()> {
        self.config(pin, SubCommand::SetMinPinLength(new_min_pin_length)).await
    }

    pub async fn set_min_pin_length_rpids(&self, rpids: Vec<String>, pin: Option<&str>) -> Result<()> {
        self.config(pin, SubCommand::SetMinPinLengthRpIds(rpids)).await
    }

    pub async fn force_change_pin(&self, pin: Option<&str>) -> Result<()> {
        self.config(pin, SubCommand::ForceChangePin).await
    }

    async fn config(&self, pin: Option<&str>, sub_command: SubCommand) -> Result<()> {
        let pin = if let Some(v) = pin {
            v
        } else {
            return Err(anyhow!("need PIN."));
        };

        // get pintoken
        let pin_token =
            self.get_pinuv_auth_token_with_permission(pin, AuthenticatorConfiguration).await?;

        let send_payload = authenticator_config_command::create_payload(pin_token, sub_command)?;
        let _response_cbor = ctaphid::ctaphid_cbor_async(self, &send_payload).await?;
        Ok(())
    }
}
