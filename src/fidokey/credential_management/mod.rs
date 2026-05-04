pub mod credential_management_command;
pub mod credential_management_params;
pub mod credential_management_response;
use super::{pin::Permission::CredentialManagement, FidoKeyHid};
use crate::{
    ctaphid, pintoken::PinToken,
    public_key_credential_descriptor::PublicKeyCredentialDescriptor,
    public_key_credential_user_entity::PublicKeyCredentialUserEntity, util,
};
use anyhow::Result;
use {
    credential_management_command::SubCommand,
    credential_management_params::{Credential, CredentialManagementData, CredentialsCount, Rp},
};

impl FidoKeyHid {
    /// CredentialManagement - getCredsMetadata (CTAP 2.1-PRE)
    pub fn credential_management_get_creds_metadata(
        &self,
        pin: Option<&str>,
    ) -> Result<CredentialsCount> {
        let pin_token = self.acquire_cm_token(pin)?;
        let meta = self.credential_management(pin_token.as_ref(), SubCommand::GetCredsMetadata)?;
        Ok(CredentialsCount::new(&meta))
    }

    /// CredentialManagement - enumerateRPsBegin & enumerateRPsNext (CTAP 2.1-PRE)
    ///
    /// The same pinUvAuthToken is used for `EnumerateRPsBegin` and every
    /// subsequent `EnumerateRPsGetNextRp` call. Per CTAP 2.1 §6.8 an
    /// authenticator MUST discard the stateful enumeration if the
    /// pinUvAuthToken that authenticated the initializing command expires —
    /// and issuing a fresh pinUvAuthToken for each iteration expires the
    /// prior one, causing `CTAP2_ERR_NOT_ALLOWED` on the continuation.
    pub fn credential_management_enumerate_rps(&self, pin: Option<&str>) -> Result<Vec<Rp>> {
        let pin_token = self.acquire_cm_token(pin)?;
        let mut datas: Vec<Rp> = Vec::new();
        let data = self.credential_management(pin_token.as_ref(), SubCommand::EnumerateRPsBegin)?;

        if data.total_rps > 0 {
            datas.push(Rp::new(&data));
            let roop_n = data.total_rps - 1;
            for _ in 0..roop_n {
                let data = self
                    .credential_management(pin_token.as_ref(), SubCommand::EnumerateRPsGetNextRp)?;
                datas.push(Rp::new(&data));
            }
        }
        Ok(datas)
    }

    /// CredentialManagement - enumerateCredentialsBegin & enumerateCredentialsNext (CTAP 2.1-PRE)
    ///
    /// See `credential_management_enumerate_rps` for why the same
    /// pinUvAuthToken is reused across the stateful iteration.
    pub fn credential_management_enumerate_credentials(
        &self,
        pin: Option<&str>,
        rpid_hash: &[u8],
    ) -> Result<Vec<credential_management_params::Credential>> {
        let pin_token = self.acquire_cm_token(pin)?;
        let mut datas: Vec<Credential> = Vec::new();

        let data = self.credential_management(
            pin_token.as_ref(),
            SubCommand::EnumerateCredentialsBegin(rpid_hash.to_vec()),
        )?;

        datas.push(Credential::new(&data));
        if data.total_credentials > 0 {
            let roop_n = data.total_credentials - 1;
            for _ in 0..roop_n {
                let data = self.credential_management(
                    pin_token.as_ref(),
                    SubCommand::EnumerateCredentialsGetNextCredential(rpid_hash.to_vec()),
                )?;
                datas.push(Credential::new(&data));
            }
        }
        Ok(datas)
    }

    /// CredentialManagement - deleteCredential (CTAP 2.1-PRE)
    pub fn credential_management_delete_credential(
        &self,
        pin: Option<&str>,
        pkcd: PublicKeyCredentialDescriptor,
    ) -> Result<()> {
        let pin_token = self.acquire_cm_token(pin)?;
        self.credential_management(pin_token.as_ref(), SubCommand::DeleteCredential(pkcd))?;
        Ok(())
    }

    /// CredentialManagement - updateUserInformation (CTAP 2.1-PRE)
    pub fn credential_management_update_user_information(
        &self,
        pin: Option<&str>,
        pkcd: PublicKeyCredentialDescriptor,
        pkcue: PublicKeyCredentialUserEntity,
    ) -> Result<()> {
        let pin_token = self.acquire_cm_token(pin)?;
        self.credential_management(
            pin_token.as_ref(),
            SubCommand::UpdateUserInformation(pkcd, pkcue),
        )?;
        Ok(())
    }

    fn acquire_cm_token(&self, pin: Option<&str>) -> Result<Option<PinToken>> {
        match pin {
            Some(pin) => {
                let token = if self.use_pre_credential_management {
                    self.get_pin_token(pin)?
                } else {
                    self.get_pinuv_auth_token_with_permission(pin, CredentialManagement)?
                };
                Ok(Some(token))
            }
            None => Ok(None),
        }
    }

    fn credential_management(
        &self,
        pin_token: Option<&PinToken>,
        sub_command: SubCommand,
    ) -> Result<CredentialManagementData> {
        let send_payload = credential_management_command::create_payload(
            pin_token,
            sub_command,
            self.use_pre_credential_management,
            self.pin_protocol_version,
        )?;

        if self.enable_log {
            println!("send(cbor) = {}", util::to_hex_str(&send_payload));
        }

        let response_cbor = ctaphid::ctaphid_cbor(self, &send_payload)?;

        if self.enable_log {
            println!("response(cbor) = {}", util::to_hex_str(&response_cbor));
        }

        credential_management_response::parse_cbor(&response_cbor)
    }
}
