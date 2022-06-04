pub mod credential_management_command;
pub mod credential_management_params;
pub mod credential_management_response;

use crate::{
    ctaphid, public_key_credential_descriptor::PublicKeyCredentialDescriptor,
    public_key_credential_user_entity::PublicKeyCredentialUserEntity, util,
};

use {
    credential_management_command::SubCommand,
    credential_management_params::{Credential, CredentialManagementData, CredentialsCount, Rp},
};

use super::{pin::Permission::CredentialManagement, FidoKeyHid};

use anyhow::{Error, Result};

impl FidoKeyHid {
    /// CredentialManagement - getCredsMetadata (CTAP 2.1-PRE)
    pub fn credential_management_get_creds_metadata(
        &self,
        pin: Option<&str>,
    ) -> Result<CredentialsCount> {
        let meta = self.credential_management(pin, SubCommand::GetCredsMetadata)?;
        Ok(CredentialsCount::new(&meta))
    }

    /// CredentialManagement - enumerateRPsBegin & enumerateRPsNext (CTAP 2.1-PRE)
    pub fn credential_management_enumerate_rps(&self, pin: Option<&str>) -> Result<Vec<Rp>> {
        let mut datas: Vec<Rp> = Vec::new();
        let data = self.credential_management(pin, SubCommand::EnumerateRPsBegin)?;

        if data.total_rps > 0 {
            datas.push(Rp::new(&data));
            let roop_n = data.total_rps - 1;
            for _ in 0..roop_n {
                let data = self.credential_management(pin, SubCommand::EnumerateRPsGetNextRp)?;
                datas.push(Rp::new(&data));
            }
        }
        Ok(datas)
    }

    /// CredentialManagement - enumerateCredentialsBegin & enumerateCredentialsNext (CTAP 2.1-PRE)
    pub fn credential_management_enumerate_credentials(
        &self,
        pin: Option<&str>,
        rpid_hash: &[u8],
    ) -> Result<Vec<credential_management_params::Credential>> {
        let mut datas: Vec<Credential> = Vec::new();

        let data = self.credential_management(
            pin,
            SubCommand::EnumerateCredentialsBegin(rpid_hash.to_vec()),
        )?;

        datas.push(Credential::new(&data));
        if data.total_credentials > 0 {
            let roop_n = data.total_credentials - 1;
            for _ in 0..roop_n {
                let data = self.credential_management(
                    pin,
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
        self.credential_management(pin, SubCommand::DeleteCredential(pkcd))?;
        Ok(())
    }

    /// CredentialManagement - updateUserInformation (CTAP 2.1-PRE)
    pub fn credential_management_update_user_information(
        &self,
        pin: Option<&str>,
        pkcd: PublicKeyCredentialDescriptor,
        pkcue: PublicKeyCredentialUserEntity,
    ) -> Result<()> {
        self.credential_management(pin, SubCommand::UpdateUserInformation(pkcd, pkcue))?;
        Ok(())
    }

    fn credential_management(
        &self,
        pin: Option<&str>,
        sub_command: SubCommand,
    ) -> Result<CredentialManagementData> {
        let cid = ctaphid::ctaphid_init(self)?;

        // pin token
        let pin_token = {
            if let Some(pin) = pin {
                if self.use_pre_credential_management {
                    Some(self.get_pin_token(&cid, pin)?)
                } else {
                    Some(self.get_pinuv_auth_token_with_permission(
                        &cid,
                        pin,
                        CredentialManagement,
                    )?)
                }
            } else {
                None
            }
        };

        let send_payload = credential_management_command::create_payload(
            pin_token,
            sub_command,
            self.use_pre_credential_management,
        )?;

        if self.enable_log {
            println!("send(cbor) = {}", util::to_hex_str(&send_payload));
        }

        let response_cbor = ctaphid::ctaphid_cbor(self, &cid, &send_payload)?;

        if self.enable_log {
            println!("response(cbor) = {}", util::to_hex_str(&response_cbor));
        }

        credential_management_response::parse_cbor(&response_cbor).map_err(Error::msg)
    }
}
