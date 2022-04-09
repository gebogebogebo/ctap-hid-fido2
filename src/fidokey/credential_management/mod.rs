pub mod credential_management_command;
pub mod credential_management_params;
pub mod credential_management_response;

use crate::ctaphid;
use crate::public_key_credential_descriptor::PublicKeyCredentialDescriptor;
use crate::public_key_credential_user_entity::PublicKeyCredentialUserEntity;

use crate::util;

use super::{pin::Permission, FidoKeyHid};

use anyhow::{Error, Result};

impl FidoKeyHid {
    /// CredentialManagement - getCredsMetadata (CTAP 2.1-PRE)
    pub fn credential_management_get_creds_metadata(
        &self,
        pin: Option<&str>,
    ) -> Result<credential_management_params::CredentialsCount> {
        let meta = self.credential_management(
            pin,
            credential_management_command::SubCommand::GetCredsMetadata,
            None,
            None,
            None,
        )?;
        Ok(credential_management_params::CredentialsCount::new(&meta))
    }

    /// CredentialManagement - enumerateRPsBegin & enumerateRPsNext (CTAP 2.1-PRE)
    pub fn credential_management_enumerate_rps(
        &self,
        pin: Option<&str>,
    ) -> Result<Vec<credential_management_params::Rp>> {
        let mut datas: Vec<credential_management_params::Rp> = Vec::new();
        let data = self.credential_management(
            pin,
            credential_management_command::SubCommand::EnumerateRPsBegin,
            None,
            None,
            None,
        )?;

        if data.total_rps > 0 {
            datas.push(credential_management_params::Rp::new(&data));
            let roop_n = data.total_rps - 1;
            for _ in 0..roop_n {
                let data = self.credential_management(
                    pin,
                    credential_management_command::SubCommand::EnumerateRPsGetNextRp,
                    None,
                    None,
                    None,
                )?;
                datas.push(credential_management_params::Rp::new(&data));
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
        let mut datas: Vec<credential_management_params::Credential> = Vec::new();

        let data = self.credential_management(
            pin,
            credential_management_command::SubCommand::EnumerateCredentialsBegin,
            Some(rpid_hash.to_vec()),
            None,
            None,
        )?;

        datas.push(credential_management_params::Credential::new(&data));
        if data.total_credentials > 0 {
            let roop_n = data.total_credentials - 1;
            for _ in 0..roop_n {
                let data = self.credential_management(
                    pin,
                    credential_management_command::SubCommand::EnumerateCredentialsGetNextCredential,
                    Some(rpid_hash.to_vec()),
                    None,
                    None,
                )?;
                datas.push(credential_management_params::Credential::new(&data));
            }
        }
        Ok(datas)
    }

    /// CredentialManagement - deleteCredential (CTAP 2.1-PRE)
    pub fn credential_management_delete_credential(
        &self,
        pin: Option<&str>,
        pkcd: Option<PublicKeyCredentialDescriptor>,
    ) -> Result<()> {
        self.credential_management(
            pin,
            credential_management_command::SubCommand::DeleteCredential,
            None,
            pkcd,
            None,
        )?;
        Ok(())
    }

    /// CredentialManagement - updateUserInformation (CTAP 2.1-PRE)
    pub fn credential_management_update_user_information(
        &self,
        pin: Option<&str>,
        pkcd: Option<PublicKeyCredentialDescriptor>,
        pkcue: Option<PublicKeyCredentialUserEntity>,
    ) -> Result<()> {
        self.credential_management(
            pin,
            credential_management_command::SubCommand::UpdateUserInformation,
            None,
            pkcd,
            pkcue,
        )?;
        Ok(())
    }

    fn credential_management(
        &self,
        pin: Option<&str>,
        sub_command: credential_management_command::SubCommand,
        rpid_hash: Option<Vec<u8>>,
        pkcd: Option<PublicKeyCredentialDescriptor>,
        pkcue: Option<PublicKeyCredentialUserEntity>,
    ) -> Result<credential_management_params::CredentialManagementData> {
        let cid = ctaphid::ctaphid_init(self).map_err(Error::msg)?;

        // pin token
        let pin_token = {
            if let Some(pin) = pin {
                if self.use_pre_credential_management {
                    Some(self.get_pin_token(&cid, pin)?)
                } else {
                    Some(self.get_pinuv_auth_token_with_permission(&cid, pin, Permission::Cm)?)
                }
            } else {
                None
            }
        };

        let send_payload = credential_management_command::create_payload(
            pin_token,
            sub_command,
            rpid_hash,
            pkcd,
            pkcue,
            self.use_pre_credential_management,
        );

        if self.enable_log {
            println!("send(cbor) = {}", util::to_hex_str(&send_payload));
        }

        let response_cbor =
            ctaphid::ctaphid_cbor(self, &cid, &send_payload).map_err(Error::msg)?;

        if self.enable_log {
            println!("response(cbor) = {}", util::to_hex_str(&response_cbor));
        }

        credential_management_response::parse_cbor(&response_cbor).map_err(Error::msg)
    }
}
