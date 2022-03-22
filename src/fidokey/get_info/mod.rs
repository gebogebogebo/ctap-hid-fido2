use crate::ctaphid;
mod get_info_command;
mod get_info_params;
mod get_info_response;

use crate::make_credential_params::Extension as Mext;

use anyhow::{anyhow, Error, Result};

use super::FidoKeyHid;

#[derive(Debug, Clone, PartialEq)]
pub enum InfoOption {
    Rk,
    Up,
    Uv,
    Plat,
    ClinetPin,
    CredentialMgmtPreview,
    CredMgmt,
    UserVerificationMgmtPreview,
    BioEnroll,
}

#[derive(Debug, Clone, PartialEq)]
pub enum InfoParam {
    VersionsU2Fv2,
    VersionsFido20,
    VersionsFido21Pre,
    VersionsFido21,
    ExtensionsCredProtect,
    ExtensionsCredBlob,
    ExtensionsLargeBlobKey,
    ExtensionsMinPinLength,
    ExtensionsHmacSecret,
}

impl FidoKeyHid {
    pub fn get_info(&self) -> Result<get_info_params::Info> {
        let cid = ctaphid::ctaphid_init(self).map_err(Error::msg)?;
        let send_payload = get_info_command::create_payload();
        let response_cbor = ctaphid::ctaphid_cbor(self, &cid, &send_payload).map_err(Error::msg)?;
        let info = get_info_response::parse_cbor(&response_cbor).map_err(Error::msg)?;
        Ok(info)
    }

    pub fn get_info_u2f(&self) -> Result<String> {
        let cid = ctaphid::ctaphid_init(self).map_err(Error::msg)?;

        let _data: Vec<u8> = Vec::new();

        // CTAP1_INS.Version = 3
        match ctaphid::send_apdu(self, &cid, 0, 3, 0, 0, &_data) {
            Ok(result) => {
                let version: String = String::from_utf8(result).unwrap();
                Ok(version)
            }
            Err(error) => Err(anyhow!(error)),
        }
    }

    pub fn enable_info_param(&self, info_param: &InfoParam) -> Result<bool> {
        let info = self.get_info()?;
        let find = match info_param {
            InfoParam::VersionsU2Fv2 => "U2F_V2",
            InfoParam::VersionsFido20 => "FIDO_2_0",
            InfoParam::VersionsFido21Pre => "FIDO_2_1_PRE",
            InfoParam::VersionsFido21 => "FIDO_2_1",
            InfoParam::ExtensionsCredProtect => Mext::CredProtect(None).as_ref(),
            InfoParam::ExtensionsCredBlob => "credBlob",
            InfoParam::ExtensionsLargeBlobKey => "credBlobKey",
            InfoParam::ExtensionsMinPinLength => "minPinLength",
            InfoParam::ExtensionsHmacSecret => Mext::HmacSecret(None).as_ref(),
        };
        let ret = info.versions.iter().find(|v| *v == find);
        if ret.is_some() {
            return Ok(true);
        }
        let ret = info.extensions.iter().find(|v| *v == find);
        if ret.is_some() {
            return Ok(true);
        }
        Ok(false)
    }
    
    pub fn enable_info_option(&self, info_option: &InfoOption) -> Result<Option<bool>> {
        let info = self.get_info()?;
        let find = match info_option {
            InfoOption::Rk => "rk",
            InfoOption::Up => "up",
            InfoOption::Uv => "uv",
            InfoOption::Plat => "plat",
            InfoOption::ClinetPin => "clientPin",
            InfoOption::CredentialMgmtPreview => "credentialMgmtPreview",
            InfoOption::CredMgmt => "credMgmt",
            InfoOption::UserVerificationMgmtPreview => "userVerificationMgmtPreview",
            InfoOption::BioEnroll => "bioEnroll",
        };
        let ret = info.options.iter().find(|v| (*v).0 == find);
        if let Some(v) = ret {
            // v.1 == true or false
            // - present and set to true.
            // - present and set to false.
            return Ok(Some(v.1));
        }
        // absent.
        Ok(None)
    }
}