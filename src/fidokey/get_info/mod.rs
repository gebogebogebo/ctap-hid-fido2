use crate::ctaphid;
mod get_info_command;
mod get_info_params;
mod get_info_response;

use anyhow::{anyhow, Error, Result};

use super::FidoKeyHid;

#[derive(Debug, Clone, PartialEq, strum_macros::AsRefStr)]
pub enum InfoOption {
    #[strum(serialize = "alwaysUv")]
    AlwaysUv,
    #[strum(serialize = "authnrCfg")]
    AuthnrCfg,
    #[strum(serialize = "bioEnroll")]
    BioEnroll,
    #[strum(serialize = "clientPin")]
    ClientPin,
    #[strum(serialize = "credentialMgmtPreview")]
    CredentialMgmtPreview,
    #[strum(serialize = "credMgmt")]
    CredMgmt,
    #[strum(serialize = "ep")]
    Ep,
    #[strum(serialize = "largeBlobs")]
    LargeBlobs,
    #[strum(serialize = "makeCredUvNotRqd")]
    MakeCredUvNotRqd,
    #[strum(serialize = "noMcGaPermissionsWithClientPin")]
    NoMcGaPermissionsWithClientPin,
    #[strum(serialize = "pinUvAuthToken")]
    PinUvAuthToken,
    #[strum(serialize = "plat")]
    Plat,
    #[strum(serialize = "rk")]
    Rk,
    #[strum(serialize = "setMinPINLength")]
    SetMinPINLength,
    #[strum(serialize = "up")]
    Up,
    #[strum(serialize = "userVerificationMgmtPreview")]
    UserVerificationMgmtPreview,
    #[strum(serialize = "uv")]
    Uv,
    #[strum(serialize = "uvAcfg")]
    UvAcfg,
    #[strum(serialize = "uvBioEnroll")]
    UvBioEnroll,
    #[strum(serialize = "uvToken")]
    UvToken,
}

#[derive(Debug, Clone, PartialEq, strum_macros::AsRefStr)]
pub enum InfoParam {
    #[strum(serialize = "U2F_V2")]
    VersionsU2Fv2,
    #[strum(serialize = "FIDO_2_0")]
    VersionsFido20,
    #[strum(serialize = "FIDO_2_1_PRE")]
    VersionsFido21Pre,
    #[strum(serialize = "FIDO_2_1")]
    VersionsFido21,
    #[strum(serialize = "credProtect")]
    ExtensionsCredProtect,
    #[strum(serialize = "credBlob")]
    ExtensionsCredBlob,
    #[strum(serialize = "credBlobKey")]
    ExtensionsLargeBlobKey,
    #[strum(serialize = "minPinLength")]
    ExtensionsMinPinLength,
    #[strum(serialize = "hmac-secret")]
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
        let ret = info.versions.iter().find(|v| *v == info_param.as_ref());
        if ret.is_some() {
            return Ok(true);
        }
        let ret = info.extensions.iter().find(|v| *v == info_param.as_ref());
        if ret.is_some() {
            return Ok(true);
        }
        Ok(false)
    }

    pub fn enable_info_option(&self, info_option: &InfoOption) -> Result<Option<bool>> {
        let info = self.get_info()?;
        let ret = info.options.iter().find(|v| (*v).0 == info_option.as_ref());
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
