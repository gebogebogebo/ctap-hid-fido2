use crate::ctaphid;
mod get_info_command;
mod get_info_params;
mod get_info_response;
use super::FidoKeyHid;
use anyhow::{anyhow, Result};

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
        let send_payload = get_info_command::create_payload();
        let response_cbor = ctaphid::ctaphid_cbor(self, &send_payload)?;
        let info = get_info_response::parse_cbor(&response_cbor)?;
        Ok(info)
    }

    pub fn get_info_u2f(&self) -> Result<String> {
        let _data: Vec<u8> = Vec::new();

        // CTAP1_INS.Version = 3
        match ctaphid::send_apdu(self, 0, 3, 0, 0, &_data) {
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
        let ret = info.options.iter().find(|v| (v).0 == info_option.as_ref());
        if let Some(v) = ret {
            // v.1 == true or false
            // - present and set to true.
            // - present and set to false.
            return Ok(Some(v.1));
        }
        // absent.
        Ok(None)
    }

    pub fn set_pin_uv_auth_protocol_two(&mut self) -> Result<bool> {
        let info = self.get_info()?;
        if info.pin_uv_auth_protocols.contains(&2) {
            self.pin_protocol_version = 2;
            return Ok(true);
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use crate::fidokey::get_info::get_info_response;

    #[test]
    fn test_get_info_response_parse_cbor_yubikey_bio() {
        let hex_data = "B30184665532465F5632684649444F5F325F306C4649444F5F325F315F505245684649444F5F325F3102856B6372656450726F746563746B686D61632D7365637265746C6C61726765426C6F624B65796863726564426C6F626C6D696E50696E4C656E6774680350D8522D9F575B486688A9BA99FA02F35B04B062726BF5627570F5627576F564706C6174F4677576546F6B656EF568616C776179735576F568637265644D676D74F569617574686E72436667F56962696F456E726F6C6CF569636C69656E7450696EF56A6C61726765426C6F6273F56E70696E557641757468546F6B656EF56F7365744D696E50494E4C656E677468F5706D616B654372656455764E6F74527164F47563726564656E7469616C4D676D7450726576696577F5781B75736572566572696669636174696F6E4D676D7450726576696577F5051904B00682020107080818800981637573620A82A263616C672664747970656A7075626C69632D6B6579A263616C672764747970656A7075626C69632D6B65790B1904000CF40D040E1A000505060F18201001110312021415";
        let bytes = hex::decode(hex_data).unwrap();
        let info = get_info_response::parse_cbor(&bytes).unwrap();

        assert_eq!(
            info.versions,
            vec!["U2F_V2", "FIDO_2_0", "FIDO_2_1_PRE", "FIDO_2_1"]
        );
        assert_eq!(
            info.extensions,
            vec![
                "credProtect",
                "hmac-secret",
                "largeBlobKey",
                "credBlob",
                "minPinLength"
            ]
        );
        assert_eq!(
            hex::encode(&info.aaguid),
            "d8522d9f575b486688a9ba99fa02f35b"
        );

        let expected_options = vec![
            ("rk".to_string(), true),
            ("up".to_string(), true),
            ("uv".to_string(), true),
            ("plat".to_string(), false),
            ("uvToken".to_string(), true),
            ("alwaysUv".to_string(), true),
            ("credMgmt".to_string(), true),
            ("authnrCfg".to_string(), true),
            ("bioEnroll".to_string(), true),
            ("clientPin".to_string(), true),
            ("largeBlobs".to_string(), true),
            ("pinUvAuthToken".to_string(), true),
            ("setMinPINLength".to_string(), true),
            ("makeCredUvNotRqd".to_string(), false),
            ("credentialMgmtPreview".to_string(), true),
            ("userVerificationMgmtPreview".to_string(), true),
        ];
        assert_eq!(info.options.len(), expected_options.len());
        for option in expected_options {
            assert!(info.options.contains(&option));
        }

        assert_eq!(info.max_msg_size, 1200);
        assert_eq!(info.pin_uv_auth_protocols, vec![2, 1]);
        assert_eq!(info.max_credential_count_in_list, 8);
        assert_eq!(info.max_credential_id_length, 128);
        assert_eq!(info.transports, vec!["usb"]);

        let expected_algorithms = vec![
            ("alg".to_string(), "-7".to_string()),
            ("type".to_string(), "public-key".to_string()),
            ("alg".to_string(), "-8".to_string()),
            ("type".to_string(), "public-key".to_string()),
        ];
        assert_eq!(info.algorithms.len(), expected_algorithms.len());
        for alg in expected_algorithms {
            assert!(info.algorithms.contains(&alg));
        }

        assert_eq!(info.max_serialized_large_blob_array, 1024);
        assert_eq!(info.force_pin_change, false);
        assert_eq!(info.min_pin_length, 4);
        assert_eq!(info.firmware_version, 328966);
        assert_eq!(info.max_cred_blob_length, 32);
        assert_eq!(info.max_rpids_for_set_min_pin_length, 1);
        assert_eq!(info.preferred_platform_uv_attempts, 3);
        assert_eq!(info.uv_modality, 2);
        assert_eq!(info.remaining_discoverable_credentials, 21);
        assert_eq!(info.attestation_formats, vec![] as Vec<String>);
    }

    #[test]
    fn test_get_info_response_parse_cbor_2() {
        let hex_data = "AA0183665532465F5632684649444F5F325F30684649444F5F325F3102836B6372656450726F746563746B686D61632D73656372657471746869726450617274795061796D656E740350EC99DB19CD1F4C06A2A9940F17A6A30B04A862726BF5627570F564706C6174F468637265644D676D74F569636C69656E7450696EF56A6C61726765426C6F6273F46E70696E557641757468546F6B656EF5706D616B654372656455764E6F74527164F505190C0006820201070A0818FF0982636E6663637573621682667061636B6564646E6F6E65";
        let bytes = hex::decode(hex_data).unwrap();
        let info = get_info_response::parse_cbor(&bytes).unwrap();

        assert_eq!(info.versions, vec!["U2F_V2", "FIDO_2_0", "FIDO_2_1"]);
        assert_eq!(
            info.extensions,
            vec!["credProtect", "hmac-secret", "thirdPartyPayment"]
        );
        assert_eq!(
            hex::encode(&info.aaguid),
            "ec99db19cd1f4c06a2a9940f17a6a30b"
        );

        let expected_options = vec![
            ("rk".to_string(), true),
            ("up".to_string(), true),
            ("plat".to_string(), false),
            ("credMgmt".to_string(), true),
            ("clientPin".to_string(), true),
            ("largeBlobs".to_string(), false),
            ("pinUvAuthToken".to_string(), true),
            ("makeCredUvNotRqd".to_string(), true),
        ];
        assert_eq!(info.options.len(), expected_options.len());
        for option in expected_options {
            assert!(info.options.contains(&option));
        }

        assert_eq!(info.max_msg_size, 3072);
        assert_eq!(info.pin_uv_auth_protocols, vec![2, 1]);
        assert_eq!(info.max_credential_count_in_list, 10);
        assert_eq!(info.max_credential_id_length, 255);
        assert_eq!(info.transports, vec!["nfc", "usb"]);
        assert_eq!(info.algorithms.len(), 0);
        assert_eq!(info.max_serialized_large_blob_array, 0);
        assert_eq!(info.force_pin_change, false);
        assert_eq!(info.min_pin_length, 0);
        assert_eq!(info.firmware_version, 0);
        assert_eq!(info.max_cred_blob_length, 0);
        assert_eq!(info.max_rpids_for_set_min_pin_length, 0);
        assert_eq!(info.preferred_platform_uv_attempts, 0);
        assert_eq!(info.uv_modality, 0);
        assert_eq!(info.remaining_discoverable_credentials, 0);
        assert_eq!(info.attestation_formats, vec!["packed", "none"]);
    }
}
