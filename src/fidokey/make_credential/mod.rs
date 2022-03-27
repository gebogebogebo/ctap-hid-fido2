pub mod make_credential_command;
pub mod make_credential_params;
pub mod make_credential_response;

use make_credential_params::{
    Attestation,
    CredentialSupportedKeyType,
    Extension as Mext,
    MakeCredentialArgs,
};

use crate::ctaphid;
use crate::enc_hmac_sha_256;
use crate::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use crate::util::should_uv;

use super::FidoKeyHid;
use super::credential_management::credential_management_params::CredentialProtectionPolicy;

use anyhow::{Error, Result};


impl FidoKeyHid {
    /// Registration command.Generate credentials(with PIN,non Resident Key)
    pub fn make_credential(
        &self,
        rpid: &str,
        challenge: &[u8],
        pin: Option<&str>,
    ) -> Result<Attestation> {
        self.make_credential_internal(
            rpid,
            challenge,
            pin,
            false,
            None,
            should_uv(pin),
            None,
            None,
        )
    }

    /// Registration command. Generate credentials (with PIN, non Resident Key) while also
    /// specifying the type of key you'd like to create.
    pub fn make_credential_with_key_type(
        &self,
        rpid: &str,
        challenge: &[u8],
        pin: Option<&str>,
        key_type: Option<CredentialSupportedKeyType>,
    ) -> Result<Attestation> {
        self.make_credential_internal(
            rpid,
            challenge,
            pin,
            false,
            None,
            should_uv(pin),
            None,
            key_type,
        )
    }

    pub fn make_credential_with_extensions(
        &self,
        rpid: &str,
        challenge: &[u8],
        pin: Option<&str>,
        extensions: Option<&Vec<Mext>>,
    ) -> Result<Attestation> {
        self.make_credential_internal(
            rpid,
            challenge,
            pin,
            false,
            None,
            should_uv(pin),
            extensions,
            None,
        )
    }

    /// Registration command.Generate credentials(with PIN ,Resident Key)
    pub fn make_credential_rk(
        &self,
        rpid: &str,
        challenge: &[u8],
        pin: Option<&str>,
        rkparam: &PublicKeyCredentialUserEntity,
    ) -> Result<Attestation> {
        self.make_credential_internal(
            rpid,
            challenge,
            pin,
            true,
            Some(rkparam),
            should_uv(pin),
            None,
            None,
        )
    }

    pub fn make_credential_with_args(&self, args: &MakeCredentialArgs) -> Result<Attestation> {
        let extensions = if args.extensions.is_some() {
            Some(args.extensions.as_ref().unwrap())
        } else {
            None
        };
    
        let (rk, rk_param) = if args.rkparam.is_some() {
            (true, Some(args.rkparam.as_ref().unwrap()))
        } else {
            (false, None)
        };
    
        self.make_credential_internal(
            &args.rpid,
            &args.challenge,
            args.pin,
            rk,
            rk_param,
            args.uv,
            extensions,
            args.key_type,
        )
    }

    fn make_credential_internal(
        &self,
        rpid: &str,
        challenge: &[u8],
        pin: Option<&str>,
        rk: bool,
        rkparam: Option<&PublicKeyCredentialUserEntity>,
        uv: Option<bool>,
        extensions: Option<&Vec<Mext>>,
        key_type: Option<CredentialSupportedKeyType>,
    ) -> Result<make_credential_params::Attestation> {
        // init
        let cid = ctaphid::ctaphid_init(&self).map_err(Error::msg)?;
    
        let user_id = {
            if let Some(rkp) = rkparam {
                rkp.id.to_vec()
            } else {
                [].to_vec()
            }
        };
    
        // create cmmand
        let send_payload = {
            let mut params = make_credential_command::Params::new(rpid, challenge.to_vec(), user_id);
            params.option_rk = rk;
            params.option_uv = uv;
            params.key_type = key_type.unwrap_or(CredentialSupportedKeyType::Ecdsa256);
    
            if let Some(rkp) = rkparam {
                params.user_name = rkp.name.to_string();
                params.user_display_name = rkp.display_name.to_string();
            }
    
            // get pintoken & create pin auth
            if let Some(pin) = pin {
                if !pin.is_empty() {
                    let pin_token = self.get_pin_token(&cid, pin)?;
                    let sig = enc_hmac_sha_256::authenticate(&pin_token.key, &params.client_data_hash);
                    params.pin_auth = sig[0..16].to_vec();
                }
            }
    
            make_credential_command::create_payload(params, extensions)
        };
    
        // send & response
        let response_cbor = ctaphid::ctaphid_cbor(self, &cid, &send_payload).map_err(Error::msg)?;
    
        let att = make_credential_response::parse_cbor(&response_cbor).map_err(Error::msg)?;
        Ok(att)
    }    
}
//

// test
//
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_make_credential_with_pin_non_rk_command() {
        let rpid = "test.com";
        let challenge = b"this is challenge".to_vec();
        // create windows
        let pin_auth = hex::decode("6F79FB322D74972ACAA844C10C183BF7").unwrap();
        let check = "01A7015820E61E2BD6C4612662960B159CD54CF8EFF1A998C89B3742519D11F85E0F5E787602A262696468746573742E636F6D646E616D656003A36269644100646E616D6561206B646973706C61794E616D6561200481A263616C672664747970656A7075626C69632D6B657907A162726BF408506F79FB322D74972ACAA844C10C183BF70901".to_string();

        // create cmmand
        let send_payload = {
            let mut params =
                make_credential_command::Params::new(rpid, challenge.to_vec(), [].to_vec());
            params.option_rk = false; // non rk
                                    //params.option_uv = true;

            println!(
                "- client_data_hash({:02})    = {:?}",
                params.client_data_hash.len(),
                crate::util::to_hex_str(&params.client_data_hash)
            );

            params.pin_auth = pin_auth.to_vec();

            make_credential_command::create_payload(params, None)
        };

        //println!(
        //    "- make_credential({:02})    = {:?}",
        //    send_payload.len(),
        //    util::to_hex_str(&send_payload)
        //);

        let command = hex::encode(send_payload).to_uppercase();
        assert_eq!(command, check);
    }
}