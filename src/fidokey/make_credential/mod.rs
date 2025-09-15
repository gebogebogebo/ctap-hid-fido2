pub mod make_credential_command;
pub mod make_credential_params;
pub mod make_credential_response;
use super::{
    credential_management::credential_management_params::CredentialProtectionPolicy, FidoKeyHid,
};
#[cfg(feature = "tokio")]use super::FidoKeyHidAsync;
use crate::{
    ctaphid, encrypt::enc_hmac_sha_256,
    public_key_credential_user_entity::PublicKeyCredentialUserEntity,
};
use anyhow::Result;
pub use make_credential_params::{
    Attestation, CredentialSupportedKeyType, Extension, Extension as Mext, MakeCredentialArgs,
    MakeCredentialArgsBuilder,
};

impl FidoKeyHid {
    pub fn make_credential_with_args(&self, args: &MakeCredentialArgs) -> Result<Attestation> {
        let user_id = {
            if let Some(rkp) = &args.user_entity {
                rkp.id.to_vec()
            } else {
                [].to_vec()
            }
        };

        // create cmmand
        let send_payload = {
            let mut params =
                make_credential_command::Params::new(&args.rpid, args.challenge.to_vec(), user_id);

            params.option_rk = args.rk.unwrap_or(false);

            params.option_uv = args.uv;

            params.exclude_list = args.exclude_list.to_vec();
            params.key_types = if args.key_types.is_empty() {
                vec![CredentialSupportedKeyType::Ecdsa256]
            } else {
                args.key_types.clone()
            };

            if let Some(rkp) = &args.user_entity {
                params.user_name = rkp.name.to_string();
                params.user_display_name = rkp.display_name.to_string();
            }

            // get pintoken & create pin auth
            if let Some(pin) = args.pin {
                let pin_token = self.get_pin_token(pin)?;
                let sig =
                    enc_hmac_sha_256::authenticate(&pin_token.key, &params.client_data_hash);
                params.pin_auth = sig[0..16].to_vec();
            }

            // TODO
            let extensions = if args.extensions.is_some() {
                Some(args.extensions.as_ref().unwrap())
            } else {
                None
            };

            make_credential_command::create_payload(params, extensions)?
        };

        // send & response
        let response_cbor = ctaphid::ctaphid_cbor(self, &send_payload)?;

        let att = make_credential_response::parse_cbor(&response_cbor)?;
        Ok(att)
    }

    /// Registration command.Generate credentials(with PIN,non Resident Key)
    pub fn make_credential(
        &self,
        rpid: &str,
        challenge: &[u8],
        pin: Option<&str>,
    ) -> Result<Attestation> {
        let mut builder = MakeCredentialArgsBuilder::new(rpid, challenge);
        if let Some(pin) = pin {
            builder = builder.pin(pin);
        }
        let arg = builder.build();
        self.make_credential_with_args(&arg)
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
        let mut builder = MakeCredentialArgsBuilder::new(rpid, challenge);
        if let Some(pin) = pin {
            builder = builder.pin(pin);
        }
        if let Some(key_type) = key_type {
            builder = builder.key_type(key_type);
        }
        let arg = builder.build();
        self.make_credential_with_args(&arg)
    }

    /// Registration command.Generate credentials(with PIN and extensions,non Resident Key)
    pub fn make_credential_with_extensions(
        &self,
        rpid: &str,
        challenge: &[u8],
        pin: Option<&str>,
        extensions: Option<&Vec<Mext>>,
    ) -> Result<Attestation> {
        let mut builder = MakeCredentialArgsBuilder::new(rpid, challenge);
        if let Some(pin) = pin {
            builder = builder.pin(pin);
        }
        if let Some(extensions) = extensions {
            builder = builder.extensions(extensions);
        }
        let arg = builder.build();
        self.make_credential_with_args(&arg)
    }

    /// Registration command.Generate credentials(with PIN ,Resident Key)
    pub fn make_credential_rk(
        &self,
        rpid: &str,
        challenge: &[u8],
        pin: Option<&str>,
        user_entity: &PublicKeyCredentialUserEntity,
    ) -> Result<Attestation> {
        let mut builder = MakeCredentialArgsBuilder::new(rpid, challenge)
            .user_entity(user_entity)
            .resident_key();

        if let Some(pin) = pin {
            builder = builder.pin(pin);
        }
        let arg = builder.build();
        self.make_credential_with_args(&arg)
    }
}

#[cfg(feature = "tokio")]impl FidoKeyHidAsync {
    pub async fn make_credential_with_args(&self, args: &MakeCredentialArgs<'_>) -> Result<Attestation> {
        let user_id = {
            if let Some(rkp) = &args.user_entity {
                rkp.id.to_vec()
            } else {
                [].to_vec()
            }
        };

        // create cmmand
        let send_payload = {
            let mut params =
                make_credential_command::Params::new(&args.rpid, args.challenge.to_vec(), user_id);

            params.option_rk = args.rk.unwrap_or(false);

            params.option_uv = args.uv;

            params.exclude_list = args.exclude_list.to_vec();
            params.key_types = if args.key_types.is_empty() {
                vec![CredentialSupportedKeyType::Ecdsa256]
            } else {
                args.key_types.clone()
            };

            if let Some(rkp) = &args.user_entity {
                params.user_name = rkp.name.to_string();
                params.user_display_name = rkp.display_name.to_string();
            }

            // get pintoken & create pin auth
            if let Some(pin) = args.pin {
                let pin_token = self.get_pin_token(pin).await?;
                let sig =
                    enc_hmac_sha_256::authenticate(&pin_token.key, &params.client_data_hash);
                params.pin_auth = sig[0..16].to_vec();
            }

            // TODO
            let extensions = if args.extensions.is_some() {
                Some(args.extensions.as_ref().unwrap())
            } else {
                None
            };

            make_credential_command::create_payload(params, extensions)?
        };

        // send & response
        let response_cbor = ctaphid::ctaphid_cbor_async(self, &send_payload).await?;

        let att = make_credential_response::parse_cbor(&response_cbor)?;
        Ok(att)
    }

    /// Registration command.Generate credentials(with PIN,non Resident Key)
    pub async fn make_credential(
        &self,
        rpid: &str,
        challenge: &[u8],
        pin: Option<&str>,
    ) -> Result<Attestation> {
        let mut builder = MakeCredentialArgsBuilder::new(rpid, challenge);
        if let Some(pin) = pin {
            builder = builder.pin(pin);
        }
        let arg = builder.build();
        self.make_credential_with_args(&arg).await
    }

    /// Registration command. Generate credentials (with PIN, non Resident Key) while also
    /// specifying the type of key you'd like to create.
    pub async fn make_credential_with_key_type(
        &self,
        rpid: &str,
        challenge: &[u8],
        pin: Option<&str>,
        key_type: Option<CredentialSupportedKeyType>,
    ) -> Result<Attestation> {
        let mut builder = MakeCredentialArgsBuilder::new(rpid, challenge);
        if let Some(pin) = pin {
            builder = builder.pin(pin);
        }
        if let Some(key_type) = key_type {
            builder = builder.key_type(key_type);
        }
        let arg = builder.build();
        self.make_credential_with_args(&arg).await
    }

    /// Registration command.Generate credentials(with PIN and extensions,non Resident Key)
    pub async fn make_credential_with_extensions(
        &self,
        rpid: &str,
        challenge: &[u8],
        pin: Option<&str>,
        extensions: Option<&Vec<Mext>>,
    ) -> Result<Attestation> {
        let mut builder = MakeCredentialArgsBuilder::new(rpid, challenge);
        if let Some(pin) = pin {
            builder = builder.pin(pin);
        }
        if let Some(extensions) = extensions {
            builder = builder.extensions(extensions);
        }
        let arg = builder.build();
        self.make_credential_with_args(&arg).await
    }

    /// Registration command.Generate credentials(with PIN ,Resident Key)
    pub async fn make_credential_rk(
        &self,
        rpid: &str,
        challenge: &[u8],
        pin: Option<&str>,
        user_entity: &PublicKeyCredentialUserEntity,
    ) -> Result<Attestation> {
        let mut builder = MakeCredentialArgsBuilder::new(rpid, challenge)
            .user_entity(user_entity)
            .resident_key();

        if let Some(pin) = pin {
            builder = builder.pin(pin);
        }
        let arg = builder.build();
        self.make_credential_with_args(&arg).await
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

            make_credential_command::create_payload(params, None).unwrap()
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
