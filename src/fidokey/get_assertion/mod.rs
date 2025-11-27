pub mod get_assertion_command;
pub mod get_assertion_params;
pub mod get_assertion_response;
pub mod get_next_assertion_command;
use crate::{ctaphid, hmac_ext::HmacExt, FidoKeyHid};
use anyhow::Result;
use get_assertion_params::{Assertion, Extension as Gext, GetAssertionArgs};
pub use get_assertion_params::{Extension, GetAssertionArgsBuilder};

impl FidoKeyHid {
    /// Create a new assertion manually specifying the args using GetAssertionArgs
    pub fn get_assertion_with_args(&self, args: &GetAssertionArgs) -> Result<Vec<Assertion>> {
        let dummy_credentials;
        let credential_ids = if !args.credential_ids.is_empty() {
            &args.credential_ids
        } else {
            dummy_credentials = vec![];
            &dummy_credentials
        };

        let extensions = if args.extensions.is_some() {
            Some(args.extensions.as_ref().unwrap())
        } else {
            None
        };

        let hmac_ext = create_hmacext(self, extensions)?;

        // create command
        let mut params = get_assertion_command::Params::new(
            &args.rpid,
            args.challenge.to_vec(),
            credential_ids.to_vec(),
        );
        params.option_up = true;
        params.option_uv = args.uv;

        // create pin auth
        if let Some(pin) = args.pin {
             params.pin_auth = self.create_pin_auth(pin, &params.client_data_hash)?;
        }

        // Get payload as Vec<u8>, not Result<Vec<u8>>
        let send_payload =
            get_assertion_command::create_payload(params, extensions, hmac_ext.clone(), self.pin_protocol_version)?;

        // send & response
        let response_cbor = ctaphid::ctaphid_cbor(self, &send_payload)?;

        let ass = get_assertion_response::parse_cbor(
            &response_cbor,
            hmac_ext.map(|ext| ext.shared_secret),
        )?;

        let mut asss = vec![ass];
        for _ in 0..(asss[0].number_of_credentials - 1) {
            let ass = get_next_assertion(self)?;
            asss.push(ass);
        }

        Ok(asss)
    }

    /// Authentication command(with PIN , non Resident Key)
    pub fn get_assertion(
        &self,
        rpid: &str,
        challenge: &[u8],
        credential_ids: &[Vec<u8>],
        pin: Option<&str>,
    ) -> Result<Assertion> {
        let mut builder = GetAssertionArgsBuilder::new(rpid, challenge);
        for credential_id in credential_ids {
            builder = builder.add_credential_id(credential_id);
        }
        if let Some(pin) = pin {
            builder = builder.pin(pin);
        }
        let args = builder.build();
        let assertions = self.get_assertion_with_args(&args)?;
        Ok(assertions[0].clone())
    }

    /// Authentication command(with PIN , non Resident Key , Extension)
    pub fn get_assertion_with_extensios(
        &self,
        rpid: &str,
        challenge: &[u8],
        credential_ids: &[Vec<u8>],
        pin: Option<&str>,
        extensions: Option<&Vec<Gext>>,
    ) -> Result<Assertion> {
        let mut builder = GetAssertionArgsBuilder::new(rpid, challenge);
        for credential_id in credential_ids {
            builder = builder.add_credential_id(credential_id);
        }
        if let Some(pin) = pin {
            builder = builder.pin(pin);
        }
        if let Some(extensions) = extensions {
            builder = builder.extensions(extensions);
        }
        let args = builder.build();
        let assertions = self.get_assertion_with_args(&args)?;
        Ok(assertions[0].clone())
    }

    /// Authentication command(with PIN , Resident Key)
    pub fn get_assertions_rk(
        &self,
        rpid: &str,
        challenge: &[u8],
        pin: Option<&str>,
    ) -> Result<Vec<Assertion>> {
        let mut builder = GetAssertionArgsBuilder::new(rpid, challenge);
        if let Some(pin) = pin {
            builder = builder.pin(pin);
        }
        let args = builder.build();
        self.get_assertion_with_args(&args)
    }
}

fn get_next_assertion(device: &FidoKeyHid) -> Result<Assertion> {
    let send_payload = get_next_assertion_command::create_payload();
    let response_cbor = ctaphid::ctaphid_cbor(device, &send_payload)?;
    get_assertion_response::parse_cbor(&response_cbor, None)
}

fn create_hmacext(device: &FidoKeyHid, extensions: Option<&Vec<Gext>>) -> Result<Option<HmacExt>> {
    if let Some(extensions) = extensions {
        for e in extensions {
            match e {
                Gext::HmacSecret(n) => {
                    let mut hmac_ext = HmacExt::default();
                    hmac_ext.create(device, &n.unwrap(), None)?;
                    return Ok(Some(hmac_ext));
                }
                Gext::HmacSecret2(n) => {
                    let mut hmac_ext = HmacExt::default();
                    let h = &n.unwrap();
                    hmac_ext.create(device, &h.0, Some(&h.1))?;
                    return Ok(Some(hmac_ext));
                }
                _ => continue,
            }
        }
    }

    Ok(None)
}
