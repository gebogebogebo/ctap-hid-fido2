pub mod get_assertion_command;
pub mod get_assertion_params;
pub mod get_assertion_response;
pub mod get_next_assertion_command;

use get_assertion_params::{Assertion, Extension as Gext, GetAssertionArgs};

use crate::ctaphid;
use crate::enc_hmac_sha_256;
use crate::hmac::HmacExt;
use crate::util::should_uv;
use crate::FidoKeyHid;

use anyhow::{Error, Result};

pub use get_assertion_params::{Extension, GetAssertionArgsBuilder};

impl FidoKeyHid {
    /// Authentication command(with PIN , non Resident Key)
    pub fn get_assertion(
        &self,
        rpid: &str,
        challenge: &[u8],
        credential_ids: &[Vec<u8>],
        pin: Option<&str>,
    ) -> Result<Assertion> {
        let asss = self.get_assertion_internal(
            rpid,
            challenge,
            credential_ids,
            pin,
            true,
            should_uv(pin),
            None,
        )?;
        Ok(asss[0].clone())
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
        let asss = self.get_assertion_internal(
            rpid,
            challenge,
            credential_ids,
            pin,
            true,
            should_uv(pin),
            extensions,
        )?;
        Ok(asss[0].clone())
    }

    /// Authentication command(with PIN , Resident Key)
    pub fn get_assertions_rk(
        &self,
        rpid: &str,
        challenge: &[u8],
        pin: Option<&str>,
    ) -> Result<Vec<Assertion>> {
        let dmy: Vec<Vec<u8>> = vec![];
        self.get_assertion_internal(rpid, challenge, &dmy, pin, true, should_uv(pin), None)
    }

    /// Create a new assertion manually specifying the args using GetAssertionArgs
    pub fn get_assertion_with_args(&self, args: &GetAssertionArgs) -> Result<Vec<Assertion>> {
        let dummy_credentials; // TODO ???
        let credential_ids = if args.credential_ids.len() > 0 {
            &args.credential_ids
        } else {
            // TODO ???
            dummy_credentials = vec![];
            &dummy_credentials
        };

        let extensions = if args.extensions.is_some() {
            Some(args.extensions.as_ref().unwrap())
        } else {
            None
        };

        let asss = self.get_assertion_internal(
            &args.rpid,
            &args.challenge,
            credential_ids,
            args.pin,
            true,
            args.uv,
            extensions,
        )?;

        Ok(asss)
    }

    fn get_assertion_internal(
        &self,
        rpid: &str,
        challenge: &[u8],
        credential_ids: &[Vec<u8>],
        pin: Option<&str>,
        up: bool,
        uv: Option<bool>,
        extensions: Option<&Vec<Gext>>,
    ) -> Result<Vec<Assertion>> {
        // init
        let cid = ctaphid::ctaphid_init(&self).map_err(Error::msg)?;

        let hmac_ext = create_hmacext(&self, &cid, extensions)?;

        // pin token
        let pin_token = {
            if let Some(pin) = pin {
                Some(self.get_pin_token(&cid, pin)?)
            } else {
                None
            }
        };

        // create cmmand
        let send_payload = {
            let mut params = get_assertion_command::Params::new(
                rpid,
                challenge.to_vec(),
                credential_ids.to_vec(),
            );
            params.option_up = up;
            params.option_uv = uv;

            // create pin auth
            if let Some(pin_token) = pin_token {
                let sig = enc_hmac_sha_256::authenticate(&pin_token.key, &params.client_data_hash);
                params.pin_auth = sig[0..16].to_vec();
            }

            get_assertion_command::create_payload(params, hmac_ext.clone())
        };

        // send & response
        let response_cbor =
            ctaphid::ctaphid_cbor(&self, &cid, &send_payload).map_err(Error::msg)?;

        let ass = get_assertion_response::parse_cbor(
            &response_cbor,
            hmac_ext.map(|ext| ext.shared_secret),
        )
        .map_err(Error::msg)?;

        let mut asss = vec![ass];
        for _ in 0..(asss[0].number_of_credentials - 1) {
            let ass = get_next_assertion(&self, &cid).map_err(Error::msg)?;
            asss.push(ass);
        }

        Ok(asss)
    }
}

fn get_next_assertion(device: &FidoKeyHid, cid: &[u8]) -> Result<Assertion, String> {
    let send_payload = get_next_assertion_command::create_payload();
    let response_cbor = ctaphid::ctaphid_cbor(device, cid, &send_payload)?;
    get_assertion_response::parse_cbor(&response_cbor, None)
}

fn create_hmacext(
    device: &FidoKeyHid,
    cid: &[u8; 4],
    extensions: Option<&Vec<Gext>>,
) -> Result<Option<HmacExt>> {
    if let Some(extensions) = extensions {
        for ext in extensions {
            match ext {
                Gext::HmacSecret(n) => {
                    let mut hmac_ext = HmacExt::default();
                    hmac_ext.create(device, cid, &n.unwrap(), None)?;
                    return Ok(Some(hmac_ext));
                }
            }
        }
        Ok(None)
    } else {
        Ok(None)
    }
}
