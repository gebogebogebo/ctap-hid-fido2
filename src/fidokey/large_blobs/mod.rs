pub mod large_blobs_command;
pub mod large_blobs_params;
pub mod large_blobs_response;

use anyhow::{Error, Result};
use crate::ctaphid;
use super::FidoKeyHid;

impl FidoKeyHid {
    pub fn large_blobs(&self, _pin: Option<&str>, _get: bool, _offset: i32) -> Result<String> {
        //   let pin = if let Some(v) = pin {
        //       v
        //   } else {
        //       return Err(anyhow!("need PIN."));
        //   };

        // TODO
        // let data = vec![0x80];
        // let hash = digest::digest(&digest::SHA256, &data);
        // let message = &hash.as_ref()[0..16];
        // println!("{:?}",util::to_hex_str(message));

        let cid = ctaphid::ctaphid_init(self).map_err(Error::msg)?;

        // get pintoken
        // let pin_token =
        //     self.get_pinuv_auth_token_with_permission(&cid, pin, super::pin::Permission::Acfg)?;

        let send_payload = large_blobs_command::create_payload(None)?;
        let response_cbor =
            ctaphid::ctaphid_cbor(self, &cid, &send_payload).map_err(Error::msg)?;

        let large_blob_data = large_blobs_response::parse_cbor(&response_cbor)?;

        Ok("".to_string())
    }
}
