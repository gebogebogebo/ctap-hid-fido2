pub mod large_blobs_command;
pub mod large_blobs_params;
pub mod large_blobs_response;

use super::FidoKeyHid;
use crate::ctaphid;
use anyhow::{Error, Result};

impl FidoKeyHid {
    pub fn large_blobs(
        &self,
        pin: Option<&str>,
        offset: u32,
        get: Option<i32>,
        set: Option<Vec<u8>>,
    ) -> Result<String> {
        // TODO
        // let data = vec![0x80];
        // let hash = digest::digest(&digest::SHA256, &data);
        // let message = &hash.as_ref()[0..16];
        // println!("{:?}",util::to_hex_str(message));

        let cid = ctaphid::ctaphid_init(self).map_err(Error::msg)?;

        // get pintoken
        let pin_token = if let Some(pin) = pin {
            Some(self.get_pinuv_auth_token_with_permission(
                &cid,
                pin,
                super::pin::Permission::LargeBlobWrite,
            )?)
        } else {
            None
        };

        let send_payload = large_blobs_command::create_payload(pin_token, offset, get, set)?;
        let response_cbor = ctaphid::ctaphid_cbor(self, &cid, &send_payload).map_err(Error::msg)?;

        let _large_blob_data = large_blobs_response::parse_cbor(&response_cbor)?;

        Ok("".to_string())
    }
}
