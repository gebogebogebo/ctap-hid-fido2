pub mod large_blobs_command;
pub mod large_blobs_params;
pub mod large_blobs_response;

use super::FidoKeyHid;
use crate::ctaphid;
use anyhow::{Error, Result};
use large_blobs_params::LargeBlobData;

impl FidoKeyHid {
    pub fn large_blobs(
        &self,
        pin: Option<&str>,
        offset: u32,
        get: Option<u32>,
        set: Option<Vec<u8>>,
    ) -> Result<LargeBlobData> {

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

        large_blobs_response::parse_cbor(&response_cbor)
    }
}
