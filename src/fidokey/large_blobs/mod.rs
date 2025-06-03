pub mod large_blobs_command;
pub mod large_blobs_params;
pub mod large_blobs_response;
use super::FidoKeyHid;
use crate::ctaphid;
use anyhow::Result;
use large_blobs_params::LargeBlobData;

impl FidoKeyHid {
    pub fn get_large_blob(&self) -> Result<LargeBlobData> {
        let offset = 0; // TODO
        let read_bytes = 1024; // TODO
        self.large_blobs(None, offset, Some(read_bytes), None)
    }

    pub fn write_large_blob(
        &self,
        pin: Option<&str>,
        write_datas: Vec<u8>,
    ) -> Result<LargeBlobData> {
        let offset = 0; // TODO
        self.large_blobs(pin, offset, None, Some(write_datas))
    }

    fn large_blobs(
        &self,
        pin: Option<&str>,
        offset: u32,
        get: Option<u32>,
        set: Option<Vec<u8>>,
    ) -> Result<LargeBlobData> {
        let cid = ctaphid::ctaphid_init(self)?;

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
        let response_cbor = ctaphid::ctaphid_cbor(self, &send_payload)?;

        large_blobs_response::parse_cbor(&response_cbor)
    }
}
