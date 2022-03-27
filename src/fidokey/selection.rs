use crate::{
    ctapdef,
    ctaphid,
};

use super::FidoKeyHid;

use anyhow::{Error, Result};

fn create_payload() -> Vec<u8> {
    // 6.9. authenticatorSelection (0x0B)
    vec![ctapdef::AUTHENTICATOR_SELECTION]
}

impl FidoKeyHid {
    /// Selection (CTAP 2.1)
    pub fn selection(&self) -> Result<String> {
        let cid = ctaphid::ctaphid_init(&self).map_err(Error::msg)?;
        let send_payload = create_payload();
        let _response_cbor = ctaphid::ctaphid_cbor(&self, &cid, &send_payload).map_err(Error::msg)?;
        Ok("".to_string())
    }
}