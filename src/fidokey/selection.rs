use super::FidoKeyHid;
use crate::{ctapdef, ctaphid};
use anyhow::Result;

fn create_payload() -> Vec<u8> {
    // 6.9. authenticatorSelection (0x0B)
    vec![ctapdef::AUTHENTICATOR_SELECTION]
}

impl FidoKeyHid {
    /// Selection (CTAP 2.1)
    pub fn selection(&self) -> Result<([u8; 4], String)> {
        let cid = ctaphid::ctaphid_init(self)?;
        let send_payload = create_payload();
        let _response_cbor = ctaphid::ctaphid_cbor(self, &send_payload)?;
        Ok((cid, "".to_string()))
    }

    pub fn cancel_selection(&self, cid_to_cancel: &[u8]) -> Result<()> {
        ctaphid::ctaphid_cancel(self, cid_to_cancel)
    }
}
