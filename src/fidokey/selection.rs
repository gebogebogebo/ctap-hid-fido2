use super::FidoKeyHid;
#[cfg(feature = "tokio")]use super::FidoKeyHidAsync;
use crate::{ctapdef, ctaphid};
use anyhow::Result;

fn create_payload() -> Vec<u8> {
    // 6.9. authenticatorSelection (0x0B)
    vec![ctapdef::AUTHENTICATOR_SELECTION]
}

impl FidoKeyHid {
    /// Selection (CTAP 2.1)
    pub fn selection(&self) -> Result<()> {
        let send_payload = create_payload();
        let _response_cbor = ctaphid::ctaphid_cbor(self, &send_payload)?;
        Ok(())
    }

    pub fn cancel_selection(&self) -> Result<()> {
        ctaphid::ctaphid_cancel(self)
    }
}

#[cfg(feature = "tokio")]impl FidoKeyHidAsync {
    /// Selection (CTAP 2.1)
    pub async fn selection(&self) -> Result<()> {
        let send_payload = create_payload();
        let _response_cbor = ctaphid::ctaphid_cbor_async(self, &send_payload).await?;
        Ok(())
    }

    pub async fn cancel_selection(&self) -> Result<()> {
        ctaphid::ctaphid_cancel_async(self).await
    }
}
