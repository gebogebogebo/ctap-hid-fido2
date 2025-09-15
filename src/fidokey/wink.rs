use super::FidoKeyHid;
#[cfg(feature = "tokio")]use super::FidoKeyHidAsync;
use crate::ctaphid;
use anyhow::Result;

impl FidoKeyHid {
    /// Lights the LED on the FIDO key
    pub fn wink(&self) -> Result<()> {
        ctaphid::ctaphid_wink(self)
    }
}

#[cfg(feature = "tokio")]impl FidoKeyHidAsync {
    /// Lights the LED on the FIDO key
    pub async fn wink(&self) -> Result<()> {
        ctaphid::ctaphid_wink_async(self).await
    }
}