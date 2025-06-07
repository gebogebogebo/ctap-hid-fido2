use super::FidoKeyHid;
use crate::ctaphid;
use anyhow::Result;

impl FidoKeyHid {
    /// Lights the LED on the FIDO key
    pub fn wink(&self) -> Result<()> {
        ctaphid::ctaphid_wink(self)
    }
}
