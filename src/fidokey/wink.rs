use crate::ctaphid;

use super::FidoKeyHid;

use anyhow::{Error, Result};

impl FidoKeyHid {
    /// Lights the LED on the FIDO key
    pub fn wink(&self) -> Result<()> {
        let cid = ctaphid::ctaphid_init(self)?;
        ctaphid::ctaphid_wink(self, &cid).map_err(Error::msg)
    }
}
