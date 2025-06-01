use crate::HidParam;
use anyhow::{anyhow, Result};
use hidapi::HidApi;
use std::ffi::CString;
use std::cell::Cell;

// Complex Submodules
pub mod authenticator_config;
pub mod bio;
pub mod common;
pub mod credential_management;
pub mod get_assertion;
pub mod get_info;
pub mod large_blobs;
pub mod make_credential;
pub mod pin;

// Simple Submodules
mod selection;
mod sub_command_base;
mod wink;

pub use get_assertion::{Extension as AssertionExtension, GetAssertionArgsBuilder};

pub use make_credential::{
    CredentialSupportedKeyType, Extension as CredentialExtension, MakeCredentialArgsBuilder,
};

pub struct FidoKeyHid {
    device_internal: hidapi::HidDevice,
    pub enable_log: bool,
    pub use_pre_bio_enrollment: bool,
    pub use_pre_credential_management: bool,
    pub keep_alive_msg: String,
    cid: Cell<Option<[u8; 4]>>,
}

impl FidoKeyHid {
    pub fn new(params: &[crate::HidParam], cfg: &crate::LibCfg) -> Result<Self> {
        let api = HidApi::new().expect("Failed to create HidApi instance");
        for param in params {
            let path = get_path(&api, param);
            if path.is_none() {
                continue;
            }

            if let Ok(dev) = api.open_path(&path.unwrap()) {
                let result = FidoKeyHid {
                    device_internal: dev,
                    enable_log: cfg.enable_log,
                    use_pre_bio_enrollment: cfg.use_pre_bio_enrollment,
                    use_pre_credential_management: cfg.use_pre_credential_management,
                    keep_alive_msg: cfg.keep_alive_msg.to_string(),
                    cid: Cell::new(None),
                };
                return Ok(result);
            }
        }
        Err(anyhow!("Failed to open device."))
    }

    pub(crate) fn write(&self, cmd: &[u8]) -> Result<usize, String> {
        match self.device_internal.write(cmd) {
            Ok(size) => Ok(size),
            Err(_) => Err("write error".into()),
        }
    }

    pub(crate) fn read(&self) -> Result<Vec<u8>, String> {
        let mut buf: Vec<u8> = vec![0; 64];
        match self.device_internal.read(&mut buf[..]) {
            Ok(_) => Ok(buf),
            Err(_) => Err("read error".into()),
        }
    }
    
    // init or get CID
    pub fn get_cid(&self) -> Result<[u8; 4]> {
        // get
        if let Some(cid) = self.cid.get() {
            return Ok(cid);
        }

        // init
        let cid = crate::ctaphid::ctaphid_init(self)?;
        self.cid.set(Some(cid));
        Ok(cid)
    }
}

/// Abstraction for getting a path from a provided HidParam
fn get_path(api: &hidapi::HidApi, param: &crate::HidParam) -> Option<CString> {
    match param {
        HidParam::Path(s) => {
            if let Ok(p) = CString::new(s.as_bytes()) {
                return Some(p);
            }
        }
        HidParam::VidPid { vid, pid } => {
            let devices = api.device_list();
            for x in devices {
                if x.vendor_id() == *vid && x.product_id() == *pid {
                    return Some(x.path().to_owned());
                }
            }
        }
    };

    None
}
