use crate::HidParam;
use anyhow::{anyhow, Result};
use hidapi::HidApi;
use std::ffi::CString;
use std::sync::Mutex;
#[cfg(feature = "tokio")]use tokio::sync::Mutex as TMutex;

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
    device_internal: Mutex<hidapi::HidDevice>,
    pub enable_log: bool,
    pub use_pre_bio_enrollment: bool,
    pub use_pre_credential_management: bool,
    pub keep_alive_msg: String,
    cid: Mutex<Option<[u8; 4]>>,
}

impl FidoKeyHid {
    pub fn new(params: &[crate::HidParam], cfg: &crate::LibCfg) -> Result<Self> {
        Ok(FidoKeyHid {
            device_internal: Mutex::new(open_fido_key_hid(&params)?), // Wrap in Mutex
            enable_log: cfg.enable_log,
            use_pre_bio_enrollment: cfg.use_pre_bio_enrollment,
            use_pre_credential_management: cfg.use_pre_credential_management,
            keep_alive_msg: cfg.keep_alive_msg.to_string(),
            cid: Mutex::new(None), // Wrap in Mutex
        })
    }

    pub(crate) fn write(&self, cmd: &[u8]) -> Result<usize, String> {
        let device = self.device_internal.lock().map_err(|e| e.to_string())?;
        match device.write(cmd) {
            Ok(size) => Ok(size),
            Err(_) => Err("write error".into()),
        }
    }

    pub(crate) fn read(&self) -> Result<Vec<u8>, String> {
        let mut buf: Vec<u8> = vec![0; 64];
        let device = self.device_internal.lock().map_err(|e| e.to_string())?;
        match device.read(&mut buf[..]) {
            Ok(_) => Ok(buf),
            Err(_) => Err("read error".into()),
        }
    }
    
    // init or get CID
    pub fn get_cid(&self) -> Result<[u8; 4]> {
        let mut cid_guard = self.cid.lock().map_err(|e| anyhow!(e.to_string()))?;
        // get
        if let Some(cid_val) = *cid_guard {
            return Ok(cid_val);
        }

        // init
        // Temporarily unlock to call ctaphid_init, which might call get_cid again (though unlikely here)
        // or other methods on self that also lock cid.
        // A more robust solution might involve passing the locked guard or restructuring.
        // However, for this specific case, ctaphid_init doesn't seem to re-enter get_cid.
        // Drop(cid_guard); // Explicitly drop before re-acquiring or calling other methods that might lock
        
        // Since ctaphid_init takes &self, and self.cid is already locked,
        // we need to be careful. However, ctaphid_init itself doesn't use self.cid.
        // It uses self.write and self.read which lock device_internal.
        // So, this should be fine.
        let new_cid = crate::ctaphid::ctaphid_init(self)?;
        *cid_guard = Some(new_cid);
        Ok(new_cid)
    }
}

#[cfg(feature = "tokio")]pub struct FidoKeyHidAsync {
    device_internal: TMutex<hidapi::HidDevice>,
    pub enable_log: bool,
    pub use_pre_bio_enrollment: bool,
    pub use_pre_credential_management: bool,
    pub keep_alive_msg: String,
    cid: TMutex<Option<[u8; 4]>>,
}

#[cfg(feature = "tokio")]impl FidoKeyHidAsync {
    pub async fn new(params: &[crate::HidParam], cfg: &crate::LibCfg) -> Result<Self> {
        let params = params.to_owned();
        let cfg = cfg.to_owned();
        tokio::task::spawn_blocking(move||{
            Ok(FidoKeyHidAsync {
                device_internal: TMutex::new(open_fido_key_hid(&params)?), // Wrap in (Tokio) Mutex
                enable_log: cfg.enable_log,
                use_pre_bio_enrollment: cfg.use_pre_bio_enrollment,
                use_pre_credential_management: cfg.use_pre_credential_management,
                keep_alive_msg: cfg.keep_alive_msg.to_string(),
                cid: TMutex::new(None), // Wrap in (Tokio) Mutex
            })
        }).await.map_err(anyhow::Error::msg)?
    }

    pub(crate) async fn write(&self, cmd: &[u8]) -> Result<usize, String> {
        let device = self.device_internal.lock().await;
        match device.write(cmd) {
            Ok(size) => Ok(size),
            Err(_) => Err("write error".into()),
        }
    }

    pub(crate) async fn read(&self) -> Result<Vec<u8>, String> {
        let mut buf: Vec<u8> = vec![0; 64];
        let device = self.device_internal.lock().await;
        match device.read(&mut buf[..]) {
            Ok(_) => Ok(buf),
            Err(_) => Err("read error".into()),
        }
    }
    
    // init or get CID
    pub async fn get_cid(&self) -> Result<[u8; 4]> {
        let mut cid_guard = self.cid.lock().await;
        // get
        if let Some(cid_val) = *cid_guard {
            return Ok(cid_val);
        }

        // init
        // Temporarily unlock to call ctaphid_init, which might call get_cid again (though unlikely here)
        // or other methods on self that also lock cid.
        // A more robust solution might involve passing the locked guard or restructuring.
        // However, for this specific case, ctaphid_init doesn't seem to re-enter get_cid.
        // Drop(cid_guard); // Explicitly drop before re-acquiring or calling other methods that might lock
        
        // Since ctaphid_init takes &self, and self.cid is already locked,
        // we need to be careful. However, ctaphid_init itself doesn't use self.cid.
        // It uses self.write and self.read which lock device_internal.
        // So, this should be fine.
        let new_cid = crate::ctaphid::ctaphid_init_async(self).await?;
        *cid_guard = Some(new_cid);
        Ok(new_cid)
    }
}

/// Common function for sync and async FidoKeyHid
fn open_fido_key_hid(params: &[crate::HidParam])->Result<hidapi::HidDevice>{
    let api = HidApi::new().expect("Failed to create HidApi instance");
    for param in params {
        let path = get_path(&api, param);
        if path.is_none() {
            continue;
        }

        if let Ok(dev) = api.open_path(&path.unwrap()) {
            return Ok(dev);
        }
    }
    Err(anyhow!("Failed to open device."))
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
