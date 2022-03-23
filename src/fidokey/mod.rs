use crate::{
    HidInfo,
    HidParam
};
use crate::str_buf::StrBuf;
use hidapi::HidApi;

use std::ffi::CString;

mod get_info;
pub mod pin;

pub struct FidoKeyHid {
    device_internal: hidapi::HidDevice,
    pub enable_log: bool,
    pub use_pre_bio_enrollment: bool,
    pub use_pre_credential_management: bool,
    pub keep_alive_msg: String,
}

impl FidoKeyHid {
    pub fn new(params: &[crate::HidParam], cfg: &crate::LibCfg) -> Result<FidoKeyHid, String> {
        let api = HidApi::new().expect("Failed to create HidApi instance");
        for param in params {
            let path = get_path(&api, &param);
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
                };
                return Ok(result);
            }
        }
        Err("Failed to open device.".into())
    }

    pub fn get_hid_devices(usage_page: Option<u16>) -> Vec<HidInfo> {
        let api = HidApi::new().expect("Failed to create HidAPI instance");
        let mut res = vec![];

        let devices = api.device_list();
        for dev in devices {
            if usage_page == None || dev.usage_page() == usage_page.unwrap() {
                let mut memo = StrBuf::new(0);

                if let Some(n) = dev.product_string() {
                    memo.add("product=");
                    memo.add(n);
                }
                memo.add(" usage_page=");
                memo.add(&dev.usage_page().to_string());

                memo.add(" usage=");
                memo.add(&dev.usage().to_string());

                if let Some(n) = dev.serial_number() {
                    memo.add(" serial_number=");
                    memo.add(n);
                }

                memo.add(format!(" path={:?}", dev.path()).as_str());

                let param = match dev.path().to_str() {
                    Ok(s) => HidParam::Path(s.to_string()),
                    _ => HidParam::VidPid { vid: dev.vendor_id(), pid: dev.product_id() },
                };

                res.push(HidInfo {
                    pid: dev.product_id(),
                    vid: dev.vendor_id(),
                    product_string: dev.product_string().unwrap_or_default().to_string(),
                    info: memo.build().to_string(),
                    param,
                });
            }
        }
        res
    }

    pub fn write(&self, cmd: &[u8]) -> Result<usize, String> {
        match self.device_internal.write(cmd) {
            Ok(size) => Ok(size),
            Err(_) => Err("write error".into()),
        }
    }

    pub fn read(&self) -> Result<Vec<u8>, String> {
        let mut buf: Vec<u8> = vec![0; 64];
        match self.device_internal.read(&mut buf[..]) {
            Ok(_) => Ok(buf),
            Err(_) => Err("read error".into()),
        }
    }
}

/// Abstraction for getting a path from a provided HidParam
fn get_path(
    api: &hidapi::HidApi,
    param: &crate::HidParam,
) -> Option<CString> {
    let devices = api.device_list();
    for x in devices.cloned() {
        match param {
            HidParam::Path(s) => {
                let c_path = CString::new(s.as_bytes());
                if c_path.is_err() {
                    return None
                }
                let c_path = c_path.unwrap();
                if c_path.as_c_str() == x.path() {
                    return Some(c_path)
                }
            },
            HidParam::VidPid { vid, pid } =>  {
                if x.vendor_id() == *vid && x.product_id() == *pid {
                    return Some(x.path().to_owned());
                }
            },
        };
    }
    None
}


