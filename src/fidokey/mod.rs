use crate::str_buf::StrBuf;
use hidapi::HidApi;

use std::ffi::CString;

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
            let path = match &param.path {
                Some(p) => CString::new(p.as_bytes()).map_err(|_| format!("Path cannot contain null bytes"))?,
                None => {
                    if let Some(dev_info) = FidoKeyHid::get_path(&api, param, 0xf1d0) {
                        dev_info.path().to_owned()
                    } else {
                        continue;
                    }
                },
            };

            if let Ok(dev) = api.open_path(&path) {
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

    fn get_path(
        api: &hidapi::HidApi,
        param: &crate::HidParam,
        usage_page: u16,
    ) -> Option<hidapi::DeviceInfo> {
        let devices = api.device_list();
        for x in devices.cloned() {
            if x.vendor_id() == param.vid
                && x.product_id() == param.pid
                && x.usage_page() == usage_page
            {
                return Some(x);
            }
        }
        None
    }

    pub fn get_hid_devices(usage_page: Option<u16>) -> Vec<(String, crate::HidParam)> {
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

                let path = match dev.path().to_str() {
                    Ok(s) => Some(s.to_owned()),
                    _ => None,
                };

                res.push((
                    memo.build().to_string(),
                    crate::HidParam {
                        vid: dev.vendor_id(),
                        pid: dev.product_id(),
                        path,
                    },
                ));
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

    /// We assume the reading mode will be blocking, so we just change it to non blocking
    /// and set it back to blocking after. This is technically incorrect because it will 
    /// change the state if it was already non-blocking, but if that's the case, you
    /// could just use the read api.
    pub fn read_non_blocking(&self) -> Result<Vec<u8>, String> {
        self.device_internal.set_blocking_mode(false).map_err(|_| format!("Could not set non blocking mode"))?;
        let mut buf: Vec<u8> = vec![0; 64];
        let res = match self.device_internal.read(&mut buf[..]) {
            Ok(0) => Ok(vec![]),
            Ok(n) => Ok(buf),
            Err(_) => Err("read error".into()),
        };

        self.device_internal.set_blocking_mode(true).map_err(|_| format!("Could not set non blocking mode"))?;
        res
    }

    pub fn read(&self) -> Result<Vec<u8>, String> {
        let mut buf: Vec<u8> = vec![0; 64];
        match self.device_internal.read(&mut buf[..]) {
            Ok(_) => Ok(buf),
            Err(_) => Err("read error".into()),
        }
    }
}
