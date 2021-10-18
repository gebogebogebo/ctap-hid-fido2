use crate::str_buf::StrBuf;
use hidapi::HidApi;

pub struct FidoKeyHid {
    device_internal: hidapi::HidDevice,
    pub enable_log: bool,
    pub use_pre_bio_enrollment: bool,
    pub use_pre_credential_management: bool,
}

impl FidoKeyHid {
    pub fn new(params: &[crate::HidParam],cfg: &crate::LibCfg) -> Result<FidoKeyHid, String> {
        let api = HidApi::new().expect("Failed to create HidApi instance");
        for param in params {
            if let Some(dev_info) = FidoKeyHid::get_path(&api, param, 0xf1d0) {
                if let Ok(dev) = api.open_path(dev_info.path()) {
                    let result = FidoKeyHid {
                        device_internal: dev,
                        enable_log: cfg.enable_log,
                        use_pre_bio_enrollment: cfg.use_pre_bio_enrollment,
                        use_pre_credential_management: cfg.use_pre_credential_management,
                    };
                    return Ok(result);
                }
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
        let api = HidApi::new().expect("Failed to create AcaPI instance");
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

                res.push((
                    memo.build().to_string(),
                    crate::HidParam {
                        vid: dev.vendor_id(),
                        pid: dev.product_id(),
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

    pub fn read(&self) -> Result<Vec<u8>, String> {
        let mut buf: Vec<u8> = vec![0; 64];
        match self.device_internal.read(&mut buf[..]) {
            Ok(_) => Ok(buf),
            Err(_) => Err("read error".into()),
        }
    }
}
