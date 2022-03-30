use hidapi::HidApi;

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
            if let Some(dev_info) = FidoKeyHid::get_path(&api, param, 0xf1d0) {
                if let Ok(dev) = api.open_path(dev_info.path()) {
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
