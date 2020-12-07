use hidapi::HidApi;

pub struct FidoKeyHid {
    pub device: hidapi::HidDevice,    
}

impl FidoKeyHid {

    pub fn new(params: &[crate::HidParam])->Result<FidoKeyHid,&'static str> {
        let api = HidApi::new().expect("Failed to create HidApi instance");
        for param in params {
            if let Some(dev_info) = FidoKeyHid::get_path(&api, &param, 0xf1d0) {
                if let Ok(dev) = api.open_path(&dev_info.path()) {
                    let result = FidoKeyHid {
                        device: dev,
                    };
                    return Ok(result);
                }
            }    
        }
        Err("Failed to open device")
    }

    fn get_path(
        api: &hidapi::HidApi,
        param: &crate::HidParam,
        usage_page: u16,
    ) -> Option<hidapi::DeviceInfo> {
        let devices = api.device_list();
        for x in devices.cloned() {
            if x.vendor_id() == param.vid && x.product_id() == param.pid && x.usage_page() == usage_page
            {
                return Some(x);
            }
        }
        None
    }

    #[allow(deprecated)]
    pub fn get_hid_devices(usage_page: Option<u16>) -> Vec<(String, crate::HidParam)> {
        let api = HidApi::new().expect("Failed to create AcaPI instance");
        let mut res = vec![];
    
        let devices = api.devices();
        for dev in devices.clone() {
            if usage_page == None || usage_page.unwrap() == dev.usage_page {
                let mut memo = "".to_string();
                if let Some(n) = dev.product_string {
                    memo = n.to_string();
                }
    
                res.push((
                    memo,
                    crate::HidParam {
                        vid: dev.vendor_id,
                        pid: dev.product_id,
                    },
                ));
            }
    
            //println!("product_string = {:?}", dev.product_string);
            //println!("- vendor_id = 0x{:2x}", dev.vendor_id);
            //println!("- product_id = 0x{:2x}", dev.product_id);
        }
        res
    }
    
    pub fn write(&self, cmd: &[u8]) -> Result<usize,std::io::Error> {
        Ok(self.device.write(cmd).unwrap())
    }

    pub fn read(&self) -> Result<Vec<u8>, &'static str> {
        let mut buf: Vec<u8> = vec![0; 64];
        match self.device.read(&mut buf[..]) {
            Ok(_) => Ok(buf),
            Err(_) => Err("read error"),
        }
    }

}