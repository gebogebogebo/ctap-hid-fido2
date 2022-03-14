use std::fs;
use std::io::Read;
use std::io::Write;

use crate::hid_linux;

pub struct FidoKeyHid {
    pub device_internal: std::fs::File,
    pub enable_log: bool,
    pub use_pre_bio_enrollment: bool,
    pub use_pre_credential_management: bool,
    pub keep_alive_msg: String,
}

impl FidoKeyHid {
    pub fn new(_params: &[crate::HidParam], cfg: &crate::LibCfg) -> Result<FidoKeyHid, String> {
        match hid_linux::enumerate() {
            Ok(devs) => {
                for dev in devs {
                    if dev.usage_page == 0xf1d0 {
                        // open
                        let mut options = fs::OpenOptions::new();
                        options.read(true).write(true);

                        let result = FidoKeyHid {
                            device_internal: options.open(&dev.path).unwrap(),
                            enable_log: cfg.enable_log,
                            use_pre_bio_enrollment: cfg.use_pre_bio_enrollment,
                            use_pre_credential_management: cfg.use_pre_credential_management,
                            keep_alive_msg: cfg.keep_alive_msg.to_string(),
                        };
                        return Ok(result);
                    }
                }
            }
            Err(_e) => {
                return Err("new Error".into());
            }
        };
        Err("Failed to open device".into())
    }

    pub fn get_hid_devices(usage_page: Option<u16>) -> Vec<(String, crate::HidParam)> {
        let mut res = vec![];

        match hid_linux::enumerate() {
            Ok(devs) => {
                //println!("devs.count={}",devs.count());
                for dev in devs {
                    //println!("dev.usage_page=0x{:x}",dev.usage_page);
                    //println!("dev.usage=0x{:x}",dev.usage);
                    //println!("dev.path={:?}",dev.path);

                    if usage_page == None || usage_page.unwrap() == dev.usage_page {
                        let memo = dev.path.into_os_string().into_string().unwrap();

                        res.push((
                            memo,
                            crate::HidParam {
                                vid: 0x00,
                                pid: 0x00,
                            },
                        ));

                        //println!("push");
                    }
                }
            }
            Err(_e) => {
                println!("e");
                return res;
            }
        };

        res
    }

    pub fn write(&self, cmd: &[u8]) -> Result<usize, String> {
        let mut dev = &self.device_internal;
        match dev.write_all(cmd) {
            Ok(_) => Ok(0),
            Err(_) => Err("write error".into()),
        }
    }

    pub fn read(&self) -> Result<Vec<u8>, String> {
        let mut dev = &self.device_internal;

        let mut buf = Vec::with_capacity(64);
        buf.resize(64, 0);
        match dev.read_exact(&mut buf[0..64]) {
            Ok(_) => Ok(buf),
            Err(_) => Err("read error".into()),
        }
    }
}
