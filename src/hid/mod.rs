// This file is part of ctap, a Rust implementation of the FIDO2 protocol.
// Copyright (c) Ariën Holthuizen <contact@ardaxi.com>
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use std::path::PathBuf;

use hidapi::HidApi;

use crate::str_buf::StrBuf;

#[derive(Debug, Clone)]
/// Storage for device related information
pub struct DeviceInfo {
    pub path: PathBuf,
    pub usage_page: u16,
    pub usage: u16,
    pub report_size: u16,
}

/// HID device vendor ID , product ID
#[derive(Clone)]
pub enum HidParam {
    /// Specified when looking for any FIDO device of a certain kind
    VidPid {vid: u16, pid: u16},
    /// Specified when looking to open a specific device. This is non-ambiguous
    /// when multiple devices of the same kind are connected.
    Path(String),
}

/// Struct that contains information about found HID devices. Also
/// contains a HidParam which can be used to lookup the device
/// later.
#[derive(Clone)]
pub struct HidInfo {
    /// Product ID
    pub pid: u16,
    /// Vendor ID
    pub vid: u16,
    /// A string describing the device provided by the device
    pub product_string: String,
    /// A generic information string build by this crate
    pub info: String,
    /// An parameter structure to be used to open this device
    /// later. This is almost always HidParam::Path.
    pub param: HidParam,
}

impl HidParam {
    /// Generate HID parameters for FIDO key devices
    pub fn get() -> Vec<HidParam> {
        vec![
            HidParam::VidPid { vid: 0x1050, pid: 0x0402 },  // Yubikey 4/5 U2F
            HidParam::VidPid { vid: 0x1050, pid: 0x0407 },  // Yubikey 4/5 OTP+U2F+CCID
            HidParam::VidPid { vid: 0x1050, pid: 0x0120 },  // Yubikey Touch U2F
            HidParam::VidPid { vid: 0x096E, pid: 0x085D },  // Biopass
            HidParam::VidPid { vid: 0x096E, pid: 0x0866 },  // All in pass
            HidParam::VidPid { vid: 0x0483, pid: 0xA2CA },  // Solokey 
            HidParam::VidPid { vid: 0x096E, pid: 0x0858 },  // ePass FIDO(A4B)
            HidParam::VidPid { vid: 0x20a0, pid: 0x42b1 },  // Nitrokey FIDO2 2.0.0
            HidParam::VidPid { vid: 0x32a3, pid: 0x3201 },  // Idem Key
        ]
    }
    pub fn auto() -> Vec<HidParam> {
        vec![]
    }
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
