// This file is part of ctap, a Rust implementation of the FIDO2 protocol.
// Copyright (c) Ariën Holthuizen <contact@ardaxi.com>
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use std::path::PathBuf;

use hidapi::HidApi;

use crate::HidParam;
use crate::str_buf::StrBuf;

#[derive(Debug, Clone)]
/// Storage for device related information
pub struct DeviceInfo {
    pub path: PathBuf,
    pub usage_page: u16,
    pub usage: u16,
    pub report_size: u16,
}


pub fn get_hid_devices(usage_page: Option<u16>) -> Vec<(String, HidParam)> {
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