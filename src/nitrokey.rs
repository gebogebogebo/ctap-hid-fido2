/*!
## Nitrokey Custom Commands
for Nitrokey FIDO2 only.
*/
use anyhow::{Error, Result};

#[allow(unused_imports)]
use crate::util;

use crate::ctaphid;
use crate::ctapihd_nitro;
use crate::Cfg;

#[derive(Debug)]
pub enum ButtonStateT {
    /// wait for the charge to settle down
    BstInitializing,
    /// ready for clearing
    BstInitializingReadyToClear,
    /// META state (never used), to ease testing,if button is ready (e.g. >READY) or not (<READY)
    BstMetaReadyToUse,
    /// ready to use
    BstUnpressed,
    /// touch registration is started
    BstPressedRecently,
    /// touch registered, normal press period
    BstPressedRegistered,
    /// touch registered, normal press, but timeouted
    BstPressedRegisteredTransitional,
    /// touch registered, extended press period
    BstPressedRegisteredExt,
    /// touch registered, extended press period, invalidated
    BstPressedRegisteredExtInvalid,
    /// BST_PRESSED_CONSUMED, but accepts requests
    BstPressedConsumedActive,
    /// touch registered and consumed, button still not released, does not accept requests
    BstPressedConsumed,
    BstMaxNum,
}
impl Default for ButtonStateT {
    fn default() -> Self {
        ButtonStateT::BstInitializing
    }
}

/// Result of get_status().
#[derive(Debug, Default)]
pub struct NitrokeyStatus {
    pub is_button_pressed_raw: bool,
    pub button_state: u8,
    pub button_state_t: ButtonStateT,
    pub last_button_cleared_time_delta: u8,
    pub last_button_pushed_time_delta: u8,
    pub led_is_blinking: bool,
    pub u2f_ms_clear_button_period: u8,
    pub u2f_ms_init_button_period: u8,
    pub button_min_press_t_ms: u8,
}

impl NitrokeyStatus {
    #[allow(dead_code)]
    pub fn print(self: &NitrokeyStatus, title: &str) {
        println!("{}", title);
        println!(
            "- is_button_pressed_raw          = {:?}",
            self.is_button_pressed_raw
        );
        println!("- button_state                   = {:?}", self.button_state);
        println!(
            "- button_state                   = {:?}",
            self.button_state_t
        );
        println!(
            "- last_button_cleared_time_delta = {:?}",
            self.last_button_cleared_time_delta
        );
        println!(
            "- last_button_pushed_time_delta  = {:?}",
            self.last_button_pushed_time_delta
        );
        println!(
            "- led_is_blinking                = {:?}",
            self.led_is_blinking
        );
        println!(
            "- u2f_ms_clear_button_period     = {:?}",
            self.u2f_ms_clear_button_period
        );
        println!(
            "- u2f_ms_init_button_period      = {:?}",
            self.u2f_ms_init_button_period
        );
        println!(
            "- button_min_press_t_ms          = {:?}",
            self.button_min_press_t_ms
        );
    }
}

/// Query the firmware version of Nitrokey.
pub fn get_version(cfg: &Cfg) -> Result<String> {
    let device = crate::get_fidokey_device(cfg)?;
    let cid = ctaphid::ctaphid_init(&device).map_err(Error::msg)?;
    let version = ctapihd_nitro::ctaphid_nitro_get_version(&device, &cid).map_err(Error::msg)?;
    Ok(version)
}

/// Generate a random number.
/// - rng_byte : The number of digits of random numbers to generate.
pub fn get_rng(cfg: &Cfg, rng_byte: u8) -> Result<String> {
    let device = crate::get_fidokey_device(cfg)?;
    let cid = ctaphid::ctaphid_init(&device).map_err(Error::msg)?;
    let status =
        ctapihd_nitro::ctaphid_nitro_get_rng(&device, &cid, rng_byte).map_err(Error::msg)?;
    Ok(status)
}

/// Query the Status of Nitrokey.
pub fn get_status(cfg: &Cfg) -> Result<NitrokeyStatus> {
    let device = crate::get_fidokey_device(cfg)?;
    let cid = ctaphid::ctaphid_init(&device).map_err(Error::msg)?;
    let status = ctapihd_nitro::ctaphid_nitro_get_status(&device, &cid).map_err(Error::msg)?;

    let mut ret = NitrokeyStatus::default();
    if status[0] == 1 {
        ret.is_button_pressed_raw = true;
    }
    ret.button_state = status[1];
    ret.button_state_t = match ret.button_state {
        0 => ButtonStateT::BstInitializing,
        1 => ButtonStateT::BstInitializingReadyToClear,
        2 => ButtonStateT::BstMetaReadyToUse,
        3 => ButtonStateT::BstUnpressed,
        4 => ButtonStateT::BstPressedRecently,
        5 => ButtonStateT::BstPressedRegistered,
        6 => ButtonStateT::BstPressedRegisteredTransitional,
        7 => ButtonStateT::BstPressedRegisteredExt,
        8 => ButtonStateT::BstPressedRegisteredExtInvalid,
        9 => ButtonStateT::BstPressedConsumedActive,
        10 => ButtonStateT::BstPressedConsumed,
        _ => ButtonStateT::BstMaxNum,
    };

    ret.last_button_cleared_time_delta = status[2];
    ret.last_button_pushed_time_delta = status[3];
    if status[4] == 1 {
        ret.led_is_blinking = true;
    }
    ret.u2f_ms_clear_button_period = status[5];
    ret.u2f_ms_init_button_period = status[6];
    ret.button_min_press_t_ms = status[7];

    Ok(ret)
}

/// firmware update API.
pub fn enter_boot(cfg: &Cfg) -> Result<()> {
    let device = crate::get_fidokey_device(cfg)?;
    let cid = ctaphid::ctaphid_init(&device).map_err(Error::msg)?;
    ctapihd_nitro::ctaphid_nitro_enter_boot(&device, &cid).map_err(Error::msg)?;
    Ok(())
}

/// firmware update API.
pub fn write_flash(cfg: &Cfg, addr: u64, data: &[u8]) -> Result<()> {
    let device = crate::get_fidokey_device(cfg)?;
    let cid = ctaphid::ctaphid_init(&device).map_err(Error::msg)?;

    let solo_bootloader_write = 0x40;
    let packet =
        create_request_packet(solo_bootloader_write, addr, data, false).map_err(Error::msg)?;

    ctapihd_nitro::ctaphid_nitro_boot(&device, &cid, &packet).map_err(Error::msg)?;
    Ok(())
}

/// firmware update API.
pub fn verify_flash(cfg: &Cfg, sig: &[u8]) -> Result<()> {
    let device = crate::get_fidokey_device(cfg)?;
    let cid = ctaphid::ctaphid_init(&device).map_err(Error::msg)?;

    let solo_bootloader_done = 0x41;
    let data = create_request_packet(solo_bootloader_done, 0, sig, false).map_err(Error::msg)?;

    ctapihd_nitro::ctaphid_nitro_boot(&device, &cid, &data).map_err(Error::msg)?;
    Ok(())
}

fn create_request_packet(
    nitro_command: u8,
    addr: u64,
    request_data: &[u8],
    is_u2f: bool,
) -> Result<Vec<u8>, String> {
    // request
    // - nitro_command(4byte) + TAG(4byte) + length(2byte) + A*16
    let mut request: Vec<u8> = vec![0; 10];

    // command
    request[0] = nitro_command;

    // addr
    // to byte array in little-endian byte order.
    let addr_bytes = addr.to_le_bytes();
    request[1] = addr_bytes[0];
    request[2] = addr_bytes[1];
    request[3] = addr_bytes[2];

    // TAG
    request[4] = 0x8c;
    request[5] = 0x27;
    request[6] = 0x90;
    request[7] = 0xf6;

    // High part of payload length
    request[8] = ((request_data.len() as u16) >> 8) as u8;
    // Low part of payload length
    request[9] = request_data.len() as u8;

    // request-data(A * 16)
    request.append(&mut request_data.into());

    // for debug
    //println!("{}",addr);
    //println!("{}:{}",request.len(),util::to_hex_str(&request));

    if !is_u2f {
        return Ok(request);
    }

    // u2f-format
    // max 255 (1byte)
    if request.len() > 255 {
        return Err("Error size".to_string());
    }
    let len = request.len() as u8;

    // data
    let mut data: Vec<u8> = vec![];

    // client param (B * 32)
    data.append(&mut vec![0x42; 32]);
    // app param (A * 32)
    data.append(&mut vec![0x41; 32]);
    // length
    data.append(&mut vec![len]);
    // request
    data.append(&mut request);

    Ok(data)
}

/// firmware update API.
pub fn is_bootloader_mode(cfg: &Cfg) -> Result<bool> {
    let device = crate::get_fidokey_device(cfg)?;
    let cid = ctaphid::ctaphid_init(&device).map_err(Error::msg)?;

    let solo_bootloader_version = 0x44;
    // request-data = A*16
    let request_data = vec![0x41; 16];
    let data = create_request_packet(solo_bootloader_version, 0, &request_data, true)
        .map_err(Error::msg)?;

    // CTAP1.INS.AUTHENTICATE = 2
    let mut response = match ctaphid::send_apdu(&device, &cid, 0, 2, 0, 0, &data) {
        Ok(r) => r,
        Err(_) => return Ok(false),
    };

    if cfg.enable_log {
        println!(
            "- response({:02})    = {:?}",
            response.len(),
            util::to_hex_str(&response)
        );
    }

    // remove headder
    let mut response = response.split_off(3 + 2);

    // status
    if response[0] != 0 {
        return Ok(false);
    }
    let response = response.split_off(1);

    // split by 0xff
    let datas: Vec<&[u8]> = response.split(|&x| x == 0xff).collect();

    // parse
    for (i, val) in datas.iter().enumerate() {
        //println!("{}: {}", i, val);
        if val.is_empty() {
            continue;
        }

        if i == 0 {
            println!("{}{}{}", val[0], val[1], val[2]);
        } else {
            // string data
            let tmp = String::from_utf8(val.to_vec());
            println!("{}", tmp.unwrap());
        }
    }

    Ok(true)
}
