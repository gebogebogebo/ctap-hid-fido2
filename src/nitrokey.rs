/*!
## Nitrokey Custom Commands
for Nitrokey FIDO2 only.
*/

use crate::ctaphid;
use crate::ctapihd_nitro;

#[cfg(not(target_os = "linux"))]
use crate::fidokey::*;

// for pi
#[cfg(target_os = "linux")]
use crate::fidokey_pi::*;

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
pub fn get_version(hid_params: &[crate::HidParam]) -> Result<String, String> {
    let device = FidoKeyHid::new(hid_params)?;
    let cid = ctaphid::ctaphid_init(&device)?;
    let version = ctapihd_nitro::ctaphid_nitro_get_version(&device, &cid)?;
    Ok(version)
}

/// Generate a random number.
/// - rng_byte : The number of digits of random numbers to generate.
pub fn get_rng(hid_params: &[crate::HidParam], rng_byte: u8) -> Result<String, String> {
    let device = FidoKeyHid::new(hid_params)?;
    let cid = ctaphid::ctaphid_init(&device)?;
    let status = ctapihd_nitro::ctaphid_nitro_get_rng(&device, &cid, rng_byte)?;
    Ok(status)
}

/// Query the Status of Nitrokey.
pub fn get_status(hid_params: &[crate::HidParam]) -> Result<NitrokeyStatus, String> {
    let device = FidoKeyHid::new(hid_params)?;
    let cid = ctaphid::ctaphid_init(&device)?;
    let status = ctapihd_nitro::ctaphid_nitro_get_status(&device, &cid)?;

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

pub fn enter_boot(hid_params: &[crate::HidParam]) -> Result<(), String> {
    let device = FidoKeyHid::new(hid_params)?;
    let cid = ctaphid::ctaphid_init(&device)?;
    let result = ctapihd_nitro::ctaphid_nitro_enter_boot(&device, &cid)?;
    Ok(result)
}

pub fn solo_bootloader(hid_params: &[crate::HidParam]) -> Result<(), String> {
    
    let device = FidoKeyHid::new(hid_params)?;
    let cid = ctaphid::ctaphid_init(&device)?;

    // authenticate
    /*
    client_param = b"B" * 32
    app_param = b"A" * 32
    key_handle = format_request

    def authenticate(self, client_param, app_param, key_handle, check_only=False):
        """Authenticate a previously registered credential.
        :param client_param: SHA256 hash of the ClientData used for the request.
        :param app_param: SHA256 hash of the app ID used for the request.
        :param key_handle: The binary key handle of the credential.
        :param check_only: True to send a "check-only" request, which is used to
            determine if a key handle is known.
        :return: The authentication response from the authenticator.
        """
        data = (
            client_param + app_param + struct.pack(">B", len(key_handle)) + key_handle
        )
        p1 = 0x07 if check_only else 0x03
        response = self.send_apdu(ins=Ctap1.INS.AUTHENTICATE, p1=p1, data=data)
        return SignatureData(response)
    */

    {
        // CTAP1_INS.Version = 3
        //　　　 　　　　U  2  F  _  V  2
        // result = 0x55 32 46 5F 56 32 90 -> U2F_V2
        //            85 50 70 95 86 50
        // http://web-apps.nbookmark.com/ascii-converter/
        let _data: Vec<u8> = Vec::new();

        match ctaphid::send_apdu(&device, &cid, 0, 3, 0, 0, &_data) {
            Ok(result) =>{
                let version: String = String::from_utf8(result).unwrap();
                println!("U2F version = {}", version);
            }
            Err(error) =>{
                println!("{}",error);
            }
        }
    }

    {
        // client param
        // (B * 32)
        let mut client_param: Vec<u8> = vec![0; 32];
        for counter in 0..32 {
            client_param[counter] = 0x42;
        }

        // app param
        // (A * 32)
        let mut app_param: Vec<u8> = vec![0; 32];
        for counter in 0..32 {
            app_param[counter] = 0x41;
        }

        // create format_request
        // \x44 \x00 \x00 \x00 \x8c \x27 \x90 \xf6 \x00 \x10 AAAAAAAAAAAAAAAA
        let solo_bootloader_version = 0x44;
        let mut format_request: Vec<u8> = vec![0; 26];
        format_request[0] = solo_bootloader_version;
        format_request[1] = 0x00;
        format_request[2] = 0x00;
        format_request[3] = 0x00;

        // TAG
        format_request[4] = 0x8c;
        format_request[5] = 0x27;
        format_request[6] = 0x90;
        format_request[7] = 0xf6;

        // length
        format_request[8] = 0x0;
        format_request[9] = 0x10;

        // data(A x 16)
        for counter in 0..16 {
            format_request[10 + counter] = 0x41;
        }
        // format_request

        // data
        let mut data: Vec<u8> =
            vec![0; client_param.len() + app_param.len() + 1 + format_request.len()];
        let mut index = 0;
        for counter in 0..client_param.len() {
            data[index] = client_param[counter];
            index = index + 1
        }
        for counter in 0..app_param.len() {
            data[index] = app_param[counter];
            index = index + 1;
        }

        data[index] = 26;
        index = index + 1;

        for counter in 0..format_request.len() {
            data[index] = format_request[counter];
            index = index + 1;
        }

        match ctaphid::send_apdu(&device, &cid, 0, 0, 0, 0, &data) {
            Ok(_result) =>{
                // PEND
            }
            Err(error) =>{
                println!("{}",error);
            }
        }

    }

    Ok(())
}
