/*!
## Nitrokey Custom Commands
for Nitrokey FIDO2 only.
*/

use crate::ctaphid;
use crate::ctapihd_nitro;
use crate::fidokey;

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
    let device = fidokey::FidoKeyHid::new(hid_params)?;
    let cid = ctaphid::ctaphid_init(&device);

    let version = match ctapihd_nitro::ctaphid_nitro_get_version(&device, &cid) {
        Ok(result) => result,
        Err(err) => {
            let msg = format!("nitrokey::get_version err = 0x{:02X}", err);
            return Err(msg);
        }
    };

    Ok(version)
}

/// Generate a random number.
/// - rng_byte : The number of digits of random numbers to generate.
pub fn get_rng(hid_params: &[crate::HidParam],rng_byte: u8) -> Result<String, String> {
    let device = fidokey::FidoKeyHid::new(hid_params)?;
    let cid = ctaphid::ctaphid_init(&device);

    let status = match ctapihd_nitro::ctaphid_nitro_get_rng(&device, &cid, rng_byte) {
        Ok(result) => result,
        Err(err) => {
            let msg = format!("nitrokey::get_rng err = 0x{:02X}", err);
            return Err(msg);
        }
    };

    Ok(status)
}

/// Query the Status of Nitrokey.
pub fn get_status(hid_params: &[crate::HidParam]) -> Result<NitrokeyStatus, String> {
    let device = fidokey::FidoKeyHid::new(hid_params)?;
    let cid = ctaphid::ctaphid_init(&device);

    let status = match ctapihd_nitro::ctaphid_nitro_get_status(&device, &cid) {
        Ok(result) => result,
        Err(err) => {
            let msg = format!("nitrokey::get_status err = 0x{:02X}", err);
            return Err(msg);
        }
    };

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
