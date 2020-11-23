use crate::ctaphid;

#[derive(Debug)]
pub enum ButtonStateT{
	BST_INITIALIZING,			// wait for the charge to settle down
	BST_INITIALIZING_READY_TO_CLEAR,	// ready for clearing
	BST_META_READY_TO_USE,			// META state (never used), to ease testing,
								// if button is ready (e.g. >READY) or not (<READY)
	BST_UNPRESSED,				// ready to use
	BST_PRESSED_RECENTLY,		// touch registration is started
	BST_PRESSED_REGISTERED,		// touch registered, normal press period
	BST_PRESSED_REGISTERED_TRANSITIONAL,		// touch registered, normal press, but timeouted
	BST_PRESSED_REGISTERED_EXT, // touch registered, extended press period
	BST_PRESSED_REGISTERED_EXT_INVALID, // touch registered, extended press period, invalidated
    BST_PRESSED_CONSUMED_ACTIVE,		// BST_PRESSED_CONSUMED, but accepts requests
	BST_PRESSED_CONSUMED,		// touch registered and consumed, button still not released, does not accept requests
	BST_MAX_NUM,
}
impl Default for ButtonStateT {
    fn default() -> Self { ButtonStateT::BST_INITIALIZING }
}

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
        println!("- is_button_pressed_raw          = {:?}", self.is_button_pressed_raw);
        println!("- button_state                   = {:?}", self.button_state);
        println!("- last_button_cleared_time_delta = {:?}", self.last_button_cleared_time_delta);
        println!("- last_button_pushed_time_delta  = {:?}", self.last_button_pushed_time_delta);
        println!("- led_is_blinking                = {:?}", self.led_is_blinking);
        println!("- u2f_ms_clear_button_period     = {:?}", self.u2f_ms_clear_button_period);
        println!("- u2f_ms_init_button_period      = {:?}", self.u2f_ms_init_button_period);
        println!("- button_min_press_t_ms          = {:?}", self.button_min_press_t_ms);
    }
}

/// Nitrokey Custom GETVERSION
pub fn get_version(hid_params: &[crate::HidParam]) -> Result<String, String> {
    let device = ctaphid::connect_device(hid_params, ctaphid::USAGE_PAGE_FIDO)?;
    let cid = ctaphid::ctaphid_init(&device);

    let version = match ctaphid::ctaphid_nitro_get_version(&device, &cid){
        Ok(result) => result,
        Err(err) => {
            let msg = format!("nitrokey::get_version err = 0x{:02X}", err);
            return Err(msg);
        }
    };

    Ok(version)
}

/// Nitrokey Custom GETRNG
pub fn get_rng(hid_params: &[crate::HidParam],rng_byte:u8) -> Result<String, String> {
    let device = ctaphid::connect_device(hid_params, ctaphid::USAGE_PAGE_FIDO)?;
    let cid = ctaphid::ctaphid_init(&device);

    let status = match ctaphid::ctaphid_nitro_get_rng(&device, &cid,rng_byte){
        Ok(result) => result,
        Err(err) => {
            let msg = format!("nitrokey::get_rng err = 0x{:02X}", err);
            return Err(msg);
        }
    };

    Ok(status)
}

/// Nitrokey Custom GETSTATUS
pub fn get_status(hid_params: &[crate::HidParam]) -> Result<NitrokeyStatus, String> {
    let device = ctaphid::connect_device(hid_params, ctaphid::USAGE_PAGE_FIDO)?;
    let cid = ctaphid::ctaphid_init(&device);

    let status = match ctaphid::ctaphid_nitro_get_status(&device, &cid){
        Ok(result) => result,
        Err(err) => {
            let msg = format!("nitrokey::get_status err = 0x{:02X}", err);
            return Err(msg);
        }
    };

    let mut ret = NitrokeyStatus::default();
    if status[0] == 1{
        ret.is_button_pressed_raw = true;
    }
    ret.button_state = status[1];
    ret.last_button_cleared_time_delta = status[2];
    ret.last_button_pushed_time_delta = status[3];
    if status[4] == 1{
        ret.led_is_blinking = true;
    }
    ret.u2f_ms_clear_button_period = status[5];
    ret.u2f_ms_init_button_period = status[6];
    ret.button_min_press_t_ms = status[7];

    Ok(ret)
}
