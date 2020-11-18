/*!
nitro_get_status API parameters()
*/

use crate::util;

#[derive(Debug, Default)]
pub struct NitrokeyStatus {
    pub is_button_pressed_raw: bool,
    pub button_state: u8,
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


/*
    ctap_buffer[0] = IS_BUTTON_PRESSED_RAW();
    ctap_buffer[1] = button_get_press_state();
    ctap_buffer[2] = last_button_cleared_time_delta();
    ctap_buffer[3] = last_button_pushed_time_delta();
    ctap_buffer[4] = led_is_blinking();
    ctap_buffer[5] = U2F_MS_CLEAR_BUTTON_PERIOD / 100;
    ctap_buffer[6] = U2F_MS_INIT_BUTTON_PERIOD / 100;
    ctap_buffer[7] = BUTTON_MIN_PRESS_T_MS / 10;
*/
/*
typedef enum {
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

	BST_MAX_NUM
} BUTTON_STATE_T;
*/
