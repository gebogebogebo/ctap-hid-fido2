use crate::common;
use anyhow::{anyhow, Result};
use ctap_hid_fido2::fidokey::{get_info::InfoOption, FidoKeyHid};

pub enum PinCommand {
    View,
    New,
    Change,
}

pub fn pin(device: &FidoKeyHid, command: PinCommand) -> Result<()> {
    match command {
        PinCommand::New => {
            println!("Set new PIN.\n");

            if let Some(client_pin) = device.enable_info_option(&InfoOption::ClientPin)? {
                if client_pin {
                    return Err(anyhow!("PIN is already set."));
                }
            };

            println!("new PIN:");
            let pin = common::get_input()?;
            println!();

            device.set_new_pin(&pin)?;

            println!("Success! :)\n");
        }
        PinCommand::Change => {
            println!("Change PIN.\n");

            if device.enable_info_option(&InfoOption::ClientPin)?.is_none() {
                return Err(anyhow!("PIN not yet set."));
            };

            println!("current PIN:");
            let current_pin = common::get_input()?;
            println!();
            println!("new PIN:");
            let new_pin = common::get_input()?;
            println!();

            device.change_pin(&current_pin, &new_pin)?;

            println!("Success! :)\n");
        }
        PinCommand::View => {
            let info = device.get_info()?;
            if info.force_pin_change {
                println!("[Force Change PIN is True]\n Please change your PIN.\n");
            }

            println!("Get PIN retry counter.\n");
            let pin_retries = device.get_pin_retries()?;
            println!("PIN retry counter = {}", pin_retries);

            if pin_retries > 0 {
                let mark = if pin_retries > 4 {
                    ":) "
                } else if pin_retries > 1 {
                    ":( "
                } else {
                    ":0 "
                };

                println!();
                for _ in 0..pin_retries {
                    print!("{}", mark);
                }
                println!();

                println!();
                println!(
                    "PIN retry counter represents the number of attempts left before PIN is disabled."
                );
                println!("Each correct PIN entry resets the PIN retry counters back to their maximum values.");
                println!("Each incorrect PIN entry decrements the counter by 1.");
                println!("Once the PIN retry counter reaches 0, built-in user verification are disabled and can only be enabled if authenticator is reset.");
            } else {
                println!("\nThe authenticator has been blocked. \nThe only way to make it available again is factory reset.");
                println!();
                println!(":_( ");
                println!();
            }

            let bio_enroll = device.enable_info_option(&InfoOption::BioEnroll)?;
            if bio_enroll.is_some() && bio_enroll.unwrap() {
                println!();
                println!();
                println!("Get UV retry counter.\n");
                match device.get_uv_retries() {
                    Ok(v) => {
                        println!("UV retry counter = {}", v);

                        if v > 0 {
                            println!();
                            println!("UV retries count is the number of built-in UV attempts remaining before built-in UV is disabled on the device.");
                        } else {
                            println!("\nUV is blocked. \nAuthenticate with a PIN will unblock it.");
                            println!();
                            println!(":_( ");
                            println!();
                        }
                    }
                    Err(err) => return Err(err),
                };
            }
        }
    }

    Ok(())
}
