use anyhow::{anyhow, Result};
use ctap_hid_fido2::InfoOption;
use crate::common;
use crate::CFG;

pub fn pin(matches: &clap::ArgMatches) -> Result<()> {
    if matches.args.is_empty() {
        println!("Get PIN retry counter.\n");
        match ctap_hid_fido2::get_pin_retries(&CFG) {
            Ok(v) => {
                println!("PIN retry counter = {}", v);

                if v > 0 {
                    let mark = if v > 4 {
                        ":) "
                    } else if v > 1 {
                        ":( "
                    } else {
                        ":0 "
                    };

                    println!();
                    for _ in 0..v {
                        print!("{}", mark);
                    }
                    println!();

                    println!();
                    println!("PIN retry counter represents the number of attempts left before PIN is disabled.");
                    println!("Each correct PIN entry resets the PIN retry counters back to their maximum values.");
                    println!("Each incorrect PIN entry decrements the counter by 1.");
                    println!("Once the PIN retry counter reaches 0, built-in user verification are disabled and can only be enabled if authenticator is reset.");
                } else {
                    println!("\nThe authenticator has been blocked. \nThe only way to make it available again is factory reset.");
                    println!();
                    println!(":_( ");
                    println!();
                }
            }
            Err(err) => return Err(err),
        };
    } else if matches.is_present("new") {
        println!("Set new PIN.\n");

        if let Some(client_pin) =
            ctap_hid_fido2::enable_info_option(&CFG, &InfoOption::ClinetPin)?
        {
            if client_pin {
                return Err(anyhow!("PIN is already set."));
            }
        };

        println!("new PIN:");
        let pin = common::get_input();
        println!();

        ctap_hid_fido2::set_new_pin(&CFG, &pin)?;

        println!("Success! :)\n");
    } else if matches.is_present("change") {
        println!("Change PIN.\n");

        if ctap_hid_fido2::enable_info_option(&CFG, &InfoOption::ClinetPin)?.is_none() {
            return Err(anyhow!("PIN not yet set."));
        };

        println!("current PIN:");
        let current_pin = common::get_input();
        println!();
        println!("new PIN:");
        let new_pin = common::get_input();
        println!();

        ctap_hid_fido2::change_pin(&CFG, &current_pin, &new_pin)?;

        println!("Success! :)\n");
    }

    Ok(())
}
