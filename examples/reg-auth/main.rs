//! Register and authenticate with a FIDO2 key (PIN example).
//!
//! # Usage
//!
//! ```text
//! # Defaults: debug log on, keep-alive message on stdout
//! cargo run --example reg-auth
//!
//! # Print CLI help
//! cargo run --example reg-auth -- --help
//!
//! # Disable CTAP/HID hex debug logs
//! cargo run --example reg-auth -- --enable-log false
//!
//! # Send keep-alive text (e.g. "Touch the sensor...") to stderr
//! cargo run --example reg-auth -- --keep-alive-msg-to-stderr true
//!
//! # Both options combined
//! cargo run --example reg-auth -- --enable-log false --keep-alive-msg-to-stderr true
//! ```
//!
//! # Options
//!
//! | Flag | Default | Description |
//! |------|---------|-------------|
//! | `--enable-log` | `true` | Print CTAP/HID debug logs to **stdout** |
//! | `--keep-alive-msg-to-stderr` | `false` | Print the user-presence prompt to **stderr** instead of stdout |
//!
//! # Verifying stderr output manually
//!
//! While the authenticator waits for user presence, redirect streams to files:
//!
//! ```text
//! cargo run --example reg-auth -- --enable-log false --keep-alive-msg-to-stderr true 1>stdout.txt 2>stderr.txt
//! grep -F "Touch the sensor" stderr.txt   # should match
//! grep -F "Touch the sensor" stdout.txt   # should not match
//! ```

use anyhow::{anyhow, Result};
use clap::{ArgAction, Parser};
use ctap_hid_fido2::{
    fidokey::{GetAssertionArgsBuilder, MakeCredentialArgsBuilder},
    verifier, Cfg, FidoKeyHidFactory,
};

#[derive(Parser)]
#[command(
    about = "Register and authenticate with a FIDO2 key (PIN example).",
    after_help = "\
Examples:
  cargo run --example reg-auth
  cargo run --example reg-auth -- --enable-log false
  cargo run --example reg-auth -- --keep-alive-msg-to-stderr true
  cargo run --example reg-auth -- --enable-log false --keep-alive-msg-to-stderr true

Verify keep-alive on stderr:
  cargo run --example reg-auth -- --keep-alive-msg-to-stderr true 1>stdout.txt 2>stderr.txt
"
)]
struct Args {
    /// Enable CTAP/HID debug log output to stdout (default: true).
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    enable_log: bool,

    /// Send keep-alive message (e.g. touch prompt) to stderr instead of stdout (default: false).
    #[arg(long, default_value_t = false, action = ArgAction::Set)]
    keep_alive_msg_to_stderr: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let rpid = "reg-auth-example-app";
    // let pin = get_input_with_message("input PIN:");
    let pin = "1234";
    let pin_protocol_version = 1;

    println!("Register");
    // create `challenge`
    let challenge = verifier::create_challenge();

    // create `MakeCredentialArgs`
    let make_credential_args = MakeCredentialArgsBuilder::new(rpid, &challenge)
        .pin(pin)
        .build();

    // create `FidoKeyHid`
    let cfg = Cfg::init()
        .with_enable_log(args.enable_log)
        .with_keep_alive_msg_to_stderr(args.keep_alive_msg_to_stderr);
    let device = FidoKeyHidFactory::create(&cfg)?.with_pin_protocol_version(pin_protocol_version);

    // get `Attestation` Object
    let attestation = device.make_credential_with_args(&make_credential_args)?;
    println!("- Register Success");

    // verify `Attestation` Object
    let verify_result = verifier::verify_attestation(rpid, &challenge, &attestation);
    if !verify_result.is_success {
        println!("- ! Verify Failed");
        return Err(anyhow!("Attestation verification failed"));
    }

    // store Credential Id and Publickey
    let userdata_credential_id = verify_result.credential_id;
    let userdata_credential_public_key = verify_result.credential_public_key;

    println!("Authenticate");
    // create `challenge`
    let challenge = verifier::create_challenge();

    // create `GetAssertionArgs`
    let get_assertion_args = GetAssertionArgsBuilder::new(rpid, &challenge)
        .pin(pin)
        .credential_id(&userdata_credential_id)
        .build();

    // get `Assertion` Object
    let assertions = device.get_assertion_with_args(&get_assertion_args)?;
    println!("- Authenticate Success");

    // verify `Assertion` Object
    if !verifier::verify_assertion(
        rpid,
        &userdata_credential_public_key,
        &challenge,
        &assertions[0],
    ) {
        println!("- ! Verify Assertion Failed");
        return Err(anyhow!("Assertion verification failed"));
    }

    Ok(())
}

pub fn get_input() -> String {
    let mut word = String::new();
    std::io::stdin().read_line(&mut word).ok();
    word.trim().to_string()
}

pub fn get_input_with_message(message: &str) -> String {
    println!("{}", message);
    let input = get_input();
    println!();
    input
}
