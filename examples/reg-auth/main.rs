use anyhow::{anyhow, Result};
use ctap_hid_fido2::{
    fidokey::{GetAssertionArgsBuilder, MakeCredentialArgsBuilder},
    verifier, Cfg, FidoKeyHidFactory,
};

fn main() -> Result<()> {
    let rpid = "reg-auth-example-app";
    // let pin = get_input_with_message("input PIN:");
    let pin = "1234";
    let pin_protocol_version = 1;

    println!("Register");
    // create `challenge`
    let challenge = verifier::create_challenge();

    // create `MakeCredentialArgs`
    let make_credential_args = MakeCredentialArgsBuilder::new(rpid, &challenge)
        .pin(&pin)
        .build();

    // create `FidoKeyHid`
    let device = FidoKeyHidFactory::create(&Cfg::init().with_enable_log(true))?
        .with_pin_protocol_version(pin_protocol_version);

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
        .pin(&pin)
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
    return word.trim().to_string();
}

pub fn get_input_with_message(message: &str) -> String {
    println!("{}", message);
    let input = get_input();
    println!();
    input
}
