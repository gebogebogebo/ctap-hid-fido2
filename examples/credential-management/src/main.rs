use ctap_hid_fido2;
use ctap_hid_fido2::util;
extern crate clap;
use clap::{App, Arg};

fn metadata(pin: Option<&str>) {
    println!("# credential_management_get_creds_metadata()");
    match ctap_hid_fido2::credential_management_get_creds_metadata(
        &ctap_hid_fido2::HidParam::get_default_params(),
        pin,
    ) {
        Ok(result) => {
            println!("{}", result);
        }
        Err(error) => {
            println!("- creds metadata error: {:?}", error);
        }
    };
    println!("");
    println!("");
}

fn rps(pin: Option<&str>) {
    println!("# credential_management_enumerate_rps()");
    match ctap_hid_fido2::credential_management_enumerate_rps(
        &ctap_hid_fido2::HidParam::get_default_params(),
        pin,
    ) {
        Ok(results) => {
            for data in results {
                println!("## rps");
                println!("{}",data);
            }
        }
        Err(error) => {
            println!("- enumerate rps error: {:?}", error);
        }
    };
    println!("");
    println!("");
}

fn credentials(pin: Option<&str>,rpid_hash: Option<&str>) {
    println!("# credential_management_enumerate_credentials()");
    println!("- value for rpid_hash: {:?}", rpid_hash);
    println!("");

    let rpid_hash_bytes: Vec<u8> = util::to_str_hex(rpid_hash.unwrap().to_string());

    match ctap_hid_fido2::credential_management_enumerate_credentials(
        &ctap_hid_fido2::HidParam::get_default_params(),
        pin,
        rpid_hash_bytes,
    ) {
        Ok(results) => {
            for data in results {
                println!("## credentials");
                println!("{}",data);
            }
        }
        Err(error) => {
            println!("- enumerate credentials error: {:?}", error);
        }
    };
    println!("");
    println!("");
}

fn delete(pin: Option<&str>,credential_id: Option<&str>) {
    println!("# credential_management_delete_credential()");
    println!("- value for credential_id: {:?}", credential_id);
    println!("");

    let mut pkcd =
        ctap_hid_fido2::credential_management_params::PublicKeyCredentialDescriptor::default();
    pkcd.id = util::to_str_hex(
        credential_id.unwrap().to_string()
    );
    pkcd.ctype = "public_key".to_string();

    match ctap_hid_fido2::credential_management_delete_credential(
        &ctap_hid_fido2::HidParam::get_default_params(),
        pin,
        Some(pkcd),
    ) {
        Ok(_) => println!("- credential_management_delete_credential Success"),
        Err(error) => println!(
            "- credential_management_delete_credential error: {:?}",
            error
        ),
    };
    println!("");
    println!("");
}

fn update(pin: Option<&str>,credential_id: Option<&str>) {
    println!("# credential_management_update_user_information()");
    println!("- value for credential_id: {:?}", credential_id);
    println!("");

    let mut pkcd =
        ctap_hid_fido2::credential_management_params::PublicKeyCredentialDescriptor::default();
    pkcd.id = util::to_str_hex(
        credential_id.unwrap().to_string()
    );
    pkcd.ctype = "public_key".to_string();

    let mut pkcue =
        ctap_hid_fido2::credential_management_params::PublicKeyCredentialUserEntity::default();
    pkcue.id = util::to_str_hex("7974657374".to_string());
    pkcue.name = "test-name".to_string();
    pkcue.display_name = "test-display-name".to_string();

    match ctap_hid_fido2::credential_management_update_user_information(
        &ctap_hid_fido2::HidParam::get_default_params(),
        pin,
        Some(pkcd),
        Some(pkcue),
    ) {
        Ok(_) => println!("- credential_management_update_user_information Success"),
        Err(error) => println!(
            "- credential_management_update_user_information error: {:?}",
            error
        ),
    };
    println!("");
    println!("");
}

fn main() {
    let app = App::new("credential-management")
        .version("0.1.0")
        .author("gebo")
        .about("CTAP 2.1 credential-management command test app")
        .arg(Arg::with_name("pin")
            .help("pin")
            .short("p")
            .long("pin")
            .takes_value(true)
            .default_value("1234")
        )
        .arg(Arg::with_name("metadata")
            .help("credential_management_get_creds_metadata")
            .short("m")
            .long("metadata")
        )
        .arg(Arg::with_name("rps")
            .help("credential_management_enumerate_rps")
            .short("r")
            .long("rps")
        )
        .arg(Arg::with_name("credentials")
            .help("credential_management_enumerate_credentials")
            .short("c")
            .long("credentials")
            .takes_value(true)
            .value_name("rpid_hash")
        )
        .arg(Arg::with_name("delete")
            .help("credential_management_delete_credential")
            .short("d")
            .long("delete")
            .takes_value(true)
            .value_name("public_key_credential_descriptor.id(credential-id)")
        )
        .arg(Arg::with_name("update")
            .help("credential_management_update_user_information")
            .short("u")
            .long("update")
            .takes_value(true)
            .value_name("public_key_credential_descriptor.id(credential-id)")
        )
        .arg(Arg::with_name("info")
            .help("authenticatorGetInfo")
            .short("i")
            .long("info")
        );

    // Parse arguments
    let matches = app.get_matches();

    // Start
    ctap_hid_fido2::hello();

    match ctap_hid_fido2::enable_ctap_2_1(&ctap_hid_fido2::HidParam::get_default_params()) {
        Ok(result) => println!("Enable CTAP 2.1 = {:?}",result),
        Err(error) => println!("- error: {:?}", error),
    };
    match ctap_hid_fido2::enable_ctap_2_1_pre(&ctap_hid_fido2::HidParam::get_default_params()) {
        Ok(result) => println!("Enable CTAP 2.1 PRE = {:?}",result),
        Err(error) => println!("- error: {:?}", error),
    };

    if matches.is_present("info"){
        println!("get_info()");
        let infos = match ctap_hid_fido2::get_info(&ctap_hid_fido2::HidParam::get_default_params()) {
            Ok(result) => result,
            Err(error) => {
                println!("error: {:?}", error);
                return;
            }
        };
        for (key, value) in infos {
            println!("- {} / {}", key, value);
        }
    }

    let pin = matches.value_of("pin").unwrap();
    println!("Value for pin: {}", pin);

    println!("----- credential-management start -----");

    if matches.is_present("metadata"){
        metadata(Some(pin));
    }

    if matches.is_present("rps"){
        rps(Some(pin));
    }

    if matches.is_present("credentials"){
        let rpid_hash = matches.value_of("credentials");    
        credentials(Some(pin),rpid_hash);
    }

    if matches.is_present("delete"){
        let credential_id = matches.value_of("delete");    
        delete(Some(pin),credential_id);
    }

    if matches.is_present("update"){
        let credential_id = matches.value_of("update");    
        update(Some(pin),credential_id);
    }

    println!("----- credential-management end -----");

    /* Test for CTAP 2.1
    match ctap_hid_fido2::config(&ctap_hid_fido2::HidParam::get_default_params()) {
        Ok(result) => {
            println!("- config : {:?}", result);
        }
        Err(error) => {
            println!("- config error: {:?}", error);
        }
    };

    match ctap_hid_fido2::selection(&ctap_hid_fido2::HidParam::get_default_params()) {
        Ok(result) => {
            println!("- selection : {:?}", result);
        }
        Err(error) => {
            println!("- selection error: {:?}", error);
        }
    };
    */
}
