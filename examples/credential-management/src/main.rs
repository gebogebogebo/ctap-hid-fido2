use ctap_hid_fido2;
use ctap_hid_fido2::public_key_credential_descriptor::PublicKeyCredentialDescriptor;
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::util;
use ctap_hid_fido2::HidParam;
use ctap_hid_fido2::InfoParam;
extern crate clap;
use clap::{App, Arg};

fn metadata(pin: Option<&str>) {
    println!("# credential_management_get_creds_metadata()");
    match ctap_hid_fido2::credential_management_get_creds_metadata(
        &HidParam::get_default_params(),
        pin,
    ) {
        Ok(result) => println!("{}", result),
        Err(e) => println!("- error: {:?}", e),
    }
}

fn rps(pin: Option<&str>) {
    println!("# credential_management_enumerate_rps()");
    match ctap_hid_fido2::credential_management_enumerate_rps(&HidParam::get_default_params(), pin)
    {
        Ok(results) => {
            for r in results {
                println!("## rps\n{}", r);
            }
        }
        Err(e) => println!("- error: {:?}", e),
    }
}

fn credentials(pin: Option<&str>, rpid_hash: Option<&str>) {
    println!("# credential_management_enumerate_credentials()");
    println!("- value for rpid_hash: {:?}", rpid_hash);
    println!("");

    let rpid_hash_bytes: Vec<u8> = util::to_str_hex(rpid_hash.unwrap());

    match ctap_hid_fido2::credential_management_enumerate_credentials(
        &HidParam::get_default_params(),
        pin,
        rpid_hash_bytes,
    ) {
        Ok(results) => {
            for c in results {
                println!("## credentials\n{}", c);
            }
        }
        Err(e) => println!("- error: {:?}", e),
    }
}

fn delete(pin: Option<&str>, credential_id: Option<&str>) {
    println!("# credential_management_delete_credential()");
    println!("- value for credential_id: {:?}", credential_id);
    println!("");

    let mut pkcd = PublicKeyCredentialDescriptor::default();
    pkcd.id = util::to_str_hex(credential_id.unwrap());
    pkcd.ctype = "public_key".to_string();

    match ctap_hid_fido2::credential_management_delete_credential(
        &HidParam::get_default_params(),
        pin,
        Some(pkcd),
    ) {
        Ok(_) => println!("- success"),
        Err(e) => println!("- error: {:?}",e),
    }
}

fn update(pin: Option<&str>, credential_id: Option<&str>) {
    println!("# credential_management_update_user_information()");
    println!("- value for credential_id: {:?}", credential_id);
    println!("");

    let mut pkcd = PublicKeyCredentialDescriptor::default();
    pkcd.id = util::to_str_hex(credential_id.unwrap());
    pkcd.ctype = "public_key".to_string();

    let mut pkcue = PublicKeyCredentialUserEntity::default();
    pkcue.id = util::to_str_hex("7974657374");
    pkcue.name = "test-name".to_string();
    pkcue.display_name = "test-display".to_string();

    match ctap_hid_fido2::credential_management_update_user_information(
        &HidParam::get_default_params(),
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
        .arg(
            Arg::with_name("pin")
                .help("pin")
                .short("p")
                .long("pin")
                .takes_value(true)
                .default_value("1234"),
        )
        .arg(
            Arg::with_name("metadata")
                .help("credential_management_get_creds_metadata")
                .short("m")
                .long("metadata"),
        )
        .arg(
            Arg::with_name("rps")
                .help("credential_management_enumerate_rps")
                .short("r")
                .long("rps"),
        )
        .arg(
            Arg::with_name("credentials")
                .help("credential_management_enumerate_credentials")
                .short("c")
                .long("credentials")
                .takes_value(true)
                .value_name("rpid_hash"),
        )
        .arg(
            Arg::with_name("delete")
                .help("credential_management_delete_credential")
                .short("d")
                .long("delete")
                .takes_value(true)
                .value_name("public_key_credential_descriptor.id(credential-id)"),
        )
        .arg(
            Arg::with_name("update")
                .help("credential_management_update_user_information")
                .short("u")
                .long("update")
                .takes_value(true)
                .value_name("public_key_credential_descriptor.id(credential-id)"),
        )
        .arg(
            Arg::with_name("info")
                .help("authenticatorGetInfo")
                .short("i")
                .long("info"),
        );

    // Parse arguments
    let matches = app.get_matches();

    // Start
    ctap_hid_fido2::hello();

    match ctap_hid_fido2::enable_info_param(
        &HidParam::get_default_params(),
        InfoParam::VersionsFido21Pre,
    ) {
        Ok(result) => println!("Enable CTAP 2.1 PRE = {:?}", result),
        Err(error) => println!("- error: {:?}", error),
    };

    if matches.is_present("info") {
        println!("get_info()");
        match ctap_hid_fido2::get_info(&HidParam::get_default_params()) {
            Ok(info) => println!("{}", info),
            Err(error) => println!("error: {:?}", error),
        };
    }

    let pin = matches.value_of("pin");
    println!("Value for pin: {:?}", pin);

    println!("----- credential-management start -----");

    if matches.is_present("metadata") {
        metadata(pin);
    }

    if matches.is_present("rps") {
        rps(pin);
    }

    if matches.is_present("credentials") {
        let rpid_hash = matches.value_of("credentials");
        credentials(pin, rpid_hash);
    }

    if matches.is_present("delete") {
        let credential_id = matches.value_of("delete");
        delete(pin, credential_id);
    }

    if matches.is_present("update") {
        let credential_id = matches.value_of("update");
        update(pin, credential_id);
    }

    println!("----- credential-management end -----");
}
