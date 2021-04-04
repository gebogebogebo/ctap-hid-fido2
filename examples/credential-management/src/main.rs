use ctap_hid_fido2;
use ctap_hid_fido2::util;

fn metadata(pin: Option<&str>) {
    println!("# credential_management_get_creds_metadata()");
    println!("");
    match ctap_hid_fido2::credential_management_get_creds_metadata(
        &ctap_hid_fido2::HidParam::get_default_params(),
        pin,
    ) {
        Ok(result) => {
            result.print("- creds metadata");
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
    println!("");
    match ctap_hid_fido2::credential_management_enumerate_rps(
        &ctap_hid_fido2::HidParam::get_default_params(),
        pin,
    ) {
        Ok(results) => {
            for data in results {
                data.print("## rps");
                println!("");
            }
        }
        Err(error) => {
            println!("- enumerate rps error: {:?}", error);
        }
    };
    println!("");
    println!("");
}

fn credentials(pin: Option<&str>) {
    println!("# credential_management_enumerate_credentials()");
    println!("");

    let rpid_hash: Vec<u8> = util::to_str_hex(
        //        "0BDF390F1237B556DB51AF378D5795D5531385CCECDB4499D6BAFBD8918460CA".to_string(),
        "8C5D729B193185CD17AC242C85E6BD23D3990ABB1C65336559524882A6EACA33".to_string(),
    );
    match ctap_hid_fido2::credential_management_enumerate_credentials(
        &ctap_hid_fido2::HidParam::get_default_params(),
        pin,
        rpid_hash,
    ) {
        Ok(results) => {
            for data in results {
                data.print("## credentials");
                println!("");
            }
        }
        Err(error) => {
            println!("- enumerate credentials error: {:?}", error);
        }
    };
    println!("");
    println!("");
}

fn delete(pin: Option<&str>) {
    println!("# credential_management_delete_credential()");
    println!("");

    let mut pkcd =
        ctap_hid_fido2::credential_management_params::PublicKeyCredentialDescriptor::default();
    pkcd.credential_id = util::to_str_hex(
        "271EDC98A27DF03BB9DAE9F7A85A3249DF4412D0BA2F301ED62E2A03AA44326067B88C5D729B193185CD17AC242C85E6BD23D3990ABB1C65336559524882A6EACA33C4010000".to_string(),
    );
    pkcd.credential_type = "public_key".to_string();

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

fn update(pin: Option<&str>) {
    println!("credential_management_update_user_information()");

    let mut pkcd =
        ctap_hid_fido2::credential_management_params::PublicKeyCredentialDescriptor::default();
    pkcd.credential_id = util::to_str_hex(
        "2476469AB7113555910F56B21F06D3A3D16D7E5775C67DB0B5CF51D0FB071935AEDC8C5D729B193185CD17AC242C85E6BD23D3990ABB1C65336559524882A6EACA33D1010000".to_string(),
    );
    pkcd.credential_type = "public_key".to_string();

    let mut pkcue =
        ctap_hid_fido2::credential_management_params::PublicKeyCredentialUserEntity::default();
    pkcue.id = util::to_str_hex("010203".to_string());
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
    ctap_hid_fido2::hello();

    println!("----- credential-management start -----");
    metadata(Some("1234"));
    rps(Some("1234"));
    credentials(Some("1234"));
    delete(Some("1234"));
    update(Some("1234"));
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
