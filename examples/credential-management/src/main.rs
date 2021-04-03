use ctap_hid_fido2;
use ctap_hid_fido2::util;

fn main() {
    ctap_hid_fido2::hello();

    println!("----- credential-management start -----");

    // PEND
    println!("credential_management_delete_credential()");
    let cre_id: Vec<u8> = util::to_str_hex(
        "01BF8A2F9DC667CB3DE31DBB155CC3824BBD57910E7FE4D0DB86FF36DE0CDC1E00258C5D729B193185CD17AC242C85E6BD23D3990ABB1C65336559524882A6EACA3302020000".to_string(),
    );
    match ctap_hid_fido2::credential_management_delete_credential(
        &ctap_hid_fido2::HidParam::get_default_params(),
        Some("1234"),
        cre_id,
    ) {
        Ok(results) => {
            /*
            for data in results {
                data.print("- credentials");
            }
            */
        }
        Err(error) => {
            println!("- credential_management_delete_credential error: {:?}", error);
        }
    };

    
    println!("credential_management_enumerate_credentials()");
    let rpid_hash: Vec<u8> = util::to_str_hex(
//        "0BDF390F1237B556DB51AF378D5795D5531385CCECDB4499D6BAFBD8918460CA".to_string(),
        "8C5D729B193185CD17AC242C85E6BD23D3990ABB1C65336559524882A6EACA33".to_string(),
    );
    match ctap_hid_fido2::credential_management_enumerate_credentials(
        &ctap_hid_fido2::HidParam::get_default_params(),
        Some("1234"),
        rpid_hash,
    ) {
        Ok(results) => {
            for data in results {
                data.print("- credentials");
            }
        }
        Err(error) => {
            println!("- enumerate credentials error: {:?}", error);
        }
    };

    println!("credential_management_get_creds_metadata()");
    match ctap_hid_fido2::credential_management_get_creds_metadata(
        &ctap_hid_fido2::HidParam::get_default_params(),
        Some("1234"),
    ) {
        Ok(result) => {
            result.print("- creds metadata");
        }
        Err(error) => {
            println!("- creds metadata error: {:?}", error);
        }
    };
    println!("credential_management_enumerate_rps()");
    match ctap_hid_fido2::credential_management_enumerate_rps(
        &ctap_hid_fido2::HidParam::get_default_params(),
        Some("1234"),
    ) {
        Ok(results) => {
            for data in results {
                data.print("- rps");
            }
        }
        Err(error) => {
            println!("- enumerate rps error: {:?}", error);
        }
    };
    // PEND

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

    println!("----- credential-management end -----");
}
