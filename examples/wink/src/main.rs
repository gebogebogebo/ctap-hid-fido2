use anyhow::Result;
use ctap_hid_fido2;

fn main() -> Result<()> {
    println!("----- wink start -----");

    //ctap_hid_fido2::wink(&ctap_hid_fido2::HidParam::get_default_params())?;

    if let Err(msg) = ctap_hid_fido2::wink(&ctap_hid_fido2::HidParam::get_default_params()){
        println!("error: {:?}", msg);
    }

    println!("----- wink end -----");
    Ok(())
}