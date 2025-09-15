use anyhow::Result;
use ctap_hid_fido2::{fidokey::get_info::InfoOption, Cfg, FidoKeyHidFactory};

#[tokio::main(flavor = "current_thread")]async fn main() -> Result<()> {
    println!("----- get-info start -----");

    println!("get_hid_devices()");
    let devs = ctap_hid_fido2::get_hid_devices_async().await;
    for info in devs {
        println!(
            "- vid=0x{:04x} , pid=0x{:04x} , info={:?}",
            info.vid, info.pid, info.info
        );
    }

    println!("get_fidokey_devices()");
    let devs = ctap_hid_fido2::get_fidokey_devices_async().await;
    for info in devs {
        println!("\n\n---------------------------------------------");
        println!(
            "- vid=0x{:04x} , pid=0x{:04x} , info={:?}",
            info.vid, info.pid, info.info
        );

        let dev = FidoKeyHidFactory::create_by_params_async(&[info.param], &Cfg::init()).await?;

        println!("get_info()");
        match dev.get_info().await {
            Ok(info) => println!("{}", info),
            Err(e) => println!("error: {:?}", e),
        }

        println!("get_pin_retries()");
        match dev.get_pin_retries().await {
            Ok(info) => println!("{}", info),
            Err(e) => println!("error: {:?}", e),
        }

        println!("get_info_u2f()");
        match dev.get_info_u2f().await {
            Ok(info) => println!("{}", info),
            Err(e) => println!("error: {:?}", e),
        }

        println!("enable_info_option() - ClientPin");
        match dev.enable_info_option(&InfoOption::ClientPin).await {
            Ok(result) => println!("PIN = {:?}", result),
            Err(e) => println!("- error: {:?}", e),
        }
    }

    println!("----- get-info end -----");
    Ok(())
}
