use anyhow::Result;
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};

fn main() -> Result<()> {
    let device = FidoKeyHidFactory::create(&Cfg::init())?;

    println!("We are going to Wink this device:");
    println!("{}", device.get_info()?);

    println!("----- wink start -----");
    device.wink()?;
    device.wink()?;
    println!("----- wink end -----");

    Ok(())
}
