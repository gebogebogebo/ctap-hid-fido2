use anyhow::Result;
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};

fn main() -> Result<()> {
    println!("----- selection sample -----");
    let device = FidoKeyHidFactory::create(&Cfg::init())?;
    device.selection()?;
    println!("selection called");
    Ok(())
}
