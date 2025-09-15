use anyhow::Result;
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};

#[tokio::main(flavor = "current_thread")]async fn main() -> Result<()> {
    let device = FidoKeyHidFactory::create_async(&Cfg::init()).await?;

    println!("We are going to Wink this device:");
    println!("{}", device.get_info().await?);

    println!("----- wink start -----");
    device.wink().await?;
    device.wink().await?;
    println!("----- wink end -----");
    
    Ok(())
}
