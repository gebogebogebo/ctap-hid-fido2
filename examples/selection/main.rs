use anyhow::{anyhow, Result};
use ctap_hid_fido2::fidokey::get_info::InfoParam;
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn main() -> Result<()> {
    println!("----- selection sample -----");

    // FidoKeyHidFactory::create will return an error if no device is found or multiple devices are found.
    let device = match FidoKeyHidFactory::create(&Cfg::init()) {
        Ok(d) => {
            println!("Found one FIDO2 device. Proceeding with selection test.");
            d
        }
        Err(e) => {
            // Check the error message to determine the cause
            let error_message = e.to_string();
            if error_message.contains("FIDO device not found.") {
                println!("No FIDO2 device found.");
            } else if error_message.contains("Multiple FIDO devices found.") {
                println!("Multiple FIDO2 devices found. This example requires exactly one device.");
            } else {
                eprintln!("Error initializing FIDO2 device: {:?}", e);
            }
            return Ok(()); // Exit if not exactly one device
        }
    };

    // Check if the device supports FIDO2.1 for selection
    if !device.enable_info_param(&InfoParam::VersionsFido21)? {
        return Err(anyhow!(
            "This authenticator is not supported for this functions."
        ));
    }

    let device_arc = Arc::new(device);
    let device_for_thread = Arc::clone(&device_arc);

    // Create a sub-thread and execute selection on the device in that thread
    println!("Spawning a thread to perform authenticatorSelection...");
    let selection_handle = thread::spawn(move || {
        println!("Selection thread: Attempting authenticatorSelection...");
        match device_for_thread.selection() {
            Ok(_) => println!("Selection thread: authenticatorSelection successful."),
            // In case of cancel_selection, 0x2D CTAP2_ERR_KEEPALIVE_CANCEL occurs.
            Err(err) => eprintln!("Selection thread: authenticatorSelection failed: {:?}", err),
        }
    });

    // Main thread waits for 3 seconds
    println!("Main thread: Waiting for 3 seconds...");
    thread::sleep(Duration::from_secs(3));

    // Execute cancel_selection on the device
    println!("Main thread: Attempting to cancel selection...");
    match device_arc.cancel_selection() {
        Ok(_) => println!("Main thread: Cancel selection successful."),
        Err(err) => eprintln!("Main thread: Cancel selection failed: {:?}", err),
    }

    // Wait for the selection thread to finish
    if let Err(e) = selection_handle.join() {
        eprintln!("Selection thread panicked: {:?}", e);
    }

    println!("Selection process finished.");
    Ok(())
}
