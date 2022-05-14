![license](https://img.shields.io/github/license/gebogebogebo/ctap-hid-fido2)
![macOS](https://img.shields.io/badge/macOS-Supported-orange)
![Windows](https://img.shields.io/badge/Windows-Supported-orange)
![Raspberry-Pi](https://img.shields.io/badge/Raspberry_Pi-Supported-orange)



# ctap-hid-fido2
Rust FIDO2 CTAP library ( and cli tool [ctapcli](README_ctapcli.md) ).

Authentication using FIDO2-compliant security keys (e.g. Yubikey) is possible.

- Features

  - Register and Authenticate.
  - Register or change PIN.
  - Enrollment and deletion of fingerprints.
  - Management of credentials recorded in security keys.

- Version
  - Ver 3.3.0
    - Implement `Credential Blob Extension`. → [Register and Authenticate Examples](README_Register_and_Authenticate.md)

  - Ver 3.2.0
  
    - Implement `Authenticator Config` - `set_min_pin_length()`. → [Authenticator Config(CTAP 2.1)](README_Authenticator_Config.md)
    - Implement `Set Min Pin Length Extension`. → [Register and Authenticate Examples](README_Register_and_Authenticate.md)

    - Implement `Large Blob` → [Large Blob(CTAP 2.1)](README_Large_Blob.md)

  - Ver 3.1.0

    - Implement `Authenticator Config` - `toggle_always_uv()`. → [Authenticator Config(CTAP 2.1)](README_Authenticator_Config.md)
  
    - add cli tool [ctapcli](README_ctapcli.md)
  


  - Ver 3.0.0
    - The usage has changed from Ver2. → [How to Use](#how-to-use).




## How to use Registration and Authentication

```rust
use ctap_hid_fido2::{
    fidokey::{GetAssertionArgsBuilder, MakeCredentialArgsBuilder},
    verifier, Cfg, FidoKeyHidFactory,
};

fn main() {
    let rpid = "reg-auth-example-app";
    let pin = get_input_with_message("input PIN:");

    println!("Register");
    // create `challenge`
    let challenge = verifier::create_challenge();

    // create `MakeCredentialArgs`
    let make_credential_args = MakeCredentialArgsBuilder::new(rpid, &challenge)
        .pin(&pin)
        .build();

    // create `FidoKeyHid`
    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();

    // get `Attestation` Object
    let attestation = device
        .make_credential_with_args(&make_credential_args)
        .unwrap();
    println!("- Register Success");

    // verify `Attestation` Object
    let verify_result = verifier::verify_attestation(rpid, &challenge, &attestation);
    if !verify_result.is_success {
        println!("- ! Verify Failed");
        return;
    }

    // store Credential Id and Publickey
    let userdata_credential_id = verify_result.credential_id;
    let userdata_credential_publickey_der = verify_result.credential_publickey_der;

    println!("Authenticate");
    // create `challenge`
    let challenge = verifier::create_challenge();

    // create `GetAssertionArgs`
    let get_assertion_args = GetAssertionArgsBuilder::new(rpid, &challenge)
        .pin(&pin)
        .credential_id(&userdata_credential_id)
        .build();

    // get `Assertion` Object
    let assertions = device.get_assertion_with_args(&get_assertion_args).unwrap();
    println!("- Authenticate Success");

    // verify `Assertion` Object
    if !verifier::verify_assertion(
        rpid,
        &userdata_credential_publickey_der,
        &challenge,
        &assertions[0],
    ) {
        println!("- ! Verify Assertion Failed");
    }
}

pub fn get_input() -> String {
    let mut word = String::new();
    std::io::stdin().read_line(&mut word).ok();
    return word.trim().to_string();
}

pub fn get_input_with_message(message: &str) -> String {
    println!("{}", message);
    let input = get_input();
    println!();
    input
}
```

- See [How to use](#How to use) and [Examples](#Examples) for detailed instructions.




## Description
**ctap-hid-fido2** is a crate implementing [CTAP 2.0 and 2.1](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html), allowing direct control of FIDO2-compliant Authenticators such as Yubikey.<br>For more information on FIDO, see [FIDO Alliance Page](https://fidoalliance.org/).



- Implements FIDO2 CTAP 2.0 & 2.1 (HID)
- [Client to Authenticator Protocol (CTAP)](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html)
- Supported FIDO key
  - [Yubikey Bio](https://www.yubico.com/products/yubikey-bio-series/)
  - [Yubikey](https://www.yubico.com/products/)
  - FEITIAN ePass FIDO(A4B)
  - FEITIAN BioPass K27 USB Security Key
  - FEITIAN AllinPass FIDO2 K33
  - [SoloKey](https://github.com/solokeys/solo)
  - [Nitrokey FIDO2](https://www.nitrokey.com/)
  - [OpenSK](https://github.com/google/OpenSK)
  - Idem Key
- Rust Version
  - cargo 1.59.0 , rustc 1.59.0 , rustup 1.24.3
- for Mac
  - macOS Monterey
- for Windows
  - Windows11 (21H2)
- for Raspberry Pi
  - Raspberry Pi OS 32bit (11 bullseye)



## Author
gebo




## Build and run

#### macOS

Nothing in particular to worry about using it.



#### Windows

- **Run as administrator**

In Windows, the security key via HID cannot be accessed unless the executing exe has administrator privileges.



#### raspberry Pi

- **installing `libusb` and `libudev` package**

(The same may be true for Linux, such as Ubuntu)

If you get the following error with the libusb-1.0 dependency and cannot build, you can solve the problem by doing the following.

```sh
sudo apt install -y libusb-1.0-0-dev libudev-dev
```



## How to use

**PIN has to be set**

Unless noted in the following Examples, a PIN must be set in the Authenticator.



**create FidoKeyHid object**

First, create a device object with `FidoKeyHidFactory::create`.

If no Authenticator can be detected on the HID device, an error will result.

```rust
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};
...

let device = match FidoKeyHidFactory::create(&Cfg::init()) {
  Ok(d) => d,
  Err(e) => {
      println!("error: {:?}", e);
      return;
  }
};
```

If more than one Authenticator is detected, an error will result. See the following description for **Multi-Authenticator support**



**Cfg**

The argument `Cfg` is fine with the default value you create using `init()`, but you can customize it to change the behavior a bit, see [Cfg definition](https://github.com/gebogebogebo/ctap-hid-fido2/blob/24df395e4ce1c3bcacdba69c63fc3a8ff5510d2c/src/lib.rs#L39-L55).



**FidoKeyHid**

Use Authenticator with the methods implemented in `FidoKeyHid`.<br>For example, `get_pin_retries()` can be used to obtain the number of PIN retries.

```rust
match device.get_pin_retries() {
    Ok(retry) => println!("{}", retry),
    Err(e) => println!("error: {:?}", e),
}
```



**Multi-Authenticator support**

If you have multiple Authenticators connected to the HID and want to control each device individually, use `get_fidokey_devices()` and `create_by_params()`.

```rust
let devs = ctap_hid_fido2::get_fidokey_devices();
for dev in devs {
  println!("- vid=0x{:04x} , pid=0x{:04x} , info={:?}",dev.vid, dev.pid, dev.info);

  let fidokey = FidoKeyHidFactory::create_by_params(&vec![dev.param], &Cfg::init()).unwrap();
  let info = fidokey.get_info().unwrap();
  println!("{}", info);
}
```



## Examples

See the following links for examples of various patterns.

- [Register and Authenticate Examples](README_Register_and_Authenticate.md)

- [Get Authenticator info and Util Examples](README_Get_Info.md)
- [Credential management (CTAP 2.1)](README_Credential_management.md)
- [Biometric management (CTAP 2.1)](README_Biometric_management.md)
- [Authenticator Config(CTAP 2.1)](README_Authenticator_Config.md)
- [Large Blob(CTAP 2.1)](README_Large_Blob.md)



## CLI tool

CLI tool can be used.

- [ctapcli](README_ctapcli.md)
