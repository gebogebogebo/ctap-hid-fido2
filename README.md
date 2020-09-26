https://img.shields.io/github/license/gebogebogebo/ctap-hid-fido2

# ctap-hid-fido2
Rust FIDO2 CTAP library

## Description
- Implements FIDO2 CTAP (HID)
- [Client to Authenticator Protocol (CTAP)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
- Confirmed operation FIDO key
  - Yubikey Blue (Security Key Series)
  - Yubikey Black (YubiKey 5)
  - FEITIAN BioPass K27 USB Security Key
  - FEITIAN AllinPass FIDO2 K33
  - SoloKey
- Rust Version
  - cargo 1.45.1 (f242df6ed 2020-07-22)
  - rustc 1.45.2 (d3fb005a3 2020-07-31)
  - rustup 1.22.1 (b01adbbc3 2020-07-08)
- for Mac
  - macOS Catalina 10.15.6
  - Visual Studio Code
- for Windows
  - Windows10 1909
  - Visual Studio Code

## Author
gebo



## Examples

#### get_info()

```Rust
use ctap_hid_fido2;

fn main() {
    println!("get_info()");
    let infos = match ctap_hid_fido2::get_info(&ctap_hid_fido2::HidParam::get_default_params()) {
        Ok(result) => result,
        Err(error) => {
            println!("error: {:?}", error);
            return;
        },
    };    
    for (key, value) in infos {
        println!("- {} / {}", key, value);
    }
}
```

console

```sh
get_info()
- versions / U2F_V2
- versions / FIDO_2_0
- extensions / hmac-secret
- aaguid / FA2B99DC9E3942578F924A30D23C4118
- options-rk / true
- options-up / true
- options-plat / false
- options-clientPin / true
- max_msg_size / 1200
- pin_protocols / 1
```



#### get_pin_retries()

```Rust
use ctap_hid_fido2;

fn main() {
    println!("get_pin_retries()");
    let retry = match ctap_hid_fido2::get_pin_retries(&ctap_hid_fido2::HidParam::get_default_params()) {
        Ok(result) => result,
        Err(error) => {
            println!("error: {:?}", error);
            return;
        },
    };    
    println!("- pin retry = {}", retry);
}
```

console

```sh
get_pin_retries()
- pin retry = 8
```



#### make_credential()

#### get_assertion()

```Rust
use ctap_hid_fido2;
use ctap_hid_fido2::util;

fn main() {
    println!("----- test-with-pin-non-rk start -----");

    // parameter
    let rpid = "test.com";
    let challenge = b"this is challenge".to_vec();
    let pin = "1234";

    println!("make_credential()");
    let cre_id = match ctap_hid_fido2::make_credential(
        &ctap_hid_fido2::HidParam::get_default_params(),
        rpid,
        &challenge,
        pin,
    ) {
        Ok(result) => result.credential_id,
        Err(err) => {
            println!("- Register Error {:?}", err);
            return;
        }
    };

    println!("- Register Success!!");
    println!(
        "- credential_id({:02}) = {:?}",
        cre_id.len(),
        util::to_hex_str(&cre_id)
    );

    println!("get_assertion_with_pin()");
    let att = match ctap_hid_fido2::get_assertion(
        &ctap_hid_fido2::HidParam::get_default_params(),
        rpid,
        &challenge,
        &cre_id,
        pin,
    ) {
        Ok(result) => result,
        Err(err) => {
            println!("- Authenticate Error {:?}", err);
            return;
        }
    };
    println!("- Authenticate Success!!");
    println!("- sign_count = {:?}", att.sign_count);
    println!(
        "- signature({:02}) = {:?}",
        att.signature.len(),
        util::to_hex_str(&att.signature)
    );

    println!("----- test-with-pin-non-rk end -----");
}
```

console

```sh
----- test-with-pin-non-rk start -----
make_credential()
- touch fido key
- Register Success!!
- credential_id(64) = "65CE1DDB3B5BF9FDD85664F324D575478783121DE0D4489E0CB5BAB24ED8C8F4965235E0F80011B7D13391295A42C964FB256DC02768B1A3DF434FEB83EE1CE7"
get_assertion_with_pin()
- touch fido key
- Authenticate Success!!
- sign_count = 271
- signature(71) = "304502201B03779653849389198BF8291C0170AD51BBC0C714E2AF1D260A3B3413E75D51022100DA9053755FD1C74214F70E58FCB1E8E302C617BA69B297AC855D15BF4D5CA748"
----- test-with-pin-non-rk end -----
```



#### wink

Just blink the LED on the FIDO key

```Rust
use ctap_hid_fido2;

fn main() {
    println!("----- wink start -----");
    if let Err(msg) = ctap_hid_fido2::wink(&ctap_hid_fido2::HidParam::get_default_params()){
        println!("error: {:?}", msg);
    }
    println!("----- wink end -----");
}
```

