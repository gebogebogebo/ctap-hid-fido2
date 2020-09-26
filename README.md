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



#### make_credential_with_pin_non_rk()

#### get_assertion_with_pin()

```Rust
use ctap_hid_fido2;
use ctap_hid_fido2::util;

fn main() {
    println!("----- test-with-pin-non-rk start -----");
    
    // parameter
    let rpid = "test.com";
    let challenge = b"this is challenge".to_vec();
    let pin = "1234";

    println!("make_credential_with_pin_non_rk()");
    let cre_id = match ctap_hid_fido2::make_credential_with_pin_non_rk(
                                &ctap_hid_fido2::HidParam::get_default_params(),
                                rpid,
                                &challenge,
                                pin){
        Ok(result) => result.credential_id,
        Err(err) => {
            println!("- Register Error {:?}",err);
            return;
        }
    };
    println!("- Register Success!!");
    println!("- credential_id({:02})  = {:?}", cre_id.len(),util::to_hex_str(&cre_id));

    println!("get_assertion_with_pin()");
    let result = match ctap_hid_fido2::get_assertion_with_pin(
                                        &ctap_hid_fido2::HidParam::get_default_params(),
                                        rpid,
                                        &challenge,
                                        &cre_id,
                                        pin){
        Ok(result) => result,
        Err(err) => {
            println!("- Authenticate Error {:?}",err);
            return;
        }
    };
    println!("- Authenticate Success!!");
    println!("- number_of_credentials = {:?}",result.number_of_credentials);

    println!("----- test-with-pin-non-rk end -----");
}
```

console

```sh
----- test-with-pin-non-rk start -----
make_credential_with_pin_non_rk()
- touch fido key
- Register Success!!
- credential_id(64)  = "1378DDCAE25657B1EB45BB09D5D2DC41E6B549A32419C34CEC251104500CBAACD52B643D4D21F8DE459CFB59D52ACF52D284E2D87BCA6A4D65DA729FD902F50D"
get_assertion_with_pin()
- touch fido key
- Authenticate Success!!
- number_of_credentials = 0
----- test-with-pin-non-rk end -----
```



#### wink

Just blink the LED on the FIDO key...

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

