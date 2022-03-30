![license](https://img.shields.io/github/license/gebogebogebo/ctap-hid-fido2)
![macOS](https://img.shields.io/badge/macOS-Supported-orange)
![Windows](https://img.shields.io/badge/Windows-Supported-orange)
![Raspberry-Pi](https://img.shields.io/badge/Raspberry_Pi-Supported-orange)



# ctap-hid-fido2
Rust FIDO2 CTAP library



## Description
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

```sh
$ cargo build
$ cargo run
```



#### Windows

- **Run as administrator**



#### raspberry Pi

(The same may be true for Linux, such as Ubuntu)

If you get the following error with the libusb-1.0 dependency and cannot build, you can solve the problem by doing the following.

- installing `libusb` and `libudev` package

```sh
sudo apt install -y libusb-1.0-0-dev libudev-dev
```



## Examples

**PIN has to be set**

Unless noted in the following samples, a PIN must be set in the Authenticator.



### Register and Authenticate

[Register and Authenticate Examples](README_Register_and_Authenticate.md)



### get_info()

[6.4. authenticatorGetInfo (0x04)](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo)

```rust
use ctap_hid_fido2;
use ctap_hid_fido2::Cfg;

fn main() {
    println!("get_info()");
    match ctap_hid_fido2::get_info(&Cfg::init()) {
        Ok(info) => println!("{}", info),
        Err(e) => println!("error: {:?}", e),
    }
}
```

**console**

```sh
get_info()
- versions                      = ["U2F_V2", "FIDO_2_0", "FIDO_2_1_PRE"]
- extensions                    = ["credProtect", "hmac-secret"]
- aaguid(16)                    = EE882879721C491397753DFCCE97072A
- options                       = [("rk", true), ("up", true), ("plat", false), ("clientPin", true), ("credentialMgmtPreview", true)]
- max_msg_size                  = 1200
- pin_uv_auth_protocols         = [1]
- max_credential_count_in_list  = 8
- max_credential_id_length      = 128
- transports                    = ["usb"]
- algorithms                    = [("alg", "-7"), ("type", "public-key"), ("alg", "-8"), ("type", "public-key")]
```



### get_info_u2f()

Created to test [CTAPHID_MSG](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#usb-hid-msg).

```rust
use ctap_hid_fido2;
use ctap_hid_fido2::Cfg;

fn main() {
    println!("get_info_u2f()");
    match ctap_hid_fido2::get_info_u2f(&Cfg::init()) {
        Ok(result) => println!("{:?}", result),
        Err(e) => println!("error: {:?}", e),
    }
}
```

**console**

```sh
get_info_u2f()
"U2F_V2"
```



### get_pin_retries()

[6.5.5.2. Platform getting PIN retries from Authenticator](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#gettingPINRetries)

pinRetries counter represents the number of attempts left before PIN is disabled.

```Rust
use ctap_hid_fido2;
use ctap_hid_fido2::Cfg;

fn main() {
    println!("get_pin_retries()");
    match ctap_hid_fido2::get_pin_retries(&Cfg::init()) {
        Ok(retry) => println!("{}", retry),
        Err(e) => println!("error: {:?}", e),
    };
}
```

**console**

```sh
get_pin_retries()
8
```



### get_uv_retries()

**Yubikey Bio Only**

[6.5.5.3. Platform getting UV Retries from Authenticator](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#gettingUVRetries)

UV retries count is the number of built-in UV attempts remaining before built-in UV is disabled on the device.

```rust
use ctap_hid_fido2;
use ctap_hid_fido2::Cfg;

fn main() {
    println!("get_uv_retries()");
    match ctap_hid_fido2::get_uv_retries(&Cfg::init()) {
        Ok(retry) => println!("{}", retry),
        Err(e) => println!("error: {:?}", e),
    };
}
```



### enable_info_param()

Same as get_info(), but checks if it has a specific feature/version.<br>It is specified by the enum of InfoParam.

```rust
match ctap_hid_fido2::enable_info_param(&Cfg::init(),InfoParam::VersionsFIDO21PRE) {
    Ok(result) => println!("FIDO 2.1 PRE = {:?}", result),
    Err(e) => println!("- error: {:?}", e),
};
```



### enable_info_option()

Same as get_info(), but checks if it has a specific option.<br>It is specified by the enum of InfoOption.

- Result is `Option<bool>`
  - `Some(true)` : option is present and set to true
  - `Some(false)` : option is present and set to false
  - `None` : option is absent

```rust
match ctap_hid_fido2::enable_info_option(&Cfg::init(),InfoOption::BioEnroll) {
    Ok(result) => println!("BioEnroll = {:?}", result),
    Err(e) => println!("- error: {:?}", e),
};
```



### wink()

Just blink the LED on the FIDO key.

```Rust
use ctap_hid_fido2;
use ctap_hid_fido2::Cfg;

fn main() {
    if let Err(msg) = ctap_hid_fido2::wink(&Cfg::init()){
        println!("error: {:?}", msg);
    }
}
```





## CTAP 2.1

### authenticatorCredentialManagement

This command manages discoverable credentials(resident key) in the authenticator.<br>[6.8. authenticatorCredentialManagement (0x0A)](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#authenticatorCredentialManagement)



#### credential_management_get_creds_metadata()

Get discoverable credentials metadata.

``` rust
match ctap_hid_fido2::credential_management_get_creds_metadata(
    &Cfg::init(),
    pin,
) {
    Ok(result) => println!("{}", result),
    Err(e) => println!("- error: {:?}", e),
};
```



#### credential_management_enumerate_rps()

Enumerate RPs present on the authenticator.

```rust
match ctap_hid_fido2::credential_management_enumerate_rps(&Cfg::init(), pin)
{
    Ok(results) => {
        for r in results {
            println!("## rps\n{}", r);
        }
    }
    Err(e) => println!("- error: {:?}", e),
}
```



#### credential_management_enumerate_credentials()

Enumerate the credentials for a RP.

```rust
match ctap_hid_fido2::credential_management_enumerate_credentials(
    &Cfg::init(),
    pin,
    rpid_hash_bytes,
) {
    Ok(results) => {
        for c in results {
            println!("## credentials\n{}", c);
        }
    }
    Err(e) => println!("- error: {:?}", e),
}
```



#### credential_management_delete_credential()

Delete a credential.

```rust
let mut pkcd = PublicKeyCredentialDescriptor::default();
pkcd.id = util::to_str_hex(credential_id.unwrap());
pkcd.ctype = "public_key".to_string();

match ctap_hid_fido2::credential_management_delete_credential(
    &Cfg::init(),
    pin,
    Some(pkcd),
) {
    Ok(_) => println!("- success"),
    Err(e) => println!("- error: {:?}",e),
}
```



### authenticatorBioEnrollment

This command manages the fingerprints in the authenticator.<br>[6.7. authenticatorBioEnrollment (0x09)](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorBioEnrollment)



#### bio_enrollment_get_fingerprint_sensor_info()

Get fingerprint sensor information.

```Rust
match ctap_hid_fido2::bio_enrollment_get_fingerprint_sensor_info(
    &Cfg::init(),
) {
    Ok(result) => println!("- {:?}", result),
    Err(e) => println!("- error: {:?}", e),
}
```



#### bio_enrollment_enumerate_enrollments()

Enumurate a list of registered fingerprints.

```Rust
match ctap_hid_fido2::bio_enrollment_enumerate_enrollments(
    &Cfg::init(),
    pin,
) {
    Ok(infos) => for i in infos {println!("- {}", i)},
    Err(e) => println!("- error: {:?}", e)
}
```



#### bio_enrollment_begin(),bio_enrollment_next()

Enroll one fingerprint.<br>run `bio_enrollment_begin` first and then `bio_enrollment_next` several times.<br>`is_finish` detects the completion of registration.

```rust
fn bio_enrollment(pin: &str) -> Result<(), String> {
    println!("bio_enrollment_begin");
    let result = ctap_hid_fido2::bio_enrollment_begin(
        &Cfg::init(),
        pin,
        Some(10000),
    )?;
    println!("{}", result.1);
    println!("");

    for _counter in 0..10 {
        if bio_enrollment_next(&result.0)? {
            break;
        }
    }
    Ok(())
}

fn bio_enrollment_next(enroll_status: &EnrollStatus1) -> Result<bool, String> {
    println!("bio_enrollment_next");
    let result = ctap_hid_fido2::bio_enrollment_next(enroll_status, Some(10000))?;
    println!("{}", result);
    println!("");
    Ok(result.is_finish)
}
```



#### bio_enrollment_set_friendly_name()

Update the registered name of the fingerprint.

```rust
match ctap_hid_fido2::bio_enrollment_set_friendly_name(
    &Cfg::init(),
    pin,
    template_id, "display-name",
) {
    Ok(()) => println!("- Success"),
    Err(e) => println!("- error: {:?}", e),
}
```



#### bio_enrollment_remove()

Delete a fingerprint.

```rust
match ctap_hid_fido2::bio_enrollment_remove(
     &Cfg::init(),
     pin,
     template_id,
 ) {
     Ok(_) => println!("- Success"),
     Err(e) => println!("- error: {:?}", e),
 }
```

