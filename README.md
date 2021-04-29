![license](https://img.shields.io/github/license/gebogebogebo/ctap-hid-fido2)

# ctap-hid-fido2
Rust FIDO2 CTAP library

**Some features of CTAP2.1PRE have been implemented.**

for Mac & Win & raspberry Pi

## Description
- Implements FIDO2 CTAP 2.0 & 2.1PRE (HID)
- [Client to Authenticator Protocol (CTAP)](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html)
- Confirmed operation FIDO key
  - Yubikey Blue (Security Key Series)
  - Yubikey Black (YubiKey 5)
  - FEITIAN ePass FIDO(A4B)
  - FEITIAN BioPass K27 USB Security Key
  - FEITIAN AllinPass FIDO2 K33
  - [SoloKey](https://github.com/solokeys/solo)
  - Nitrokey FIDO2
  - [OpenSK](https://github.com/google/OpenSK)
- Rust Version
  - cargo 1.51.0 , rustc 1.51.0 , rustup 1.23.1
- for Mac
  - macOS Catalina / Big Sur
  - Visual Studio Code
- for Windows
  - Windows10 1909
  - Visual Studio Code

## Author
gebo


## Build and run

#### Windows
- **Run as administrator**

#### raspberry Pi
- **Cargo.toml modified and build**

```
[dependencies]
# hidapi = "1.2.3"    <- comment out
serde_cbor = "0.11.1"
```

- Run as sudo


```
$ chmod +x test_for_pi.sh
$ ./test_for_pi.sh
```

## Examples

#### get_info()

[6.4. authenticatorGetInfo (0x04)](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#authenticatorGetInfo)

> Using this method, platforms can request that the authenticator report a list of its supported protocol versions and extensions, its AAGUID, and other aspects of its overall capabilities. Platforms should use this information to tailor their command parameters choices.



```rust
use ctap_hid_fido2;
use ctap_hid_fido2::HidParam;

fn main() {
    println!("get_info()");
    match ctap_hid_fido2::get_info(&ctap_hid_fido2::HidParam::get_default_params()) {
        Ok(info) => println!("{}",info),
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



#### get_info_u2f()

Created to test [CTAPHID_MSG](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#usb-hid-msg).

```rust
use ctap_hid_fido2;
use ctap_hid_fido2::HidParam;

fn main() {
    println!("get_info_u2f()");
    match ctap_hid_fido2::get_info_u2f(&HidParam::get_default_params()) {
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



#### get_pin_retries()

[6.5.2.2. PIN-Entry and User Verification Retries Counters](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#authnrClientPin-globalState-retries)

pinRetries counter represents the number of attempts left before PIN is disabled.

```Rust
use ctap_hid_fido2;
use ctap_hid_fido2::HidParam;

fn main() {
    println!("get_pin_retries()");
    match ctap_hid_fido2::get_pin_retries(&HidParam::get_default_params()) {
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



#### enable_info_param()

Same as get_info(), but checks if it has a specific feature/version.<br>It is specified by the enum of InfoParam.

```rust
match ctap_hid_fido2::enable_info_param(&HidParam::get_default_params(),InfoParam::VersionsFIDO21PRE) {
    Ok(result) => println!("FIDO 2.1 PRE = {:?}", result),
    Err(e) => println!("- error: {:?}", e),
};
```



#### enable_info_option()

Same as get_info(), but checks if it has a specific option.<br>It is specified by the enum of InfoOption.

- Result is `Option<bool>`
  - `Some(true)` : option is present and set to true
  - `Some(false)` : option is present and set to false
  - `None` : option is absent

```rust
match ctap_hid_fido2::enable_info_option(&HidParam::get_default_params(),InfoOption::BioEnroll) {
    Ok(result) => println!("BioEnroll = {:?}", result),
    Err(e) => println!("- error: {:?}", e),
};
```



#### wink

Just blink the LED on the FIDO key.

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



#### make_credential()
#### get_assertion()
#### verifier::create_challenge()
#### verifier::verify_attestation()
#### verifier::verify_assertion()

```Rust
use ctap_hid_fido2;
use ctap_hid_fido2::util;
use ctap_hid_fido2::verifier;

fn main() {
    println!("----- test-with-pin-non-rk start -----");

    // parameter
    let rpid = "test.com";
    let pin = "1234";
    let challenge = verifier::create_challenge();

    println!("Register - make_credential()");
    println!("- rpid          = {:?}", rpid);
    println!(
        "- challenge({:02}) = {:?}",
        challenge.len(),
        util::to_hex_str(&challenge)
    );

    let att = match ctap_hid_fido2::make_credential(
        &ctap_hid_fido2::HidParam::get_default_params(),
        rpid,
        &challenge,
        Some(pin),
    ) {
        Ok(result) => result,
        Err(err) => {
            println!("- error {:?}", err);
            return;
        }
    };

    println!("- Register Success!!");
    att.print("Attestation");

    println!("Verify");
    let verify_result = verifier::verify_attestation(rpid, &challenge, &att);
    println!(
        "- is_success                   = {:?}",
        verify_result.is_success
    );
    println!(
        "- credential_id({:02})            = {:?}",
        verify_result.credential_id.len(),
        util::to_hex_str(&verify_result.credential_id)
    );
    println!(
        "- credential_publickey_der({:02}) = {:?}",
        verify_result.credential_publickey_der.len(),
        util::to_hex_str(&verify_result.credential_publickey_der)
    );

    println!("Authenticate - get_assertion_with_pin()");
    let challenge = verifier::create_challenge();
    println!(
        "- challenge({:02}) = {:?}",
        challenge.len(),
        util::to_hex_str(&challenge)
    );

    let ass = match ctap_hid_fido2::get_assertion(
        &ctap_hid_fido2::HidParam::get_default_params(),
        rpid,
        &challenge,
        &verify_result.credential_id,
        Some(pin),
    ) {
        Ok(result) => result,
        Err(err) => {
            println!("- Authenticate Error {:?}", err);
            return;
        }
    };
    println!("- Authenticate Success!!");
    ass.print("Assertion");

    println!("Verify");
    let is_success = verifier::verify_assertion(
        rpid,
        &verify_result.credential_publickey_der,
        &challenge,
        &ass,
    );
    println!("- is_success = {:?}", is_success);

    println!("----- test-with-pin-non-rk end -----");
}
```

**console**

```sh
----- test-with-pin-non-rk start -----

Register - make_credential()
- rpid          = "test.com"
- challenge(32) = "769448B3A7F951DEABC96358BFCB897F0336AA63FBE9227625529FDC96317950"
- touch fido key
- Register Success!!

Verify
- is_success                   = true
- credential_id(64)            = "FA02C83CC646726A763035221E4C9CBE23A864D14CCD2CA6116FF8FE6FC5A98BEAB88E160F1FDE88A6955B9DE5BE0896EA1EDEF4F79950FD83427ADC48C84F0C"
- credential_publickey_der(65) = "04BDE029737A3B8546FDE3EF565CBACA9946F29C6865033942918826ACCAC5465E7F8F130455C2C7DE86DBA25CBDBA5BDBE701E22051FE2070B9689FECBF7C6027"

Authenticate - get_assertion_with_pin()
- challenge(32) = "01E2EE84FCA308F66417BBDDD05D27399BF9306707C0B85813CB0679EBBB494F"
- touch fido key
- Authenticate Success!!

Verify
- is_success = true

----- test-with-pin-non-rk end -----
```



#### make_credential_rk()

```Rust
use ctap_hid_fido2;
use ctap_hid_fido2::make_credential_params;
use ctap_hid_fido2::util;
use ctap_hid_fido2::verifier;

fn main() {
    println!("----- test-with-pin-rk start -----");

    // parameter
    let rpid = "ge.com";
    let pin = "1234";
    let challenge = verifier::create_challenge();

    let mut rkparam = make_credential_params::RkParam::default();
    rkparam.user_id = b"11111".to_vec();
    rkparam.user_name = "gebo".to_string();
    rkparam.user_display_name = "GEBO GEBO".to_string();

    println!("Register - make_credential()");
    println!("- rpid          = {:?}", rpid);
    println!(
        "- challenge({:02}) = {:?}",
        challenge.len(),
        util::to_hex_str(&challenge)
    );
    rkparam.print("RkParam");

    let att = match ctap_hid_fido2::make_credential_rk(
        &ctap_hid_fido2::HidParam::get_default_params(),
        rpid,
        &challenge,
        Some(pin),
        &rkparam
        ) {
        Ok(result) => result,
        Err(err) => {
            println!("- Register Error {:?}", err);
            return;
        }
    };

    println!("- Register Success!!");
    att.print("Attestation");

    println!("Verify");
    let verify_result = verifier::verify_attestation(rpid, &challenge, &att);
    println!(
        "- is_success                   = {:?}",
        verify_result.is_success
    );
    println!(
        "- credential_publickey_der({:02}) = {:?}",
        verify_result.credential_publickey_der.len(),
        util::to_hex_str(&verify_result.credential_publickey_der)
    );

    println!("----- test-with-pin-rk end -----");
}
```

**console**

```sh
----- test-with-pin-rk start -----

Register - make_credential()
- rpid          = "ge.com"
- challenge(32) = "FC0644242F0C3FADFD4E5EBEEF4B0CED629C7E76D50417148E5BF5D59EE67298"

RkParam
- user_id(05)       = "3131313131"
- user_name         = "gebo"
- user_display_name = "GEBO GEBO"

- touch fido key
- Register Success!!

Verify
- is_success                   = true
- credential_publickey_der(65) = "045751B33677185635A8136668A64EABEED8DB7350C19E1804B67E66350B297BE0B64EE29ADBF64FE74DA684A2E8BB7F87314BD301C512E660E3C258FDA93C5C5D"

----- test-with-pin-rk end -----
```



#### get_assertions_rk()

```Rust
use ctap_hid_fido2;
use ctap_hid_fido2::util;
use ctap_hid_fido2::verifier;

fn main() {
    println!("----- test-with-pin-rk start -----");

    // parameter
    let rpid = "ge.com";
    let pin = "1234";

    println!("Authenticate - get_assertions_rk()");

    let challenge = verifier::create_challenge();
    let asss = match ctap_hid_fido2::get_assertions_rk(
        &ctap_hid_fido2::HidParam::get_default_params(),
        rpid,
        &challenge,
        Some(pin),
    ) {
        Ok(asss) => asss,
        Err(err) => {
            println!("- Authenticate Error {:?}", err);
            return;
        }
    };
    println!("Authenticate Success!!");

    println!("- Assertion Num = {:?}",asss.len());
    for ass in asss {
        ass.print("Assertion");
        println!(
            "- user_id({:02})       = {:?}",
            ass.user_id.len(),
            util::to_hex_str(&ass.user_id)
        );
    }

    println!("----- test-with-pin-rk end -----");
}
```

**console**

user_name and user_display_name are set only when multiple Assertions are acquired.

```sh
----- test-with-pin-rk start -----
Authenticate - get_assertions_rk()
- touch fido key

Authenticate Success!!
- Assertion Num = 1
- user_id(05)       = "3131313131"
- user_name         = ""
- user_display_name = ""
----- test-with-pin-rk end -----
```



If you want to enable UV-user verification, please specify None instead of a PIN.
make_credential(),get_assertion()

```rust
    let att = match ctap_hid_fido2::make_credential(
        &ctap_hid_fido2::HidParam::get_default_params(),
        rpid,
        &challenge,
        None,
    ) {
        Ok(result) => result,
        Err(err) => {
            println!("- error {:?}", err);
            return;
        }
    };

    let ass = match ctap_hid_fido2::get_assertion(
        &ctap_hid_fido2::HidParam::get_default_params(),
        rpid,
        &challenge,
        &verify_result.credential_id,
        None,
    ) {
        Ok(result) => result,
        Err(err) => {
            println!("- Authenticate Error {:?}", err);
            return;
        }
    };
```



### CTAP 2.1 PRE

#### authenticatorCredentialManagement

This command manages discoverable credentials(resident key) in the authenticator.<br>[6.8. authenticatorCredentialManagement (0x0A)](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#authenticatorCredentialManagement)



##### credential_management_get_creds_metadata()

Get discoverable credentials metadata.

``` rust
match ctap_hid_fido2::credential_management_get_creds_metadata(
    &ctap_hid_fido2::HidParam::get_default_params(),
    pin,
) {
    Ok(result) => println!("{}", result),
    Err(e) => println!("- error: {:?}", e),
};
```



##### credential_management_enumerate_rps()

Enumerate RPs present on the authenticator.

```rust
match ctap_hid_fido2::credential_management_enumerate_rps(&HidParam::get_default_params(), pin)
{
    Ok(results) => {
        for r in results {
            println!("## rps\n{}", r);
        }
    }
    Err(e) => println!("- error: {:?}", e),
}
```



##### credential_management_enumerate_credentials()

Enumerate the credentials for a RP.

```rust
match ctap_hid_fido2::credential_management_enumerate_credentials(
    &HidParam::get_default_params(),
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



##### credential_management_delete_credential()

Delete a credential.

```rust
let mut pkcd = PublicKeyCredentialDescriptor::default();
pkcd.id = util::to_str_hex(credential_id.unwrap());
pkcd.ctype = "public_key".to_string();

match ctap_hid_fido2::credential_management_delete_credential(
    &HidParam::get_default_params(),
    pin,
    Some(pkcd),
) {
    Ok(_) => println!("- success"),
    Err(e) => println!("- error: {:?}",e),
}
```



#### authenticatorBioEnrollment

This command manages the fingerprints in the authenticator.<br>[6.7. authenticatorBioEnrollment (0x09)](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#authenticatorBioEnrollment)



##### bio_enrollment_get_fingerprint_sensor_info()

Get fingerprint sensor information.

```Rust
match ctap_hid_fido2::bio_enrollment_get_fingerprint_sensor_info(
    &HidParam::get_default_params(),
) {
    Ok(result) => println!("- {:?}", result),
    Err(e) => println!("- error: {:?}", e),
}
```



##### bio_enrollment_enumerate_enrollments()

Enumurate a list of registered fingerprints.

```Rust
match ctap_hid_fido2::bio_enrollment_enumerate_enrollments(
    &HidParam::get_default_params(),
    pin,
) {
    Ok(infos) => for i in infos {println!("- {}", i)},
    Err(e) => println!("- error: {:?}", e)
}
```



##### bio_enrollment_begin(),bio_enrollment_next()

Enroll one fingerprint.<br>run `bio_enrollment_begin` first and then `bio_enrollment_next` several times.<br>`is_finish` detects the completion of registration.

```rust
fn bio_enrollment(pin: &str) -> Result<(), String> {
    println!("bio_enrollment_begin");
    let result = ctap_hid_fido2::bio_enrollment_begin(
        &HidParam::get_default_params(),
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



##### bio_enrollment_set_friendly_name()

Update the registered name of the fingerprint.

```rust
match ctap_hid_fido2::bio_enrollment_set_friendly_name(
    &HidParam::get_default_params(),
    pin,
    TemplateInfo::new(util::to_str_hex(template_id), name),
) {
    Ok(()) => println!("- Success"),
    Err(e) => println!("- error: {:?}", e),
}
```



##### bio_enrollment_remove()

Delete a fingerprint.

```rust
match ctap_hid_fido2::bio_enrollment_remove(
     &HidParam::get_default_params(),
     pin,
     util::to_str_hex(template_id),
 ) {
     Ok(_) => println!("- Success"),
     Err(e) => println!("- error: {:?}", e),
 }
```




## Nitrokey Custom Commands

for Nitrokey FIDO2 only.



#### nitrokey::get_version()
Query the firmware version of Nitrokey.

```rust
fn main() {
    println!("----- Nitrokey GETVERSION start -----");
    // get 4byte payload "2001" -> ver 2.0.0.1
    match ctap_hid_fido2::nitrokey::get_version(&ctap_hid_fido2::HidParam::get_default_params()) {
        Ok(version) => println!("version = {}", version),
        Err(err) => println!("version = {}", err),
    };
    println!("----- Nitrokey GETVERSION end -----");
}
```

**console**

``` sh
----- Nitrokey GETVERSION start -----
version = 2.2.0.1
----- Nitrokey GETVERSION end -----
```



#### nitrokey::get_status()
Query the Status of Nitrokey.

```rust
fn main() {
    println!("----- Nitrokey GETSTATUS start -----");
    match ctap_hid_fido2::nitrokey::get_status(&ctap_hid_fido2::HidParam::get_default_params()) {
        Ok(status) => status.print("status"),
        Err(err) => println!("status = {}", err),
    };
    println!("----- Nitrokey GETSTATUS end -----");
}
```

**console**

```sh
----- Nitrokey GETSTATUS start -----
status
- is_button_pressed_raw          = false
- button_state                   = 3
- button_state                   = BstUnpressed
- last_button_cleared_time_delta = 131
- last_button_pushed_time_delta  = 131
- led_is_blinking                = false
- u2f_ms_clear_button_period     = 200
- u2f_ms_init_button_period      = 5
- button_min_press_t_ms          = 100
----- Nitrokey GETSTATUS end -----
```



#### nitrokey::get_rng()

Generate a random number.

```rust
fn main() {
    println!("----- Nitrokey GETRNG start -----");
    // get 8 byte rundom data
    match ctap_hid_fido2::nitrokey::get_rng(&ctap_hid_fido2::HidParam::get_default_params(), 8) {
        Ok(rng) => println!("rng = {}", rng),
        Err(err) => println!("rng = {}", err),
    };
    println!("----- Nitrokey GETRNG end -----");
}
```

**console**

```sh
----- Nitrokey GETRNG start -----
rng = D93C4D39DAA8FEF8
----- Nitrokey GETRNG end -----
```

