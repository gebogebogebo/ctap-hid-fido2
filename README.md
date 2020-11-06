![license](https://img.shields.io/github/license/gebogebogebo/ctap-hid-fido2)

# ctap-hid-fido2
Rust FIDO2 CTAP library
for Mac & Win

Sorry, Linux is not yet supported.

## Description
- Implements FIDO2 CTAP (HID)
- [Client to Authenticator Protocol (CTAP)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
- Confirmed operation FIDO key
  - Yubikey Blue (Security Key Series)
  - Yubikey Black (YubiKey 5)
  - FEITIAN ePass FIDO(A4B)
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
        }
    };
    for (key, value) in infos {
        println!("- {} / {}", key, value);
    }
}
```

**console**

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
    let retry =
        match ctap_hid_fido2::get_pin_retries(&ctap_hid_fido2::HidParam::get_default_params()) {
            Ok(result) => result,
            Err(error) => {
                println!("error: {:?}", error);
                return;
            }
        };
    println!("- pin retry = {}", retry);
}
```

**console**

```sh
get_pin_retries()
- pin retry = 8
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

```
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
