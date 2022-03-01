# Register and Authenticate



## Legacy Pattern Sample

### non-discoverable credentials/non-resident-key

```rust
use anyhow::Result;
use ctap_hid_fido2;
use ctap_hid_fido2::util;
use ctap_hid_fido2::verifier;
use ctap_hid_fido2::Cfg;

fn main() -> Result<()> {
    println!("----- test-with-pin-non-rk start -----");

    // parameter
    let rpid = "test.com";
    let pin = Some("1234");
    // let pin = None; // Yubikey bio for fingerprint authentication
    let challenge = verifier::create_challenge();

    // Register
    println!("Register - make_credential()");
    println!("- rpid          = {:?}", rpid);
    println!(
        "- challenge({:02}) = {:?}",
        challenge.len(),
        util::to_hex_str(&challenge)
    );

    let att = ctap_hid_fido2::make_credential(
        &Cfg::init(),
        rpid,
        &challenge,
        pin,
    )?;

    println!("- Register Success!!");
    println!("Attestation");
    println!("{}", att);

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
    println!("");

    // Authenticate
    println!("Authenticate - get_assertion_with_pin()");
    let challenge = verifier::create_challenge();
    println!(
        "- challenge({:02}) = {:?}",
        challenge.len(),
        util::to_hex_str(&challenge)
    );

    let ass = ctap_hid_fido2::get_assertion(
        &Cfg::init(),
        rpid,
        &challenge,
        &verify_result.credential_id,
        pin,
    )?;
    println!("- Authenticate Success!!");
    println!("Assertion");
    println!("{}", ass);

    println!("Verify");
    let is_success = verifier::verify_assertion(
        rpid,
        &verify_result.credential_publickey_der,
        &challenge,
        &ass,
    );
    println!("- is_success = {:?}", is_success);

    println!("----- test-with-pin-non-rk end -----");
    Ok(())
}
```

- If you want to use Yubikey bio for fingerprint authentication, specify None for pin.

**console**

```sh
----- test-with-pin-non-rk start -----
Register - make_credential()
- rpid          = "test.com"
- challenge(32) = "054E416942D60F9F584B58A1E53B3ED85E9ECBB486D72CE690569E884B038267"
- touch fido key
- Register Success!!
Attestation
- rpid_hash(32)                           = 99AB715D84A3BC5E0E92AA50E67A5813637FD1744BD301AB08F87191DDB816E0
- flags_user_present_result               = true
- flags_user_verified_result              = true
- flags_attested_credential_data_included = true
- flags_extension_data_included           = false
- sign_count                              = 1
- aaguid(16)                              = EE882879721C491397753DFCCE97072A
- credential_descriptor                   = (id : 4AE2... , type : )
- credential_publickey                    = (der : 04A0... , pem : -----BEGIN PUBLIC KEY-----...)
- attstmt_alg                             = -7
- attstmt_sig(71)                         = 3045...
- attstmt_x5c_num                         = 1
Verify
- is_success                   = true
- credential_id(64)            = "4AEA..."
- credential_publickey_der(65) = "04A0..."

Authenticate - get_assertion_with_pin()
- challenge(32) = "0B1A3BF49C6D335592EE789C9C662365E06F4D9A63E6C4EA5B62B221E072A33E"
- touch fido key
- Authenticate Success!!
Assertion
- rpid_hash(32)                           = 99AB715D84A3BC5E0E92AA50E67A5813637FD1744BD301AB08F87191DDB816E0
- flags_user_present_result               = true
- flags_user_verified_result              = true
- flags_attested_credential_data_included = false
- flags_extension_data_included           = false
- sign_count                              = 4
- number_of_credentials                   = 0
- signature(71)                           = 3045...
- user                                    = (id :  , name :  , display_name : )
- credential_id(64)                       = 4AEA...
Verify
- is_success = true
----- test-with-pin-non-rk end -----
```



#### Using Key Type

TODO



#### Using HMAC Secret Extension

**Register**

```rust
fn main() -> Result<()> {
  let rpid = "test.com";
  let pin = Some("1234");
  let challenge = verifier::create_challenge();

  let ext = Mext::HmacSecret(Some(true));
  let att = ctap_hid_fido2::make_credential_with_extensions(
      &Cfg::init(),
      rpid,
      &challenge,
      pin,
      Some(&vec![ext]),
  )?;
}
```

**Authenticate**

```rust
fn main() -> Result<()> {

  let rpid = "test.com";
  let pin = Some("1234");
  let challenge = verifier::create_challenge();
  let credential_id = ???;
  
  let ext = Gext::create_hmac_secret_from_string("this is salt");
  let ass = ctap_hid_fido2::get_assertion_with_extensios(
      &Cfg::init(),
      rpid,
      &challenge,
      &credential_id,
      pin,
      Some(&vec![ext]),
  )?;
}
```



### discoverable credentials/resident-key

```Rust
use anyhow::Result;
use ctap_hid_fido2;
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::util;
use ctap_hid_fido2::verifier;
use ctap_hid_fido2::Cfg;

fn main() -> Result<()> {
    println!("----- test-with-pin-rk start -----");

    // parameter
    let rpid = "ge.com";
    let pin = Some("1234");

    // Register
    println!("Register - make_credential()");
    let challenge = verifier::create_challenge();
    let rkparam = PublicKeyCredentialUserEntity::new(Some(b"1111"),Some("gebo"),Some("GEBO GEBO"));

    println!("- rpid          = {:?}", rpid);
    println!(
        "- challenge({:02}) = {:?}",
        challenge.len(),
        util::to_hex_str(&challenge)
    );
    println!("- rkparam       = {}", rkparam);

    let att = ctap_hid_fido2::make_credential_rk(
        &Cfg::init(),
        rpid,
        &challenge,
        pin,
        &rkparam,
    )?;

    println!("- Register Success!!");
    println!("{}", att);

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
    println!(
        "- credential_id({:02}) = {:?}",
        verify_result.credential_id.len(),
        util::to_hex_str(&verify_result.credential_id)
    );

    // Authenticate
    println!("Authenticate - get_assertions_rk()");
    let challenge = verifier::create_challenge();
    let asss = ctap_hid_fido2::get_assertions_rk(
        &Cfg::init(),
        rpid,
        &challenge,
        pin,
    )?;
    println!("Authenticate Success!!");

    println!("- Assertion Num = {:?}", asss.len());
    for ass in asss {
        println!("- assertion = {}", ass);
        println!("- user = {}", ass.user);
    }

    println!("----- test-with-pin-rk end -----");
    Ok(())
}
```

- user_name and user_display_name are set only when multiple Assertions are acquired.
- If you want to enable UV-user verification, please specify None instead of a PIN.
  make_credential(),get_assertion()






## Builder Pattern Sample

### non-discoverable credentials/non-resident-key

**Register**

```rust
fn main() -> Result<()> {
  let rpid = "test.com";
  let pin = "1234";
  let challenge = verifier::create_challenge();

  let make_credential_args = ctap_hid_fido2::MakeCredentialArgsBuilder::new(&rpid, &challenge)
  .pin(pin)
  .build();

  let att = ctap_hid_fido2::make_credential_with_args(&cfg, &make_credential_args)?;
  let verify_result = verifier::verify_attestation(rpid, &challenge, &att);
  if verify_result.is_success {
    println!("Verify Success");
    // store
    // - verify_result.credential_id
    // - verify_result.credential_publickey_der
  }
}
```

**Authenticate**

```rust
fn main() -> Result<()> {
  let rpid = "test.com";
  let pin = "1234";
  let challenge = verifier::create_challenge();
  let credential_id = ???;
  let credential_publickey_der = ???

  let get_assertion_args = ctap_hid_fido2::GetAssertionArgsBuilder::new(&rpid, &challenge)
  .pin(pin)
  .credential_id(&credential_id)
  .build();

  let assertions = ctap_hid_fido2::get_assertion_with_args(cfg,&get_assertion_args)?;

  let is_success = verifier::verify_assertion(
    rpid,
    &credential_publickey_der,
    &challenge,
    &assertions[0],
  );
  if is_success {
    println!("Verify Success");
  }
}
```



#### Using Key Type



#### Using HMAC Secret Extension



### discoverable credentials/resident-key
