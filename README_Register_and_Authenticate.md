# Register and Authenticate



## Legacy Pattern Sample

### non-discoverable credentials/non-resident-key

→ link

- If you want to use Yubikey bio for fingerprint authentication, specify None for pin.



#### Using Key Type

→ link

- Verify Assertion in Ed25519 is always false because it is not yet implemented

  

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

→ link



#### with Key Type

→ link

Verify Assertion in Ed25519 is always false because it is not yet implemented



#### with HMAC Secret Extension

→ link



### discoverable credentials/resident-key

→ link

