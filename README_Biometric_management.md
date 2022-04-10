# Biometric management

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

