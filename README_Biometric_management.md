# Biometric management

This command manages the fingerprints in the authenticator.<br>[Spec: 6.7. authenticatorBioEnrollment (0x09)](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorBioEnrollment)



To use this feature, the Authenticator must implement `BioEnroll` or `UserVerificationMgmtPreview`. check with `enable_info_option()`

```rust
fn is_supported(device: &FidoKeyHid) -> Result<bool> {
    if device.enable_info_option(&InfoOption::BioEnroll)?.is_some() {
        return Ok(true);
    }

    if device
        .enable_info_option(&&InfoOption::UserVerificationMgmtPreview)?
        .is_some()
    {
        Ok(true)
    } else {
        Ok(false)
    }
}
```

> [Example](https://github.com/gebogebogebo/ctap-hid-fido2/blob/7b5b70a07bd7e8f7a82023375539824c3f7343fd/examples/ctapcli/bio.rs#L113-L126)



## bio_enrollment_get_fingerprint_sensor_info()

Get fingerprint sensor information.

```Rust
match device.bio_enrollment_get_fingerprint_sensor_info() {
    Ok(result) => println!("- {:?}", result),
    Err(e) => println!("- error: {:?}", e),
}
```



## bio_enrollment_enumerate_enrollments()

Enumurate a list of registered fingerprints.

```Rust
match device.bio_enrollment_enumerate_enrollments(Some(pin)) {
    Ok(infos) => for i in infos {println!("- {}", i)},
    Err(e) => println!("- error: {:?}", e)
}
```



## bio_enrollment_begin(),bio_enrollment_next()

Enroll one fingerprint.<br>run `bio_enrollment_begin` first and then `bio_enrollment_next` several times.<br>`is_finish` detects the completion of registration.

```rust
fn bio_enrollment(pin: &str) -> Result<(), String> {
    println!("bio_enrollment_begin");
    let result = device.bio_enrollment_begin(
        Some(pin),
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
    let result = device.bio_enrollment_next(enroll_status, Some(10000))?;
    println!("{}", result);
    println!("");
    Ok(result.is_finish)
}
```



## bio_enrollment_set_friendly_name()

Update the registered name of the fingerprint.

```rust
match device::bio_enrollment_set_friendly_name(
    Some(pin),
    template_id, "display-name",
) {
    Ok(()) => println!("- Success"),
    Err(e) => println!("- error: {:?}", e),
}
```



## bio_enrollment_remove()

Delete a fingerprint.

```rust
match ctap_hid_fido2::bio_enrollment_remove(
     Some(pin),
     template_id,
 ) {
     Ok(_) => println!("- Success"),
     Err(e) => println!("- error: {:?}", e),
 }
```

