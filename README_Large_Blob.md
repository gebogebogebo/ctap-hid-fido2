# Large Blob

This command allows at least 1024 bytes of large blob data to be stored on Authenticators.<br>[Spec: 6.10. authenticatorLargeBlobs (0x0C)](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorLargeBlobs)



To use this feature, the Authenticator must implement `LargeBlobs` . check with `enable_info_option()`

```rust
fn is_supported(device: &FidoKeyHid) -> Result<bool> {
    if device
        .enable_info_option(&InfoOption::LargeBlobs)?
        .is_some()
    {
        Ok(true)
    } else {
        Ok(false)
    }
}
```

>  [Example](https://github.com/gebogebogebo/ctap-hid-fido2/blob/c0b8279335b3387d6307731602e59655b7cc5517/examples/ctapcli/blobs.rs#L51-L60)



## get_large_blob()

[Spec: 6.10.2. Reading and writing serialised data](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#largeBlobsRW)

```rust
let large_brob_data = device.get_large_blob()?;
```

> [Example](https://github.com/gebogebogebo/ctap-hid-fido2/blob/c0b8279335b3387d6307731602e59655b7cc5517/examples/ctapcli/blobs.rs#L22)
>
> [LargeBlobData](https://github.com/gebogebogebo/ctap-hid-fido2/blob/c0b8279335b3387d6307731602e59655b7cc5517/src/fidokey/large_blobs/large_blobs_params.rs#L5-L8)



## write_large_blob()

[Spec: 6.10.2. Reading and writing serialised data](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#largeBlobsRW)

```rust
device.write_large_blob(Some(&pin), write_datas)?;
```

> [Example](https://github.com/gebogebogebo/ctap-hid-fido2/blob/c0b8279335b3387d6307731602e59655b7cc5517/examples/ctapcli/blobs.rs#L40)



