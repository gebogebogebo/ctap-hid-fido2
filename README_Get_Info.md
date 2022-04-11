# Get Authenticator Info and Util Examples

### get_info()

View information about the connected Authenticator.

[Spec: 6.4. authenticatorGetInfo (0x04)](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo)

```rust
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};

fn main() {
    println!("get_info()");
    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();
    let info = device.get_info().unwrap();
    println!("{}", info);
}
```

**console**

```sh
get_info()
- versions                           = ["U2F_V2", "FIDO_2_0", "FIDO_2_1_PRE", "FIDO_2_1"]
- extensions                         = ["credProtect", "hmac-secret", "largeBlobKey", "credBlob", "minPinLength"]
- aaguid(16)                         = D8522D9F575B486688A9BA99FA02F35B
- options                            = [("rk", true), ("up", true), ("uv", true), ("plat", false), ("uvToken", true), ("alwaysUv", true), ("credMgmt", true), ("authnrCfg", true), ("bioEnroll", true), ("clientPin", true), ("largeBlobs", true), ("pinUvAuthToken", true), ("setMinPINLength", true), ("makeCredUvNotRqd", false), ("credentialMgmtPreview", true), ("userVerificationMgmtPreview", true)]
- max_msg_size                       = 1200
- pin_uv_auth_protocols              = [2, 1]
- max_credential_count_in_list       = 8
- max_credential_id_length           = 128
- transports                         = ["usb"]
- algorithms                         = [("alg", "-7"), ("type", "public-key"), ("alg", "-8"), ("type", "public-key")]
- max_serialized_large_blob_array    = 1024
- force_pin_change                   = false
- min_pin_length                     = 4
- firmware_version                   = 328966
- max_cred_blob_length               = 32
- max_rpids_for_set_min_pin_length   = 1
- preferred_platform_uv_attempts     = 3
- uv_modality                        = 2
- remaining_discoverable_credentials = 22
```



### enable_info_param()

Same as `get_info()`, but checks if it has a specific feature/version.<br>It is specified by the enum of `InfoParam`.

```rust
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory, fidokey::get_info::InfoParam};

fn main() {
    println!("enable_info_param()");
    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();
    let info = device.enable_info_param(&InfoParam::VersionsFido21Pre).unwrap();
    println!("VersionsFido21Pre = {}", info);
}
```

**console**

```sh
enable_info_param()
VersionsFido21Pre = true
```



### enable_info_option()

Same as `get_info()`, but checks if it has a specific option.<br>It is specified by the enum of `InfoOption`.

- Result is `Option<bool>`
  - `Some(true)` : option is present and set to true
  - `Some(false)` : option is present and set to false
  - `None` : option is absent

```rust
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory, fidokey::get_info::InfoOption};

fn main() {
    println!("enable_info_option()");
    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();
    let info = device.enable_info_option(&InfoOption::BioEnroll).unwrap();
    println!("BioEnroll = {:?}", info);
}
```

**console**

```sh
enable_info_option()
BioEnroll = Some(true)
```



### get_pin_retries()

pinRetries counter represents the number of attempts left before PIN is disabled.

[Spec: 6.5.5.2. Platform getting PIN retries from Authenticator](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#gettingPINRetries)

```Rust
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};

fn main() {
    println!("get_pin_retries()");
    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();
    let info = device.get_pin_retries().unwrap();
    println!("{}", info);
}
```

**console**

```sh
get_pin_retries()
8
```



### get_uv_retries()

**Yubikey Bio Only**

UV(User Verification) retries count is the number of built-in UV attempts remaining before built-in UV is disabled on the device.

[Spec: 6.5.5.3. Platform getting UV Retries from Authenticator](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#gettingUVRetries)

```rust
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};

fn main() {
    println!("get_uv_retries()");
    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();
    let info = device.get_uv_retries().unwrap();
    println!("{}", info);
}
```

**console**

```sh
get_uv_retries()
3
```



### wink()

Just blink the LED on the FIDO key.

[Spec: 11.2.9.2.1. CTAPHID_WINK (0x08)](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#usb-hid-wink)

```Rust
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};

fn main() {
    println!("wink()");
    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();
    device.wink().unwrap();
}
```



### selection()

**CTAP 2.1 Only**

Check the touch of the Authenticator's touch sensor.

[Spec: 6.9. authenticatorSelection (0x0B)](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorSelection)

```rust
pub fn up(device: &FidoKeyHid) -> Result<()> {
    if !device.enable_info_param(&InfoParam::VersionsFido21)? {
        return Err(anyhow!(
            "This authenticator is not supported for this functions."
        ));
    }
    device.selection()?;
    Ok(())
}
```

> [Example](https://github.com/gebogebogebo/ctap-hid-fido2/blob/c22cacad1f62a1f1aa52a7af85b0a2a94be1dcac/examples/ctapcli/main.rs#L250-L258)

