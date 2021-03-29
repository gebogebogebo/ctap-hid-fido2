use crate::FidoKeyHid;
use crate::get_pin_token;
use crate::HidParam;
use crate::ctaphid;
use crate::credential_management_command;
use crate::util;

pub fn credential_management(
    hid_params: &[HidParam],
    pin: Option<&str>
) -> Result<String, String> {
    let device = FidoKeyHid::new(hid_params)?;
    let cid = ctaphid::ctaphid_init(&device)?;

    // pin token
    let pin_token = {
        if let Some(pin) = pin {
            Some(get_pin_token(&device, &cid, pin.to_string())?)
        } else {
            None
        }
    };

    // create pin auth
    if let Some(pin_token) = pin_token {
        // pinUvAuthParam (0x04): authenticate(pinUvAuthToken, getCredsMetadata (0x01)).
        // First 16 bytes of HMAC-SHA-256 of contents using pinUvAuthToken.
        let pin_auth = pin_token.authenticate(&vec![0x01],16);
        //println!("- pin_auth({:02})    = {:?}", pin_auth.len(),util::to_hex_str(&pin_auth));

        //let pin_auth = pin_token.sign(&util::create_clientdata_hash(challenge));
        //println!("- pin_auth({:02})    = {:?}", pin_auth.len(),util::to_hex_str(&pin_auth));

        let send_payload = credential_management_command::create_payload_get_creds_metadata(pin_auth.to_vec());
        println!("send(cbor) = {}",util::to_hex_str(&send_payload));

        let _response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload)?;
        println!("response(cbor) = {}",util::to_hex_str(&_response_cbor));
    }

        
    Ok("".to_string())
}