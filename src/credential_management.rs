use crate::FidoKeyHid;
use crate::get_pin_token;
use crate::HidParam;
use crate::ctaphid;
use crate::credential_management_params;
use crate::credential_management_command;
use crate::credential_management_response;
use crate::util;

pub fn credential_management(
    hid_params: &[HidParam],
    pin: Option<&str>,
    sub_command: credential_management_command::SubCommand,
) -> Result<credential_management_params::CredsMetadata, String> {
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
        let pin_auth = pin_token.authenticate_v2(&vec![sub_command as u8],16);
        //println!("- pin_auth({:02})    = {:?}", pin_auth.len(),util::to_hex_str(&pin_auth));

        //let pin_auth = pin_token.sign(&util::create_clientdata_hash(challenge));
        //println!("- pin_auth({:02})    = {:?}", pin_auth.len(),util::to_hex_str(&pin_auth));

        let send_payload = credential_management_command::create_payload(pin_auth.to_vec(),sub_command);

        println!("send(cbor) = {}",util::to_hex_str(&send_payload));

        let response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload)?;
        println!("response(cbor) = {}",util::to_hex_str(&response_cbor));

        Ok(credential_management_response::parse_cbor(&response_cbor)?)
        //data.print("Debug");
    }else{
        Err("PIN Token Error".to_string())
    }
        
}