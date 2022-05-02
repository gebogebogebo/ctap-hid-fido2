use crate::encrypt::shared_secret;
use crate::{ctapdef, ctaphid, pintoken::PinToken};

use super::FidoKeyHid;

use crate::encrypt::enc_hmac_sha_256;
use anyhow::{anyhow, Error, Result};
use serde_cbor::to_vec;
use serde_cbor::Value;
use std::collections::BTreeMap;
use ring::{digest};
use crate::util;

fn create_payload(_pin_token: Option<PinToken>) -> Vec<u8> {
    // create cbor
    let mut map = BTreeMap::new();

    // 0x01: get
    map.insert(Value::Integer(0x01), Value::Integer(17 as i128));

    // 0x02: set
    //map.insert(Value::Integer(0x02), Value::Integer(0 as i128));

    // 0x03: offset
    map.insert(Value::Integer(0x03), Value::Integer(0 as i128));

    // // 0x05: pinUvAuthParam
    // let pin_uv_auth_param = {
    //     // pinUvAuthParam (0x04)
    //     // - authenticate(pinUvAuthToken, 32×0xff || 0x0d || uint8(subCommand) || subCommandParams).
    //     // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorConfig
    //     let mut message = vec![0xff; 32];
    //     message.append(&mut vec![0x0d]);
    //     message.append(&mut vec![sub_command as u8]);
    //     message.append(&mut sub_command_params_cbor);

    //     let sig = enc_hmac_sha_256::authenticate(&pin_token.key, &message);
    //     let pin_auth = sig[0..16].to_vec();
    //     pin_auth
    // };
    // map.insert(
    //     Value::Integer(0x05),
    //     Value::Bytes(pin_uv_auth_param.to_vec()),
    // );

    // 0x06: pinUvAuthProtocol
    //map.insert(Value::Integer(0x06), Value::Integer(1));


    // CBOR
    let cbor = Value::Map(map);
    let mut payload = [ctapdef::AUTHENTICATOR_LARGEBLOBS].to_vec();
    payload.append(&mut to_vec(&cbor).unwrap());
    payload
}

impl FidoKeyHid {
    pub fn large_blobs(&self, _pin: Option<&str>, _get: bool, _offset: i32) -> Result<String> {
        //   let pin = if let Some(v) = pin {
        //       v
        //   } else {
        //       return Err(anyhow!("need PIN."));
        //   };

        // TODO
        let data = vec![0x80];
        let hash = digest::digest(&digest::SHA256, &data);
        let message = &hash.as_ref()[0..16];
        println!("{:?}",util::to_hex_str(message));

        let cid = ctaphid::ctaphid_init(self).map_err(Error::msg)?;

        // get pintoken
        // let pin_token =
        //     self.get_pinuv_auth_token_with_permission(&cid, pin, super::pin::Permission::Acfg)?;

        let send_payload = create_payload(None);
        let _response_cbor =
            ctaphid::ctaphid_cbor(self, &cid, &send_payload).map_err(Error::msg)?;
        Ok("".to_string())
    }
}
