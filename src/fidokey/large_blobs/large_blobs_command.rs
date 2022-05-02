use crate::{ctapdef, pintoken::PinToken};

use anyhow::Result;
use serde_cbor::{to_vec, Value};
use std::collections::BTreeMap;

pub fn create_payload(_pin_token: Option<PinToken>) -> Result<Vec<u8>> {
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
  payload.append(&mut to_vec(&cbor)?);
  Ok(payload)
}
