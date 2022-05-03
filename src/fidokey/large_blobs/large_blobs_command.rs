use crate::{
  ctapdef,
  encrypt::enc_hmac_sha_256,
  pintoken::PinToken,
  util,
};

use anyhow::Result;
use ring::digest;
use serde_cbor::{to_vec, Value};
use std::collections::BTreeMap;

pub fn create_payload(
    pin_token: Option<PinToken>,
    offset: u32,
    get: Option<i32>,
    set: Option<Vec<u8>>,
) -> Result<Vec<u8>> {
    // create cbor
    let mut map = BTreeMap::new();

    // 0x01: get
    if let Some(read_bytes) = get {
        map.insert(Value::Integer(0x01), Value::Integer(read_bytes as i128));
    }

    // 0x03: offset
    map.insert(Value::Integer(0x03), Value::Integer(offset as i128));

    //if let Some(write_datas) = set {
    if let Some(write_datas) = set {
      //let data = to_vec(&Value::Array(vec![])).unwrap();
      // let data = to_vec(&Value::Bytes(vec![0x30])).unwrap();
      let data = to_vec(&Value::Bytes(write_datas)).unwrap();
      let hash = digest::digest(&digest::SHA256, &data);
      let message = &hash.as_ref()[0..16];
      println!("- data: {:?}",util::to_hex_str(&data));
      println!("- message: {:?}",util::to_hex_str(message));

    //let write_datas = util::to_str_hex("8076be8b528d0075f7aae98d6fa57a6d3c");
      //let write_datas = util::to_str_hex("40C3641F8544D7C02F3580B07C0F9887F0");
      //let write_datas = util::to_str_hex("4130AA508C2187FCA56F397FF75ADC52B94E");
      let write_datas = util::to_str_hex("44686F6765BE01422B86F44CF9C556ACA7BF7109A1");

      // 0x02: set
      map.insert(Value::Integer(0x02), Value::Bytes(write_datas.to_vec()));

      // 0x04: length
      map.insert(
          Value::Integer(0x04),
          Value::Integer(write_datas.len() as i128),
      );

      // 0x05: pinUvAuthParam
      // 0x06: pinUvAuthProtocol
      if let Some(pin_token) = pin_token {
        // pinUvAuthParam
        //   authenticate(
        //     pinUvAuthToken,
        //     32×0xff
        //       || h’0c00'
        //       || uint32LittleEndian(offset)
        //       || SHA-256(contents of set byte string, i.e. not including an outer CBOR tag with major type two)
        //   )
        // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#largeBlobsRW

        let pin_uv_auth_param = {
            println!("- {:?}",util::to_hex_str(&write_datas));
            println!("- {:?}",offset);
            println!("- {:?}",write_datas.len());

            let mut message = vec![0xff; 32];
            message.append(&mut vec![0x0c,0x00]);
            message.append(&mut offset.to_le_bytes().to_vec());

            let hash = digest::digest(&digest::SHA256, &write_datas);
            message.append(&mut hash.as_ref().to_vec());

            let sig = enc_hmac_sha_256::authenticate(&pin_token.key, &message);
            sig[0..16].to_vec()
        };
        map.insert(Value::Integer(0x05), Value::Bytes(pin_uv_auth_param));
        map.insert(Value::Integer(0x06), Value::Integer(1));
      }

    }

    // CBOR
    let cbor = Value::Map(map);
    let mut payload = [ctapdef::AUTHENTICATOR_LARGEBLOBS].to_vec();
    payload.append(&mut to_vec(&cbor)?);
    Ok(payload)
}
