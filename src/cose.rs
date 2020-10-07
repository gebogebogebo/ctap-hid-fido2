use crate::util;
use num::NumCast;
use serde_cbor::Value;
use std::collections::HashMap;
use byteorder::{BigEndian, WriteBytesExt};
use base64;

#[derive(Debug, Default)]
pub struct CoseKey {
    pub key_type: u16,
    pub algorithm: i32,
    pub parameters: HashMap<i16, Value>,
}

impl CoseKey {
    #[allow(dead_code)]
    pub fn print(self: &CoseKey, title: &str) {
        println!("{}", title);
        println!("- kty       = {:?}", self.key_type);
        println!("- alg       = {:?}", self.algorithm);
        if let Some(Value::Integer(intval)) = self.parameters.get(&-1) {
            println!("- crv       = {:?}", intval);
        }
        if let Some(Value::Bytes(bytes)) = self.parameters.get(&-2) {
            println!(
                "- x({:02})     = {:?}",
                bytes.len(),
                util::to_hex_str(bytes)
            );
        }
        if let Some(Value::Bytes(bytes)) = self.parameters.get(&-3) {
            println!(
                "- y({:02})     = {:?}",
                bytes.len(),
                util::to_hex_str(bytes)
            );
        }
    }

    pub fn decode(cbor: &Value) -> Result<Self, String> {
        let mut cose = CoseKey::default();

        if let Value::Map(xs) = cbor {
            for (key, val) in xs {
                // debug
                //util::cbor_value_print(val);

                if let Value::Integer(member) = key {
                    match member {
                        1 => cose.key_type = util::cbor_cast_value(val).unwrap(),
                        3 => cose.algorithm = util::cbor_cast_value(val).unwrap(),
                        -1 => {
                            //println!("member = {:?} , val = {:?}",member,val);
                            cose.parameters.insert(
                                NumCast::from(*member).unwrap(),
                                Value::Integer(util::cbor_cast_value(val).unwrap()),
                            );
                        }
                        -2 | -3 => {
                            //println!("member = {:?} , val = {:?}",member,val);
                            cose.parameters.insert(
                                NumCast::from(*member).unwrap(),
                                Value::Bytes(util::cbor_value_to_vec_u8(val).unwrap()),
                            );
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(cose)
    }

    pub fn encode(&self) -> Vec<u8> {

        let mut wtr = vec![];

        // key type
        wtr.write_i16::<BigEndian>(0x01).unwrap();
        wtr.write_u16::<BigEndian>(self.key_type).unwrap();

        // algorithm
        wtr.write_i16::<BigEndian>(0x02).unwrap();
        wtr.write_i32::<BigEndian>(self.algorithm).unwrap();

        for (key, value) in self.parameters.iter() {
            wtr.write_i16::<BigEndian>(*key).unwrap();
            if let Value::Bytes(bytes) = value {
                wtr.append(&mut bytes.to_vec());
            }
        }

        wtr
    }

    pub fn convert_to_publickey_der(&self) -> Vec<u8>{
        // COSE形式の公開鍵をPEM形式に変換する
        // 1.26byteのメタデータを追加
        // 2.0x04を追加
        // 3.COSEデータのxとyを追加
        let mut pub_key = vec![];

        // 1
        let meta_header = hex::decode("48656c6c6f20776f726c6421").unwrap();
        pub_key.append(&mut meta_header.to_vec());

        // 2
        pub_key.push(0x04);

        // 3
        if let Some(Value::Bytes(bytes)) = self.parameters.get(&-2) {
            pub_key.append(&mut bytes.to_vec());
        }
        if let Some(Value::Bytes(bytes)) = self.parameters.get(&-3) {
            pub_key.append(&mut bytes.to_vec());
        }

        pub_key
    }

    pub fn convert_to_publickey_pem(&self,public_key_der:&[u8]){
        // DER形式の公開鍵をPEM形式に変換する
        // 1.Base64エンコード
        // 2.64文字ごとに改行コードをいれる
        // 3.ヘッダとフッタを入れる

        // 1.
        let base64 = base64::encode(public_key_der);


        // 2.
        //base64
    }
    /*
        // Publick Key
        public static string ToPemPublicKey(byte[] der)
        {
            var pemdata = string.Format("-----BEGIN PUBLIC KEY-----\n") + toPem(der) + string.Format("-----END PUBLIC KEY-----");
            return pemdata;
        }

         private static string toPem(byte[] der)
        {
            // DER形式をPEM形式に変換する
            //     DER -> 鍵や証明書をASN.1というデータ構造で表し、それをシリアライズしたバイナリファイル
            //     PEM -> DERと同じASN.1のバイナリデータをBase64によってテキスト化されたファイル 
            // 1.Base64エンコード
            // 2.64文字ごとに改行コードをいれる
            // 3.ヘッダとフッタを入れる

            var b64cert = Convert.ToBase64String(der);

            string pemdata = "";
            int roopcount = (int)Math.Ceiling(b64cert.Length / 64.0f);
            for (int intIc = 0; intIc < roopcount; intIc++) {
                int start = 64 * intIc;
                if (intIc == roopcount - 1) {
                    pemdata = pemdata + b64cert.Substring(start) + "\n";
                } else {
                    pemdata = pemdata + b64cert.Substring(start, 64) + "\n";
                }
            }
            return pemdata;
        }
       
    */

}
