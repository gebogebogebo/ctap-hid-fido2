use crate::str_buf::StrBuf;
use base64::{engine::general_purpose, Engine as _};
use ring::digest;

pub fn to_hex_str(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut acc, n| {
        acc.push_str(&format!("{:02X}", n));
        acc
    })
}

pub fn to_str_hex(hexstr: &str) -> Vec<u8> {
    hex::decode(hexstr).unwrap_or_default()
}

pub fn print_typename<T>(_: T) {
    println!("{}", std::any::type_name::<T>());
}

#[allow(dead_code)]
pub(crate) fn debugp(title: &str, bytes: &[u8]) {
    println!("{}", StrBuf::bufh(title, bytes));
}

pub(crate) fn create_clientdata_hash(challenge: Vec<u8>) -> Vec<u8> {
    // sha256
    let hasher = digest::digest(&digest::SHA256, &challenge);
    hasher.as_ref().to_vec()
}

#[allow(dead_code)]
pub(crate) fn convert_to_publickey_pem(public_key_der: &[u8]) -> String {
    let mut tmp = vec![];

    if public_key_der.is_empty() {
        return "".to_string();
    }

    // 0.metadata(26byte)
    let meta_header = hex::decode("3059301306072a8648ce3d020106082a8648ce3d030107034200").unwrap();
    tmp.append(&mut meta_header.to_vec());

    tmp.append(&mut public_key_der.to_vec());

    // 1.encode Base64
    let base64_str = general_purpose::STANDARD_NO_PAD.encode(tmp);

    // 2. /n　every 64 characters
    let pem_base = {
        let mut pem_base = "".to_string();
        let mut counter = 0;
        for c in base64_str.chars() {
            pem_base = pem_base + &c.to_string();
            if counter == 64 - 1 {
                pem_base += "\n";
                counter = 0;
            } else {
                counter += 1;
            }
        }
        pem_base + "\n"
    };

    // 3. Header and footer
    "-----BEGIN PUBLIC KEY-----\n".to_string() + &pem_base + "-----END PUBLIC KEY-----"
}
