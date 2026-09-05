use aes::cipher::{block_padding::NoPadding, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};

// AES256-CBC(key,IV=0,message)
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

#[allow(dead_code)]
pub fn encrypt_message_str(key: &[u8; 32], message: &str) -> Vec<u8> {
    encrypt_message(key, message.as_bytes())
}

pub fn encrypt_message(key: &[u8; 32], message: &[u8]) -> Vec<u8> {
    if message.len() > 4096 {
        panic!("Message too long");
    }

    let mut buffer = message.to_vec();
    let pt_len = message.len();
    let zero_iv = [0u8; 16];
    let ciphertext = Aes256CbcEnc::new(&(*key).into(), &zero_iv.into())
        .encrypt_padded::<NoPadding>(&mut buffer, pt_len)
        .unwrap();
    ciphertext.to_vec()
}

pub fn encrypt_message_with_iv(key: &[u8], iv: &[u8], message: &[u8]) -> Vec<u8> {
    if message.len() > 4096 {
        panic!("Message too long");
    }

    let mut buffer = message.to_vec();
    let pt_len = message.len();
    let ciphertext = Aes256CbcEnc::new_from_slices(key, iv)
        .expect("AES-256-CBC requires a 32-byte key and 16-byte IV")
        .encrypt_padded::<NoPadding>(&mut buffer, pt_len)
        .unwrap();
    ciphertext.to_vec()
}

#[allow(dead_code)]
pub fn decrypt_message_str(key: &[u8; 32], message: &[u8]) -> String {
    let bytes = decrypt_message(key, message);
    String::from_utf8(bytes.to_vec()).unwrap()
}

pub fn decrypt_message(key: &[u8; 32], message: &[u8]) -> Vec<u8> {
    if message.len() > 4096 {
        panic!("Message too long");
    }

    let mut buffer = message.to_vec();
    let zero_iv = [0u8; 16];
    let plaintext = Aes256CbcDec::new(&(*key).into(), &zero_iv.into())
        .decrypt_padded::<NoPadding>(&mut buffer)
        .unwrap();
    plaintext.to_vec()
}

pub fn decrypt_message_with_iv(key: &[u8], iv: &[u8], message: &[u8]) -> Vec<u8> {
    if message.len() > 4096 {
        panic!("Message too long");
    }

    let mut buffer = message.to_vec();
    let plaintext = Aes256CbcDec::new_from_slices(key, iv)
        .expect("AES-256-CBC requires a 32-byte key and 16-byte IV")
        .decrypt_padded::<NoPadding>(&mut buffer)
        .unwrap();
    plaintext.to_vec()
}
