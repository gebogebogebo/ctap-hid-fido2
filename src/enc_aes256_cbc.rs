use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::NoPadding;

// AES256-CBC(key,IV=0,message)
type Aes256Cbc = Cbc<Aes256, NoPadding>;

pub fn encrypt_message_str(key: &[u8; 32], message: &str) -> Vec<u8> {
    encrypt_message(key, message.as_bytes())
}

pub fn encrypt_message(key: &[u8; 32], message: &[u8]) -> Vec<u8> {
    if message.len() > 4096 {
        panic!("Message too long");
    }

    let cipher = Aes256Cbc::new_from_slices(key, &[0u8; 16]).unwrap();
    let mut buffer = message.to_vec();
    let ciphertext = cipher.encrypt(&mut buffer, message.len()).unwrap();

    ciphertext.to_vec()
}

pub fn decrypt_message_str(key: &[u8; 32], message: &[u8]) -> String {
    let bytes = decrypt_message(key, message);
    String::from_utf8(bytes.to_vec()).unwrap()
}

pub fn decrypt_message(key: &[u8; 32], message: &[u8]) -> Vec<u8> {
    if message.len() > 4096 {
        panic!("Message too long");
    }

    let cipher = Aes256Cbc::new_from_slices(key, &[0u8; 16]).unwrap();
    let mut buffer = message.to_vec();

    let plaintext = cipher.decrypt(&mut buffer).unwrap();

    plaintext.to_vec()
}
