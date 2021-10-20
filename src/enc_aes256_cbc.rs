use crypto::aes;
use crypto::buffer::{ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};

// AES256-CBC(key,IV=0,message)

pub fn encrypt_message_str(key: &[u8; 32], message: &str) -> Vec<u8> {
    encrypt_message(key, message.as_bytes())
}

pub fn encrypt_message(key: &[u8; 32], message: &[u8]) -> Vec<u8> {
    let mut encryptor = aes::cbc_encryptor(
        aes::KeySize::KeySize256,
        key,
        &[0u8; 16],
        crypto::blockmodes::NoPadding,
    );

    // read buffer
    let mut input = RefReadBuffer::new(message);

    // write buffer(MAX 4096 byte)
    let mut buffer = [0; 4096];
    let mut output = RefWriteBuffer::new(&mut buffer);

    // encrypt
    let _encrypt_result = encryptor.encrypt(&mut input, &mut output, true).unwrap();

    // get result
    let mut result = Vec::<u8>::new();
    result.extend(output.take_read_buffer().take_remaining().iter().copied());

    result
}

pub fn decrypt_message_str(key: &[u8; 32], message: &[u8]) -> String {
    let bytes = decrypt_message(key, message);
    String::from_utf8(bytes.to_vec()).unwrap()
}

pub fn decrypt_message(key: &[u8; 32], message: &[u8]) -> Vec<u8> {
    let mut decryptor = aes::cbc_decryptor(
        aes::KeySize::KeySize256,
        key,
        &[0u8; 16],
        crypto::blockmodes::NoPadding,
    );

    // read buffer
    let mut input = RefReadBuffer::new(message);

    // write buffer(MAX 4096 byte)
    let mut buffer = [0; 4096];
    let mut output = RefWriteBuffer::new(&mut buffer);

    let _decrypt_result = decryptor.decrypt(&mut input, &mut output, true).unwrap();

    // get result
    let mut result = Vec::<u8>::new();
    result.extend(output.take_read_buffer().take_remaining().iter().copied());

    result
}
