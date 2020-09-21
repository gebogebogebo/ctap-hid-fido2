use serde_cbor::Value;
use num::NumCast;
use sha2::{Sha256, Digest};

pub fn to_hex_str(bytes:&[u8]) -> String
{
    bytes.iter().map(|n| format!("{:02X}", n)).collect::<String>()
    //&val
    //String::from("aaa")
}

pub fn print_typename<T>(_: T) {
    println!("{}", std::any::type_name::<T>());
}

pub fn cbor_value_to_i128(value:&Value)->Option<i128>{
    if let Value::Integer(x) = value{
        Some(*x)
    }else{
        None
    }
}

pub fn cbor_value_to_i32(value:&Value)->Option<i32>{
    if let Value::Integer(x) = value{
        Some(NumCast::from(*x).unwrap())
    }else{
        None
    }
}

pub fn cbor_value_to_u16(value:&Value)->Option<u16>{
    if let Value::Integer(x) = value{
        Some(NumCast::from(*x).unwrap())
    }else{
        None
    }
}

pub fn cbor_value_to_vec_u8(value:&Value)->Option<Vec<u8>>{
    if let Value::Bytes(xs) = value {
        Some(xs.to_vec())
    }else{
        None
    }
}

pub fn cbor_value_to_vec_string(value:&Value)->Option<Vec<String>>{
    if let Value::Array(x) = value {
        let mut strings = [].to_vec();
        for ver in x{
            if let Value::Text(s) = ver{
                strings.push(s.to_string());
            }
        }
        Some(strings)
    }else{
        None
    }
}

pub fn cbor_value_print(value:&Value){
    match value{
        Value::Bytes(s) => print_typename(s),
        Value::Text(s) => print_typename(s),
        Value::Integer(s) => print_typename(s),
        Value::Map(s) => print_typename(s),
        _ => println!("unknown Value type"),
    };
}

pub fn create_clientdata_hash(challenge:Vec<u8>) -> Vec<u8>{
    // sha256
    let mut hasher = Sha256::new();
    hasher.update(challenge);
    let result = hasher.finalize();
    result.to_vec()
}
