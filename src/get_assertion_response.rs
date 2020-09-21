
use serde_cbor::Value;
use crate::util;
use std::io::Cursor;
use byteorder::{BigEndian, ReadBytesExt};

pub struct Assertion
{
    pub rpid_hash:Vec<u8>,
    pub flags_user_present_result:bool,
    pub flags_user_verified_result:bool,
    pub flags_attested_credential_data_included:bool,
    pub flags_extension_data_included:bool,

    pub sign_count:u32,
    pub aaguid:Vec<u8>,

    pub number_of_credentials:i32,

    pub signature:Vec<u8>,
    pub user_id:Vec<u8>,
    pub user_name:String,
    pub user_display_name:String,

    pub credential_id:Vec<u8>,
}

fn parse_cbor_authdata(authdata:Vec<u8>,ass:&mut Assertion){
    let mut index = 0;

    let clo_vec = |idx:usize,x:usize|{(authdata[idx..idx+x].to_vec(),idx+x)};

    // rpIdHash	(32)
    let ret = clo_vec(index,32);
    ass.rpid_hash = ret.0;
    index = ret.1;

    // flags(1)
    let byte = authdata[index];
    ass.flags_user_present_result = if let 0x01 = byte&0x01 {true}else{false};
    ass.flags_user_verified_result = if let 0x04 = byte&0x04 {true}else{false};
    ass.flags_attested_credential_data_included = if let 0x40 = byte&0x40 {true}else{false};
    ass.flags_extension_data_included = if let 0x80 = byte&0x80 {true}else{false};
    index = index + 1;

    // signCount(4)
    let clo = |idx:usize,x:usize|{
        let mut rdr = Cursor::new(authdata[idx..idx+x].to_vec());
        (rdr.read_u32::<BigEndian>().unwrap(),idx+x)
    };
    let ret = clo(index,4);
    ass.sign_count = ret.0;
    //index = ret.1;

    // aaguid(16)
    //let ret = clo_vec(index,16);
    //ass.aaguid = ret.0;
    //index = ret.1;

}

fn parse_cbor_member(member:i128,val:&Value,ass:&mut Assertion){

    util::cbor_value_print(val);

    match member{
        1 => {
            // 0x01:credential
            if let Value::Map(xs) = val{
                for (key, val2) in xs {     
                    //util::cbor_value_print(key);
                    //util::cbor_value_print(val2);
                    if let Value::Text(s) = key{
                        let ss = s.as_str();
                        match ss{
                            "id" => ass.credential_id=util::cbor_value_to_vec_u8(val2).unwrap(),
                            "type" =>{},
                            _ =>{},
                        }
                        //println!("key = {:?}",key);
                    }
                }
            }

        },
        2 => {
            // 0x02:AuthData
            if let Value::Bytes(xs) = val {
                parse_cbor_authdata(xs.to_vec(),ass);
            }
        },
        3 => {
            // 0x03:signature
            ass.signature=util::cbor_value_to_vec_u8(val).unwrap();
        },
        4 => {
            // 0x04:user
        },
        5 => {
            // 0x05:numberOfCredentials
        },
        _ => println!("- anything error"),
    }
}

pub fn parse_cbor(bytes:&[u8]) -> Result<Assertion,String>{

    let cbor: Value = serde_cbor::from_slice(bytes).unwrap();
    
    let mut ass = Assertion {
        rpid_hash:[].to_vec(),
        flags_user_present_result:false,
        flags_user_verified_result:false,
        flags_attested_credential_data_included:false,
        flags_extension_data_included:false,
    
        sign_count:0,
        aaguid:[].to_vec(),
    
        number_of_credentials:0,
    
        signature:[].to_vec(),
        user_id:[].to_vec(),
        user_name:String::from(""),
        user_display_name:String::from(""),
    
        credential_id:[].to_vec(),
        };

    if let Value::Map(map) = cbor{
        for (key, val) in &map {     
            if let Value::Integer(member) = key {
                println!("member = {}",member);
                parse_cbor_member(*member,val,&mut ass);
                println!("");
            }
        }
        Ok(ass)
    }else{
        Err(String::from("parse error!"))
    }
}
