use hidapi::HidApi;
use std::{thread, time};
use crate::util;

const CTAP_FRAME_INIT:u8 = 0x80;
const PACKET_SIZE:usize = 1+64;
const PAYLOAD_SIZE_AN_INITIALIZATION_PACKET:usize = 64-7;
const PAYLOAD_SIZE_A_CONTINUATION_PACKET:usize = 64-5;

// CTAP Command
const CTAPHID_INIT:u8 = CTAP_FRAME_INIT|0x06;
const CTAPHID_WINK:u8 = CTAP_FRAME_INIT|0x08;
const CTAPHID_CBOR:u8 = CTAP_FRAME_INIT|0x10;
//This command code is used in response messages only.
//const CTAPHID_ERROR:u8 = CTAP_FRAME_INIT|0x3F;
const CTAPHID_KEEPALIVE:u8 = CTAP_FRAME_INIT|0x3B;
//const CTAPHID_KEEPALIVE_STATUS_PROCESSING = 1;     // The authenticator is still processing the current request.
//const CTAPHID_KEEPALIVE_STATUS_UPNEEDED = 2;       // The authenticator is waiting for user presence.

pub struct HidParam {
	vid: u16,
    pid: u16,
}

impl HidParam {
    pub fn get_default_params() -> Vec<HidParam>{
        vec![
            HidParam{vid:0x1050,pid:0x0402},        // yubikey
            HidParam{vid:0x1050,pid:0x0120},        // yubikey
            HidParam{vid:0x096E,pid:0x85D},         // biopass
            HidParam{vid:0x483,pid:0x0a2ca},        // solokey
        ]
    }
}

#[allow(deprecated)]
pub fn get_hid_devices()->Vec<HidParam>{
    let api = HidApi::new().expect("Failed to create AcaPI instance");
    let mut res:Vec<HidParam> = vec![];

    let devices = api.devices();
    for dev in devices{
        res.push(HidParam{vid:dev.vendor_id,pid:dev.product_id});
        println!("product_string = {:?}", dev.product_string);
        println!("- vendor_id = 0x{:2x}", dev.vendor_id);
        println!("- product_id = 0x{:2x}", dev.product_id);
    }
    res
}

pub fn connect_device(params : Vec<HidParam>)-> hidapi::HidDevice{
    let api = HidApi::new().expect("Failed to create AcaPI instance");
    for param in params{
        if let Ok(dev) = api.open(param.vid, param.pid){
            return dev;
        }
    }
    panic!("Failed to open device");
}

pub fn ctaphid_init(device : &hidapi::HidDevice) -> [u8;4]{

    // CTAPHID_INIT
    let cmd: [u8; 65] = [0x00,0xff,0xff,0xff,0xff,CTAPHID_INIT,0x00,0x08,0xfc,0x8c,0xc9,0x91,0x14,0xb5,0x3b,0x12,0x00,
                         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00];
    println!("CTAPHID_INIT = {}", util::to_hex_str(&cmd));

    // Write data to device
    let _res = device.write(&cmd).unwrap();
    //println!("Wrote: {:?} byte", res);

    let mut buf = [0u8; 64];
    let _res = device.read(&mut buf[..]).unwrap();
    //println!("Read: {:?} byte", &buf[..res]);

    // CID
    [buf[15],buf[16],buf[17],buf[18]]
}

fn ctaphid_cbor_responce_status(packet:&[u8;64]) -> (u8,u16,u8){

    // cid
    //println!("- cid: {:?}", &packet[0..4]);
    // cmd
    println!("- cmd: 0x{:2X}", packet[4]);

    // 応答データ全体のサイズ packet[5],[6]
    let payload_size = ((packet[5] as u16) << 8) + packet[6] as u16;
    // CTAP Status
    let response_status = packet[7];

    (packet[4],payload_size,response_status)
}

fn ctaphid_cbor_responce_get_payload_1(packet:&[u8;64]) -> Vec<u8>{
    (&packet[7..64]).to_vec()
}

fn ctaphid_cbor_responce_get_payload_2(packet:&[u8;64]) -> Vec<u8>{
    (&packet[5..64]).to_vec()
}

fn create_initialization_packet(cid:&[u8],payload:&Vec<u8>) -> (Vec<u8>,bool){
    let mut cmd:Vec<u8> = vec![0; PACKET_SIZE];

    // Report ID
    // The first byte of data must contain the Report ID.
    // For devices which only support a single report, this must be set to 0x0.
    cmd[0] = 0x00;

    // cid
    cmd[1] = cid[0];
    cmd[2] = cid[1];
    cmd[3] = cid[2];
    cmd[4] = cid[3];

    // Command identifier (bit 7 always set)	
    // CTAP_FRAME_INIT(0x80) | CTAPHID_CBOR (0x10)
    cmd[5] = CTAPHID_CBOR;

    // High part of payload length
    cmd[6] = (((payload.len() as u16) >> 8) as u8) & 0xff;
    // Low part of payload length
    cmd[7] = (payload.len() as u8) & 0xff;

    // payload
    let mut size = payload.len();
    let mut next = false;
    if payload.len() > PAYLOAD_SIZE_AN_INITIALIZATION_PACKET {
        size = PAYLOAD_SIZE_AN_INITIALIZATION_PACKET;
        next = true;
    }

    for counter in 0..size{
        cmd[8+counter] = payload[counter];
    }

    (cmd,next)
}

fn create_continuation_packet(seqno:u8,cid:&[u8],payload:&Vec<u8>) -> (Vec<u8>,bool){
    let mut cmd:Vec<u8> = vec![0; PACKET_SIZE];

    // Report ID
    cmd[0] = 0x00;

    // cid
    cmd[1] = cid[0];
    cmd[2] = cid[1];
    cmd[3] = cid[2];
    cmd[4] = cid[3];

    // seq
    cmd[5] = seqno;

    let index:usize = PAYLOAD_SIZE_AN_INITIALIZATION_PACKET+PAYLOAD_SIZE_A_CONTINUATION_PACKET*seqno as usize;

    // payload
    let mut size:usize = payload.len()-index;
    let mut next = false;
    if size > PAYLOAD_SIZE_A_CONTINUATION_PACKET {
        size = PAYLOAD_SIZE_A_CONTINUATION_PACKET;
        next = true;
    }

    for counter in 0..size{
        cmd[6+counter] = payload[index+counter];
    }

    (cmd,next)
}

pub fn ctaphid_wink(device:&hidapi::HidDevice , cid:&[u8]){

    // CTAPHID_WINK
    let cmd: [u8; 65] = [0x00,cid[0],cid[1],cid[2],cid[3],CTAPHID_WINK,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00];
    println!("CTAPHID_WINK = {}", util::to_hex_str(&cmd));

    // Write data to device
    let _res = device.write(&cmd).unwrap();
    //println!("Wrote: {:?} byte", res);

    let mut buf = [0u8; 64];
    let res = device.read_timeout(&mut buf[..],1000).unwrap();
    //let err = device.check_error();
    println!("Read: {:?}", &buf[..res]);    

    //buf.to_vec()
}

pub fn ctaphid_cbor(device:&hidapi::HidDevice , cid:&[u8] , payload:&Vec<u8>) -> Result<Vec<u8>,u8>{

    // initialization_packet
    let res = create_initialization_packet(cid,payload);
    println!("CTAPHID_CBOR(0) = {}", util::to_hex_str(&res.0));

    // Write data to device
    let _res = device.write(&res.0).unwrap();
    //println!("Wrote: {:?} byte", res);

    // next
    if res.1 == true {
        for seqno in 0..100{
            let res = create_continuation_packet(seqno,cid,payload);
            println!("CTAPHID_CBOR(1) = {}", util::to_hex_str(&res.0));
            let _res = device.write(&res.0).unwrap();
            if res.1 == false {
                break;
            }
        }
    }

    // read - 1st packet
    let mut buf = [0u8; 64];

    let mut st:(u8,u16,u8)=(0,0,0);
    for _ in 0..100{

        let _res = device.read(&mut buf[..]).unwrap();
        //println!("Read: {:?} byte", res);

        // PEND Result型にする
        st = ctaphid_cbor_responce_status(&buf);
        if st.0 == CTAPHID_CBOR {
            break;
        } else if st.0 == CTAPHID_KEEPALIVE {
            println!("keep alive");
            thread::sleep(time::Duration::from_millis(100));
        } else {
            println!("err");
            break;
        }
    }

    let payload_size = st.1;
    let response_status = st.2;
    println!("payload_size = {:?} byte", payload_size);
    println!("response_status = 0x{:02X}", response_status);

    if response_status != 0x00{
        Err(response_status)
    }else{
        let mut payload = ctaphid_cbor_responce_get_payload_1(&buf);

        // 次のパケットがある?
        if (payload.len() as u16) < payload_size {
            for _ in 1..=100 {
                // read next packet
                let mut buf = [0u8; 64];
                let _res = device.read(&mut buf[..]).unwrap();
                //println!("Read: {:?} byte", &buf[..res]);
        
                let mut p2 = ctaphid_cbor_responce_get_payload_2(&buf);
        
                // payloadに連結
                payload.append(&mut p2);
    
                // 次のパケットがある?
                if (payload.len() as u16) >= payload_size {
                    break;
                }
            }
        }
    
        // get CBOR
        let mut cbor_data: Vec<u8> = vec![];    // 空のVec生成
        for n in 1..payload_size {
            let index:usize = n.into();
            let dat = payload[index];
            cbor_data.push(dat);
        }
    
        println!("");
        println!("## Cbor Data");
        println!("{}", util::to_hex_str(&cbor_data));
        println!("##");
    
        Ok(cbor_data)    
    }
}
