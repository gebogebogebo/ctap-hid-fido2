pub struct PinToken {
    pub key: Vec<u8>,
}

impl PinToken {
    pub fn new(data: &[u8]) -> PinToken {
        PinToken { key: data.to_vec() }
    }
}
