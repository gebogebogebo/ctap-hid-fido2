use crate::cose;
use crate::util;
use serde_cbor::Value;
use std::fmt;

#[derive(Debug, Default, Clone)]
pub(crate) struct BioEnrollmentData {
    pub modality: u32,
}
