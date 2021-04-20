//use crate::cose;
use crate::util;
//use serde_cbor::Value;
use std::fmt;

#[derive(Debug, Default, Clone)]
pub(crate) struct BioEnrollmentData {
    pub modality: u32,
    pub fingerprint_kind: u32,
    pub max_capture_samples_required_for_enroll: u32,
    pub template_id: Vec<u8>,
    pub last_enroll_sample_status: u32,
    pub remaining_samples: u32,
    //pub template_infos: ??
    pub max_template_friendly_name: u32,
}

impl fmt::Display for BioEnrollmentData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tmp1 = format!("- modality = ");
        let tmp2 = format!("- fingerprint_kind = ");
        let tmp3 = format!("- max_capture_samples_required_for_enroll = ");
        let tmp4 = format!("- template_id({:02})                   = ",
            self.template_id.len()
        );
        let tmp5 = format!("- last_enroll_sample_status = ");
        let tmp6 = format!("- max_template_friendly_name = ");
        write!(
            f,
            "{}{}\n{}{}\n{}{}\n{}{}\n{}{}\n{}{}",
            tmp1,
            self.modality,
            tmp2,
            self.fingerprint_kind,
            tmp3,
            self.max_capture_samples_required_for_enroll,
            tmp4,
            util::to_hex_str(&self.template_id),
            tmp5,
            self.last_enroll_sample_status,
            tmp6,
            self.max_template_friendly_name,
        )
    }
}
