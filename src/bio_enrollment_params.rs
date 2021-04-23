use crate::util;
use std::fmt;

#[allow(dead_code)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Modality {
    Unknown = 0x00,
    Fingerprint = 0x01,
}

#[allow(dead_code)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum FingerprintKind {
    Unknown = 0,
    TouchType = 1,
    SwipeType = 2,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct BioEnrollmentData {
    pub modality: u32,
    pub fingerprint_kind: u32,
    pub max_capture_samples_required_for_enroll: u32,
    pub template_id: Vec<u8>,
    pub last_enroll_sample_status: u32,
    pub remaining_samples: u32,
    pub template_infos: Vec<TemplateInfo>,
    pub max_template_friendly_name: u32,
}
impl fmt::Display for BioEnrollmentData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tmp1 = format!("- modality = ");
        let tmp2 = format!("- fingerprint_kind = ");
        let tmp3 = format!("- max_capture_samples_required_for_enroll = ");
        let tmp4 = format!(
            "- template_id({:02})                   = ",
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

#[derive(Debug, Default, Clone)]
pub(crate) struct TemplateInfo {
    pub template_id: Vec<u8>,
    pub template_friendly_name: String,
}
impl fmt::Display for TemplateInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tmp1 = format!(
            "- template_id({:02})                   = ",
            self.template_id.len()
        );
        let tmp2 = format!("- template_friendly_name = ");
        write!(
            f,
            "{}{}\n{}{}",
            tmp1,
            util::to_hex_str(&self.template_id),
            tmp2,
            self.template_friendly_name,
        )
    }
}
