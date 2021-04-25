use crate::util;
use std::fmt;
use crate::FidoKeyHid;
use crate::pintoken::PinToken;

#[allow(dead_code)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Modality {
    Unknown,
    Fingerprint,
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
        let tmp1 = format!("- modality                                = ");
        let tmp2 = format!("- fingerprint_kind                        = ");
        let tmp3 = format!("- max_capture_samples_required_for_enroll = ");
        let tmp4 = format!(
            "- template_id({:02})                         = ",
            self.template_id.len()
        );
        let tmp5 = format!("- last_enroll_sample_status               = ");
        let tmp6 = format!("- remaining_samples                       = ");
        let tmp7 = format!("- max_template_friendly_name              = ");
        let tmp8 = format!("- template_infos                          = ");
        let mut tmp8_val = "".to_string();
        for i in self.template_infos.iter(){
            let tmp = format!("{}",i);
            tmp8_val.push_str(&tmp);
        }
        write!(
            f,
            "{}{}\n{}{}\n{}{}\n{}{}\n{}{}\n{}{}\n{}{}\n{}{}",
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
            self.remaining_samples,
            tmp7,
            self.max_template_friendly_name,
            tmp8,
            tmp8_val,
        )
    }
}

#[derive(Debug, Default, Clone)]
pub struct TemplateInfo {
    pub template_id: Vec<u8>,
    pub template_friendly_name: Option<String>,
}
impl TemplateInfo {
    pub fn new(template_id: Vec<u8>,template_friendly_name: Option<&str>) -> TemplateInfo {
        let mut ret = TemplateInfo::default();
        ret.template_id = template_id.clone();
        if let Some(v) = template_friendly_name {
            ret.template_friendly_name = Some(v.to_string());
        }else{
            ret.template_friendly_name = None;
        }
        ret
    }
}

impl fmt::Display for TemplateInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tmp1 = format!(
            "({:02}byte)0x",
            self.template_id.len()
        );
        let tmp2 = format!("");
        write!(
            f,
            "({}{},{}{:?})",
            tmp1,
            util::to_hex_str(&self.template_id),
            tmp2,
            self.template_friendly_name,
        )
    }
}

pub struct EnrollStatus {
    pub last_enroll_sample_status: u8,
    pub message: String,
    pub template_id: Vec<u8>,
    pub device: FidoKeyHid,
    pub cid: [u8;4],
    pub pin_token: Option<PinToken>,
}
