use crate::{pintoken::PinToken, str_buf::StrBuf, util};
use std::fmt;

pub struct EnrollStatus1 {
    pub pin_token: Option<PinToken>,
    pub template_id: Vec<u8>,
}

#[derive(Debug, Default, Clone)]
pub struct BioSensorInfo {
    pub modality: Modality,
    pub fingerprint_kind: FingerprintKind,
    pub max_capture_samples_required_for_enroll: u32,
    pub max_template_friendly_name: u32,
}

impl fmt::Display for BioSensorInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut strbuf = StrBuf::new(0);
        strbuf.addln("- Modality");
        strbuf.addln(&format!("  - {:?}", self.modality));

        strbuf.addln("- Fingerprint kind");
        match self.fingerprint_kind {
            FingerprintKind::TouchType => {
                strbuf.addln("  - touch type fingerprints");
            }
            FingerprintKind::SwipeType => {
                strbuf.addln("  - swipe type fingerprints");
            }
            _ => {
                strbuf.addln("  - unknown");
            }
        }

        strbuf.addln("- Maximum good samples required for enrollment");
        strbuf.addln(&format!(
            "  - {:?}",
            self.max_capture_samples_required_for_enroll
        ));

        strbuf.addln(
            "- Maximum number of bytes the authenticator will accept as a templateFriendlyName",
        );
        strbuf.addln(&format!("  - {:?}", self.max_template_friendly_name));

        write!(f, "{}", strbuf.build())
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub enum Modality {
    #[default]
    Unknown,
    Fingerprint,
}
impl From<u32> for Modality {
    fn from(from: u32) -> Modality {
        match from {
            0x01 => Modality::Fingerprint,
            _ => Modality::Unknown,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Copy, Clone, Default)]
pub enum FingerprintKind {
    #[default]
    Unknown = 0,
    TouchType = 1,
    SwipeType = 2,
}
impl From<u32> for FingerprintKind {
    fn from(from: u32) -> FingerprintKind {
        match from {
            0x01 => FingerprintKind::TouchType,
            0x02 => FingerprintKind::SwipeType,
            _ => FingerprintKind::Unknown,
        }
    }
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
        let mut tmp_val = "".to_string();
        for i in self.template_infos.iter() {
            tmp_val.push_str(&format!("{}", i));
        }

        let mut strbuf = StrBuf::new(19);
        strbuf
            .append("- modality", &self.modality)
            .append("- fingerprint_kind", &self.fingerprint_kind)
            .append(
                "- max_capture_samples_required_for_enroll",
                &self.max_capture_samples_required_for_enroll,
            )
            .appenh("- template_id", &self.template_id)
            .append(
                "- last_enroll_sample_status",
                &self.last_enroll_sample_status,
            )
            .append("- remaining_samples", &self.remaining_samples)
            .append(
                "- max_template_friendly_name",
                &self.max_template_friendly_name,
            )
            .append("- template_infos", &tmp_val);
        write!(f, "{}", strbuf.build())
    }
}

#[derive(Debug, Default, Clone)]
pub struct TemplateInfo {
    pub template_id: Vec<u8>,
    pub template_friendly_name: Option<String>,
}
impl TemplateInfo {
    pub fn new(template_id: &[u8], template_friendly_name: Option<&str>) -> TemplateInfo {
        let mut ret = TemplateInfo {
            template_id: template_id.to_vec(),
            ..Default::default()
        };
        if let Some(v) = template_friendly_name {
            ret.template_friendly_name = Some(v.to_string());
        } else {
            ret.template_friendly_name = None;
        }
        ret
    }
}

impl fmt::Display for TemplateInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.template_friendly_name.clone().unwrap();
        let mut strbuf = StrBuf::new(19);
        /*
        strbuf
            .appenh("- template_id", &self.template_id)
            .append("- template_friendly_name", &name);
        write!(f, "{}", strbuf.build())
        */

        strbuf.add(&format!("{:02} : ", util::to_hex_str(&self.template_id)));
        strbuf.add(&name);
        write!(f, "{}", strbuf.build())
    }
}

pub struct EnrollStatus2 {
    pub status: u8,
    pub message: String,
    pub remaining_samples: u32,
    pub is_finish: bool,
}
impl fmt::Display for EnrollStatus2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut strbuf = StrBuf::new(19);
        strbuf
            .append("- status", &self.status)
            .append("- message", &self.message)
            .append("- remaining_samples", &self.remaining_samples)
            .append("- is_finish", &self.is_finish);
        write!(f, "{}", strbuf.build())
    }
}
