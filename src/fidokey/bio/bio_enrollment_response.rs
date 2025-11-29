use super::bio_enrollment_params::{BioEnrollmentData, TemplateInfo};
use crate::util_ciborium;
use anyhow::Result;

pub(crate) fn parse_cbor(bytes: &[u8]) -> Result<BioEnrollmentData> {
    let mut data = BioEnrollmentData::default();
    let maps = util_ciborium::cbor_bytes_to_map(bytes)?;
    for (key, val) in &maps {
        if util_ciborium::is_integer(key) {
            match util_ciborium::integer_to_i64(key)? {
                0x01 => data.modality = util_ciborium::cbor_value_to_num(val)?,
                0x02 => data.fingerprint_kind = util_ciborium::cbor_value_to_num(val)?,
                0x03 => {
                    data.max_capture_samples_required_for_enroll =
                        util_ciborium::cbor_value_to_num(val)?
                }
                0x04 => data.template_id = util_ciborium::cbor_value_to_vec_u8(val)?,
                0x05 => data.last_enroll_sample_status = util_ciborium::cbor_value_to_num(val)?,
                0x06 => data.remaining_samples = util_ciborium::cbor_value_to_num(val)?,
                0x07 => {
                    if util_ciborium::is_array(val) {
                        let array_ref = util_ciborium::extract_array_ref(val)?;
                        for x in array_ref {
                            data.template_infos.push(TemplateInfo {
                                template_id: util_ciborium::cbor_get_bytes_from_map(x, "1")?,
                                template_friendly_name: Some(
                                    util_ciborium::cbor_get_string_from_map(x, "2")?,
                                ),
                            });
                        }
                    }
                }
                0x08 => data.max_template_friendly_name = util_ciborium::cbor_value_to_num(val)?,
                _ => println!(
                    "parse_cbor_member - unknown info {:?}",
                    util_ciborium::integer_to_i64(key)?
                ),
            }
        }
    }
    Ok(data)
}
