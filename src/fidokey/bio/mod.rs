mod bio_enrollment_command;
mod bio_enrollment_params;
mod bio_enrollment_response;
use crate::pintoken::PinToken;
use crate::util;
use crate::{ctapdef, ctaphid};
use crate::{fidokey::pin::Permission::BioEnrollment, FidoKeyHid};
#[cfg(feature = "tokio")]use crate::FidoKeyHidAsync;
use anyhow::Result;
pub use bio_enrollment_command::SubCommand as BioCmd;
pub use bio_enrollment_params::*;

impl FidoKeyHid {
    /// BioEnrollment - getFingerprintSensorInfo (CTAP 2.1-PRE)
    pub fn bio_enrollment_get_fingerprint_sensor_info(&self) -> Result<BioSensorInfo> {
        // 6.7.2. Get bio modality
        let data1 = self.bio_enrollment(None, None)?;
        if self.enable_log {
            println!("{}", data1);
        }

        // 6.7.3. Get fingerprint sensor info
        let data2 = self.bio_enrollment(None, Some(BioCmd::GetFingerprintSensorInfo))?;

        if self.enable_log {
            println!("{}", data2);
        }

        Ok(BioSensorInfo {
            modality: data1.modality.into(),
            fingerprint_kind: data2.fingerprint_kind.into(),
            max_capture_samples_required_for_enroll: data2.max_capture_samples_required_for_enroll,
            max_template_friendly_name: data2.max_template_friendly_name,
        })
    }

    /// BioEnrollment - EnrollBegin
    pub fn bio_enrollment_begin(
        &self,
        pin: &str,
        timeout_milliseconds: Option<u16>,
    ) -> Result<(EnrollStatus1, EnrollStatus2)> {
        let pin_token_option = self.bio_enrollment_init(Some(pin))?;

        let data = self.bio_enrollment(
            pin_token_option.as_ref(),
            Some(BioCmd::EnrollBegin(timeout_milliseconds)),
        )?;

        if self.enable_log {
            println!("{}", data);
        }

        let result1 = EnrollStatus1 {
            pin_token: pin_token_option,
            template_id: data.template_id.to_vec(),
        };

        let finish = data.last_enroll_sample_status == 0x00 && data.remaining_samples == 0;
        let result2 = EnrollStatus2 {
            status: data.last_enroll_sample_status as u8,
            message: ctapdef::get_ctap_last_enroll_sample_status_message(
                data.last_enroll_sample_status as u8,
            ),
            remaining_samples: data.remaining_samples,
            is_finish: finish,
        };
        Ok((result1, result2))
    }

    /// BioEnrollment - CaptureNext
    pub fn bio_enrollment_next(
        &self,
        enroll_status: &EnrollStatus1,
        timeout_milliseconds: Option<u16>,
    ) -> Result<EnrollStatus2> {
        let template_info = TemplateInfo::new(&enroll_status.template_id, None);
        let data = self.bio_enrollment(
            enroll_status.pin_token.as_ref(),
            Some(BioCmd::EnrollCaptureNextSample(
                template_info,
                timeout_milliseconds,
            )),
        )?;

        if self.enable_log {
            println!("{}", data);
        }

        let finish = data.last_enroll_sample_status == 0x00 && data.remaining_samples == 0;
        let result = EnrollStatus2 {
            status: data.last_enroll_sample_status as u8,
            message: ctapdef::get_ctap_last_enroll_sample_status_message(
                data.last_enroll_sample_status as u8,
            ),
            remaining_samples: data.remaining_samples,
            is_finish: finish,
        };
        Ok(result)
    }

    /// BioEnrollment - Cancel current enrollment
    pub fn bio_enrollment_cancel(&self) -> Result<()> {
        let data = self.bio_enrollment(
            None,
            Some(BioCmd::CancelCurrentEnrollment),
        )?;

        if self.enable_log {
            println!("{}", data);
        }

        Ok(())
    }

    /// BioEnrollment - enumerateEnrollments (CTAP 2.1-PRE)
    /// 6.7.6. Enumerate enrollments
    pub fn bio_enrollment_enumerate_enrollments(&self, pin: &str) -> Result<Vec<TemplateInfo>> {
        let pin_token_option = self.bio_enrollment_init(Some(pin))?;
        let pin_token = pin_token_option.unwrap();

        let data = self.bio_enrollment(
            Some(&pin_token),
            Some(BioCmd::EnumerateEnrollments),
        )?;

        if self.enable_log {
            println!("{}", data);
        }

        Ok(data.template_infos)
    }

    /// BioEnrollment - Rename/Set FriendlyName
    /// 6.7.7. Rename/Set FriendlyName
    pub fn bio_enrollment_set_friendly_name(
        &self,
        pin: &str,
        template_id: &[u8],
        template_name: &str,
    ) -> Result<()> {
        let template_info = TemplateInfo::new(template_id, Some(template_name));

        let pin_token_option = self.bio_enrollment_init(Some(pin))?;
        let pin_token = pin_token_option.unwrap();

        let data = self.bio_enrollment(
            Some(&pin_token),
            Some(BioCmd::SetFriendlyName(template_info)),
        )?;

        if self.enable_log {
            println!("{}", data);
        }

        Ok(())
    }

    /// 6.7.8. Remove enrollment
    pub fn bio_enrollment_remove(&self, pin: &str, template_id: &[u8]) -> Result<()> {
        let pin_token_option = self.bio_enrollment_init(Some(pin))?;
        let pin_token = pin_token_option.unwrap();

        let template_info = TemplateInfo::new(template_id, None);
        let data = self.bio_enrollment(
            Some(&pin_token),
            Some(BioCmd::RemoveEnrollment(template_info)),
        )?;

        if self.enable_log {
            println!("{}", data);
        }

        Ok(())
    }

    fn bio_enrollment(
        &self,
        pin_token: Option<&PinToken>,
        sub_command: Option<bio_enrollment_command::SubCommand>,
    ) -> Result<BioEnrollmentData> {
        let send_payload = bio_enrollment_command::create_payload(
            pin_token,
            sub_command,
            self.use_pre_bio_enrollment,
        )?;

        if self.enable_log {
            println!("send(cbor) = {}", util::to_hex_str(&send_payload));
        }

        let response_cbor = ctaphid::ctaphid_cbor(self, &send_payload)?;
        if self.enable_log {
            println!("response(cbor) = {}", util::to_hex_str(&response_cbor));
        }

        let ret = bio_enrollment_response::parse_cbor(&response_cbor)?;
        Ok(ret)
    }

    fn bio_enrollment_init(&self, pin: Option<&str>) -> Result<Option<PinToken>> {
        // pin token
        let pin_token = {
            if let Some(pin) = pin {
                if self.use_pre_bio_enrollment {
                    Some(self.get_pin_token(pin)?)
                } else {
                    Some(self.get_pinuv_auth_token_with_permission(pin, BioEnrollment)?)
                }
            } else {
                None
            }
        };

        Ok(pin_token)
    }
}

#[cfg(feature = "tokio")]impl FidoKeyHidAsync {
    /// BioEnrollment - getFingerprintSensorInfo (CTAP 2.1-PRE)
    pub async fn bio_enrollment_get_fingerprint_sensor_info(&self) -> Result<BioSensorInfo> {
        // 6.7.2. Get bio modality
        let data1 = self.bio_enrollment(None, None).await?;
        if self.enable_log {
            println!("{}", data1);
        }

        // 6.7.3. Get fingerprint sensor info
        let data2 = self.bio_enrollment(None, Some(BioCmd::GetFingerprintSensorInfo)).await?;

        if self.enable_log {
            println!("{}", data2);
        }

        Ok(BioSensorInfo {
            modality: data1.modality.into(),
            fingerprint_kind: data2.fingerprint_kind.into(),
            max_capture_samples_required_for_enroll: data2.max_capture_samples_required_for_enroll,
            max_template_friendly_name: data2.max_template_friendly_name,
        })
    }

    /// BioEnrollment - EnrollBegin
    pub async fn bio_enrollment_begin(
        &self,
        pin: &str,
        timeout_milliseconds: Option<u16>,
    ) -> Result<(EnrollStatus1, EnrollStatus2)> {
        let pin_token_option = self.bio_enrollment_init(Some(pin)).await?;

        let data = self.bio_enrollment(
            pin_token_option.as_ref(),
            Some(BioCmd::EnrollBegin(timeout_milliseconds)),
        ).await?;

        if self.enable_log {
            println!("{}", data);
        }

        let result1 = EnrollStatus1 {
            pin_token: pin_token_option,
            template_id: data.template_id.to_vec(),
        };

        let finish = data.last_enroll_sample_status == 0x00 && data.remaining_samples == 0;
        let result2 = EnrollStatus2 {
            status: data.last_enroll_sample_status as u8,
            message: ctapdef::get_ctap_last_enroll_sample_status_message(
                data.last_enroll_sample_status as u8,
            ),
            remaining_samples: data.remaining_samples,
            is_finish: finish,
        };
        Ok((result1, result2))
    }

    /// BioEnrollment - CaptureNext
    pub async fn bio_enrollment_next(
        &self,
        enroll_status: &EnrollStatus1,
        timeout_milliseconds: Option<u16>,
    ) -> Result<EnrollStatus2> {
        let template_info = TemplateInfo::new(&enroll_status.template_id, None);
        let data = self.bio_enrollment(
            enroll_status.pin_token.as_ref(),
            Some(BioCmd::EnrollCaptureNextSample(
                template_info,
                timeout_milliseconds,
            )),
        ).await?;

        if self.enable_log {
            println!("{}", data);
        }

        let finish = data.last_enroll_sample_status == 0x00 && data.remaining_samples == 0;
        let result = EnrollStatus2 {
            status: data.last_enroll_sample_status as u8,
            message: ctapdef::get_ctap_last_enroll_sample_status_message(
                data.last_enroll_sample_status as u8,
            ),
            remaining_samples: data.remaining_samples,
            is_finish: finish,
        };
        Ok(result)
    }

    /// BioEnrollment - Cancel current enrollment
    pub async fn bio_enrollment_cancel(&self) -> Result<()> {
        let data = self.bio_enrollment(
            None,
            Some(BioCmd::CancelCurrentEnrollment),
        ).await?;

        if self.enable_log {
            println!("{}", data);
        }

        Ok(())
    }

    /// BioEnrollment - enumerateEnrollments (CTAP 2.1-PRE)
    /// 6.7.6. Enumerate enrollments
    pub async fn bio_enrollment_enumerate_enrollments(&self, pin: &str) -> Result<Vec<TemplateInfo>> {
        let pin_token_option = self.bio_enrollment_init(Some(pin)).await?;
        let pin_token = pin_token_option.unwrap();

        let data = self.bio_enrollment(
            Some(&pin_token),
            Some(BioCmd::EnumerateEnrollments),
        ).await?;

        if self.enable_log {
            println!("{}", data);
        }

        Ok(data.template_infos)
    }

    /// BioEnrollment - Rename/Set FriendlyName
    /// 6.7.7. Rename/Set FriendlyName
    pub async fn bio_enrollment_set_friendly_name(
        &self,
        pin: &str,
        template_id: &[u8],
        template_name: &str,
    ) -> Result<()> {
        let template_info = TemplateInfo::new(template_id, Some(template_name));

        let pin_token_option = self.bio_enrollment_init(Some(pin)).await?;
        let pin_token = pin_token_option.unwrap();

        let data = self.bio_enrollment(
            Some(&pin_token),
            Some(BioCmd::SetFriendlyName(template_info)),
        ).await?;

        if self.enable_log {
            println!("{}", data);
        }

        Ok(())
    }

    /// 6.7.8. Remove enrollment
    pub async fn bio_enrollment_remove(&self, pin: &str, template_id: &[u8]) -> Result<()> {
        let pin_token_option = self.bio_enrollment_init(Some(pin)).await?;
        let pin_token = pin_token_option.unwrap();

        let template_info = TemplateInfo::new(template_id, None);
        let data = self.bio_enrollment(
            Some(&pin_token),
            Some(BioCmd::RemoveEnrollment(template_info)),
        ).await?;

        if self.enable_log {
            println!("{}", data);
        }

        Ok(())
    }

    async fn bio_enrollment(
        &self,
        pin_token: Option<&PinToken>,
        sub_command: Option<bio_enrollment_command::SubCommand>,
    ) -> Result<BioEnrollmentData> {
        let send_payload = bio_enrollment_command::create_payload(
            pin_token,
            sub_command,
            self.use_pre_bio_enrollment,
        )?;

        if self.enable_log {
            println!("send(cbor) = {}", util::to_hex_str(&send_payload));
        }

        let response_cbor = ctaphid::ctaphid_cbor_async(self, &send_payload).await?;
        if self.enable_log {
            println!("response(cbor) = {}", util::to_hex_str(&response_cbor));
        }

        let ret = bio_enrollment_response::parse_cbor(&response_cbor)?;
        Ok(ret)
    }

    async fn bio_enrollment_init(&self, pin: Option<&str>) -> Result<Option<PinToken>> {
        // pin token
        let pin_token = {
            if let Some(pin) = pin {
                if self.use_pre_bio_enrollment {
                    Some(self.get_pin_token(pin).await?)
                } else {
                    Some(self.get_pinuv_auth_token_with_permission(pin, BioEnrollment).await?)
                }
            } else {
                None
            }
        };

        Ok(pin_token)
    }
}
