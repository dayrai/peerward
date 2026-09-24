#[derive(Clone, Default, PartialEq, Eq)]
struct EnrollmentDisplay {
    status: String,
    fingerprint: String,
    application: String,
}
impl EnrollmentDisplay {
    fn from_payload(value: &Value) -> Option<Self> {
        let status = value.get("status")?.as_str()?;
        if !matches!(status, "none" | "prepared" | "retained" | "pending") {
            return None;
        }
        let fingerprint = value
            .get("identity_fingerprint")
            .and_then(Value::as_str)
            .unwrap_or("");
        if status != "none"
            && (fingerprint.len() != 64
                || !fingerprint
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        {
            return None;
        }
        Some(Self {
            status: status.into(),
            fingerprint: fingerprint.into(),
            application: value
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .chars()
                .take(36)
                .collect(),
        })
    }
}
#[component]
fn EnrollmentStatus() -> Element {
    let locale = consume_context::<Signal<Locale>>();
    let enrollment = consume_context::<Signal<EnrollmentDisplay>>();
    let mut discard = use_signal(|| false);
    let display = enrollment();
    let zh = locale() == Locale::ZhCn;
    rsx! {
        section{aria_label:if zh{"接入核验与重试"}else{"Enrollment verification and retry"},
            button{class:"secondary",onclick:move |_|{send_command("prepare_join",json!({}));},
                if zh{"准备设备身份 / 查看指纹"}else{"Prepare identity / show fingerprint"}
            }
            if !display.fingerprint.is_empty(){
                p{class:"mobile-help",if zh{"通过可信的独立渠道将此指纹提供给管理员。"}else{"Give this fingerprint to your administrator through a trusted independent channel."}}
                code{"{display.fingerprint}"}
                p{role:"status",class:"mobile-help",
                    if display.status=="pending"{
                        if zh{"正在等待管理员核验；尚未获得网络访问权。"}else{"Waiting for administrator verification. Network access is not yet granted."}
                    }else if display.status=="retained"{
                        if zh{"原申请已保留。重新提交同一邀请可恢复查询，切勿生成另一套密钥。"}else{"The original claim is retained. Submit the same invitation to resume; keep the existing keys."}
                    }else{
                        if zh{"身份已保存在本机，可接收预绑定邀请。"}else{"Identity saved on this device; ready for a prebound invitation."}
                    }
                }
                if !display.application.is_empty(){details{summary{if zh{"申请详情"}else{"Request details"}}code{"{display.application}"}}}
                label{input{r#type:"checkbox",checked:discard,onchange:move |e|discard.set(e.checked())}
                    if zh{"放弃本地申请和密钥；此操作不会释放已占用的票据，后续需要新邀请。"}else{"Abandon the local claim and keys. Reserved tickets stay reserved; a new invitation will be required."}
                }
                button{class:"danger",disabled:!discard(),onclick:move |_|{send_command("discard_join",json!({"confirm_discard":true}));discard.set(false);},
                    if zh{"放弃本地申请"}else{"Abandon local claim"}
                }
            }
        }
    }
}

fn enrollment_error(locale: Locale, code: &str) -> Option<&'static str> {
    Some(match (locale, code) {
        (Locale::ZhCn, "enrollment_credential_outside_validity") => {
            "凭据尚未生效或已经过期。请检查本机日期与时间，然后用同一邀请重试；原申请和密钥已保留。"
        }
        (Locale::EnUs, "enrollment_credential_outside_validity") => {
            "The credential is not yet valid or has expired. Check the device date and time, then retry the same invitation; the original claim and keys are retained."
        }
        (
            Locale::ZhCn,
            "application_rejected" | "application_cancelled" | "application_expired",
        ) => "此申请已拒绝、取消或过期。请联系管理员获取新邀请，再放弃本地旧申请。",
        (
            Locale::EnUs,
            "application_rejected" | "application_cancelled" | "application_expired",
        ) => {
            "This request was rejected, cancelled or expired. Obtain a new invitation before abandoning the old local claim."
        }
        (Locale::ZhCn, "prebound_identity_mismatch") => {
            "邀请绑定的公钥与本机不符。请核对已准备的设备指纹，或请管理员重新邀请。"
        }
        (Locale::EnUs, "prebound_identity_mismatch") => {
            "This invitation is bound to different keys. Verify the prepared device fingerprint or request a new invitation."
        }
        (Locale::ZhCn, "state_conflict" | "not_found") => {
            "票据不可用或已被其他申请占用。请让管理员核对邀请记录；本机原申请已保留。"
        }
        (Locale::EnUs, "state_conflict" | "not_found") => {
            "The invitation is unavailable or reserved by another claim. Ask the administrator to check its history; your original claim is retained."
        }
        (Locale::ZhCn, "enrollment_failed_claim_retained") => {
            "暂时无法完成接入。原申请和密钥已保留；检查网络后重新提交同一邀请以重试。"
        }
        (Locale::EnUs, "enrollment_failed_claim_retained") => {
            "Enrollment could not complete. The original claim and keys are retained; check connectivity and submit the same invitation to retry."
        }
        (Locale::ZhCn, "enrollment_in_progress") => "接入操作正在进行，请等待当前申请结果。",
        (Locale::EnUs, "enrollment_in_progress") => {
            "Enrollment is already running. Wait for the current request."
        }
        _ => return None,
    })
}
