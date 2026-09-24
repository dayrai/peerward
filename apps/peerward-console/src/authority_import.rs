#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityFileDocument {
    schema_version: u32,
    mesh_id: MeshId,
    serial: CredentialSerial,
    public_key: String,
    not_before: u64,
    not_after: u64,
    signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ImportedAuthorityCertificate {
    mesh_id: MeshId,
    serial: CredentialSerial,
    public_key: [u8; 32],
    not_before: UnixTime,
    not_after: UnixTime,
    signature: [u8; 64],
}

impl ImportedAuthorityCertificate {
    fn decode(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() != 144 {
            return Err(());
        }
        Ok(Self {
            mesh_id: MeshId::from_uuid(uuid::Uuid::from_slice(&bytes[..16]).map_err(|_| ())?)
                .map_err(|_| ())?,
            serial: CredentialSerial::from_uuid(
                uuid::Uuid::from_slice(&bytes[16..32]).map_err(|_| ())?,
            )
            .map_err(|_| ())?,
            public_key: bytes[32..64].try_into().map_err(|_| ())?,
            not_before: UnixTime(u64::from_be_bytes(bytes[64..72].try_into().map_err(|_| ())?)),
            not_after: UnixTime(u64::from_be_bytes(bytes[72..80].try_into().map_err(|_| ())?)),
            signature: bytes[80..144].try_into().map_err(|_| ())?,
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(144);
        bytes.extend_from_slice(self.mesh_id.as_bytes());
        bytes.extend_from_slice(self.serial.as_bytes());
        bytes.extend_from_slice(&self.public_key);
        bytes.extend_from_slice(&self.not_before.0.to_be_bytes());
        bytes.extend_from_slice(&self.not_after.0.to_be_bytes());
        bytes.extend_from_slice(&self.signature);
        bytes
    }
}

fn decode_hex_array<const LENGTH: usize>(value: &str) -> Result<[u8; LENGTH], ()> {
    hex::decode(value).map_err(|_| ())?.try_into().map_err(|_| ())
}

fn parse_authority_certificate_file(bytes: &[u8]) -> Result<ImportedAuthorityCertificate, ()> {
    if let Ok(certificate) = ImportedAuthorityCertificate::decode(bytes) {
        return Ok(certificate);
    }
    if bytes.len() > 8 * 1024 {
        return Err(());
    }
    let document: AuthorityFileDocument =
        toml::from_str(std::str::from_utf8(bytes).map_err(|_| ())?).map_err(|_| ())?;
    if document.schema_version != 1 || document.not_before >= document.not_after {
        return Err(());
    }
    let certificate = ImportedAuthorityCertificate {
        mesh_id: document.mesh_id,
        serial: document.serial,
        public_key: decode_hex_array(&document.public_key)?,
        not_before: UnixTime(document.not_before),
        not_after: UnixTime(document.not_after),
        signature: decode_hex_array(&document.signature)?,
    };
    ImportedAuthorityCertificate::decode(&certificate.encode())
}

#[component]
fn AuthorityCertificateImport(
    document: Signal<String>,
    disabled: bool,
    locale: Locale,
) -> Element {
    let mesh_id = editor_value(&document(), "certificate_mesh_id");
    let serial = editor_value(&document(), "certificate_serial");
    let not_before = editor_value(&document(), "certificate_not_before");
    let not_after = editor_value(&document(), "certificate_not_after");
    let file_name = editor_value(&document(), "certificate_file_name");
    let error = editor_value(&document(), "certificate_import_error");
    rsx! {
        label { r#for: "authority-certificate-file", {console_message(locale, "authority-certificate-file")} }
        input {
            id: "authority-certificate-file",
            r#type: "file",
            accept: ".cert,application/octet-stream,text/plain",
            disabled,
            onchange: move |event| {
                let Some(file) = event.files().into_iter().next() else { return };
                let name = file.name();
                if file.size() > 8 * 1024 {
                    set_editor_values(document, &[
                        ("certificate", String::new()),
                        ("certificate_file_name", name),
                        ("certificate_import_error", console_message(locale, "certificate-file-invalid").into()),
                    ]);
                    return;
                }
                spawn(async move {
                    let parsed = file.read_bytes().await.ok()
                        .and_then(|bytes| parse_authority_certificate_file(&bytes).ok());
                    if let Some(certificate) = parsed {
                        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
                        set_editor_values(document, &[
                            ("certificate", URL_SAFE_NO_PAD.encode(certificate.encode())),
                            ("certificate_file_name", name),
                            ("certificate_mesh_id", certificate.mesh_id.to_string()),
                            ("certificate_serial", certificate.serial.to_string()),
                            ("certificate_not_before", certificate.not_before.0.to_string()),
                            ("certificate_not_after", certificate.not_after.0.to_string()),
                            ("certificate_import_error", String::new()),
                        ]);
                    } else {
                        set_editor_values(document, &[
                            ("certificate", String::new()),
                            ("certificate_file_name", name),
                            ("certificate_import_error", console_message(locale, "certificate-file-invalid").into()),
                        ]);
                    }
                });
            },
        }
        if !error.is_empty() { p { class: "error", role: "alert", "{error}" } }
        if !serial.is_empty() {
            fieldset { class: "certificate-preview",
                legend { {console_message(locale, "certificate-preview")} }
                dl {
                    dt { {console_message(locale, "file-name")} } dd { "{file_name}" }
                    dt { {console_message(locale, "mesh-id")} } dd { code { "{mesh_id}" } }
                    dt { {console_message(locale, "credential-serial")} } dd { code { "{serial}" } }
                    dt { {console_message(locale, "not-before")} } dd { "{not_before}" }
                    dt { {console_message(locale, "not-after")} } dd { "{not_after}" }
                }
            }
        }
    }
}

#[cfg(test)]
mod authority_import_tests {
    use super::*;

    fn certificate() -> ImportedAuthorityCertificate {
        ImportedAuthorityCertificate {
            mesh_id: MeshId::new(),
            serial: CredentialSerial::new(),
            public_key: [7; 32],
            not_before: UnixTime(100),
            not_after: UnixTime(200),
            signature: [9; 64],
        }
    }

    #[test]
    fn authority_import_accepts_exact_binary_and_strict_bootstrap_document() {
        let expected = certificate();
        assert_eq!(
            parse_authority_certificate_file(&expected.encode()),
            Ok(expected.clone())
        );
        let document = format!(
            "schema_version = 1\nmesh_id = \"{}\"\nserial = \"{}\"\npublic_key = \"{}\"\nnot_before = 100\nnot_after = 200\nsignature = \"{}\"\n",
            expected.mesh_id,
            expected.serial,
            hex::encode(expected.public_key),
            hex::encode(expected.signature),
        );
        assert_eq!(
            parse_authority_certificate_file(document.as_bytes()),
            Ok(expected)
        );
        assert!(
            parse_authority_certificate_file(format!("{document}unknown = true\n").as_bytes())
                .is_err()
        );
    }
}
