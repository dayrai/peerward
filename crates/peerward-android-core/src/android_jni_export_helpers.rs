fn encode_authority_update(update: &crate::AuthorityTrustUpdate) -> Result<Vec<u8>, MobileError> {
    let count = u16::try_from(update.certificates.len()).map_err(|_| MobileError::InvalidInput)?;
    let mut output = Vec::with_capacity(10 + update.certificates.len() * 144);
    output.extend_from_slice(&update.revision.to_be_bytes());
    output.extend_from_slice(&count.to_be_bytes());
    for certificate in &update.certificates {
        if certificate.len() != 144 {
            return Err(MobileError::InvalidInput);
        }
        output.extend_from_slice(certificate);
    }
    Ok(output)
}
