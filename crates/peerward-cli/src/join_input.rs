const MAX_JOIN_INPUT_BYTES: u64 = 16 * 1024;

fn read_join_invitation(
    argument: Option<String>,
    file: Option<&Path>,
) -> Result<Zeroizing<String>, CliError> {
    match (argument, file) {
        (Some(value), None) => bounded_join_input(Zeroizing::new(value).as_bytes()),
        (None, Some(path)) if path == Path::new("-") => bounded_join_input(std::io::stdin().lock()),
        (None, Some(path)) => {
            let mut options = OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
            }
            let input = options
                .open(path)
                .map_err(|_| CliError::invalid("cannot open invitation file"))?;
            let metadata = input
                .metadata()
                .map_err(|_| CliError::invalid("cannot inspect invitation file"))?;
            if !metadata.is_file() || metadata.len() > MAX_JOIN_INPUT_BYTES {
                return Err(CliError::invalid(
                    "invitation must be a bounded regular file",
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(CliError::invalid(
                        "invitation file must not be accessible by group or others",
                    ));
                }
            }
            bounded_join_input(input)
        }
        _ => Err(CliError::invalid(
            "supply exactly one invitation argument or --bundle-file",
        )),
    }
}

fn bounded_join_input(input: impl std::io::Read) -> Result<Zeroizing<String>, CliError> {
    use std::io::Read as _;
    let mut bytes = Zeroizing::new(Vec::new());
    input
        .take(MAX_JOIN_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| CliError::invalid("cannot read invitation"))?;
    if bytes.len() > usize::try_from(MAX_JOIN_INPUT_BYTES).expect("small constant") {
        return Err(CliError::invalid("invitation exceeds 16 KiB"));
    }
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| CliError::invalid("invitation must be UTF-8"))?
        .trim();
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return Err(CliError::invalid("invitation must contain one URI"));
    }
    Ok(Zeroizing::new(value.to_owned()))
}

#[cfg(test)]
mod join_input_tests {
    use super::*;

    #[test]
    fn invitation_reader_bounds_and_normalizes_without_echoing_secrets() {
        assert_eq!(
            &**bounded_join_input(&b"peerward://join?bundle=secret\n"[..]).unwrap(),
            "peerward://join?bundle=secret"
        );
        for value in [
            vec![b'x'; 16 * 1024 + 1],
            vec![0xff],
            b"one\ntwo".to_vec(),
            vec![],
        ] {
            assert!(bounded_join_input(value.as_slice()).is_err());
        }
    }

    #[test]
    fn invitation_sources_are_exclusive_in_command_parser() {
        use clap::Parser as _;
        assert!(
            Cli::try_parse_from([
                "peerward",
                "join",
                "accept",
                "--bundle-file",
                "-",
                "--output-dir",
                "profile"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "peerward",
                "join",
                "accept",
                "secret",
                "--bundle-file",
                "-",
                "--output-dir",
                "profile"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from(["peerward", "join", "accept", "--output-dir", "profile"]).is_err()
        );
    }
}
