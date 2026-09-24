#[cfg(test)]
mod webhook_tls_tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

    struct TlsFixture(std::path::PathBuf);
    impl Drop for TlsFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn pinned_https_retains_certificate_hostname_checks_and_rejects_redirects() {
        let root = std::env::temp_dir().join(format!("peerward-webhook-tls-{}", Uuid::new_v4()));
        private_dir(&root).unwrap();
        let fixture = TlsFixture(root);
        let cert = fixture.0.join("certificate.pem");
        let key = fixture.0.join("key.pem");
        // This independently generated, short-lived test CA is trusted only by
        // the isolated client below. Production keeps platform/WebPKI roots.
        let output = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-noenc",
                "-days",
                "2",
                "-subj",
                "/CN=webhook-fixture.example",
                "-addext",
                "subjectAltName=DNS:webhook-fixture.example",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-keyout",
            ])
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated TLS certificate generation"
        );
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certs = CertificateDer::pem_file_iter(&cert)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let private = PrivateKeyDer::from_pem_slice(&std::fs::read(&key).unwrap()).unwrap();
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, private)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = count.clone();
        let router = Router::new()
            .route(
                "/accept",
                post(move || {
                    let seen = seen.clone();
                    async move {
                        seen.fetch_add(1, Ordering::SeqCst);
                        StatusCode::NO_CONTENT
                    }
                }),
            )
            .route(
                "/redirect",
                post(move || async move {
                    (
                        StatusCode::TEMPORARY_REDIRECT,
                        [(
                            header::LOCATION,
                            format!("https://webhook-fixture.example:{}/accept", address.port()),
                        )],
                    )
                }),
            );
        let server = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                let router = router.clone();
                tokio::spawn(async move {
                    let Ok(Ok(socket)) =
                        tokio::time::timeout(Duration::from_secs(3), acceptor.accept(socket)).await
                    else {
                        return;
                    };
                    let service = hyper_util::service::TowerToHyperService::new(router);
                    let builder = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    );
                    let _ = tokio::time::timeout(
                        Duration::from_secs(3),
                        builder.serve_connection(hyper_util::rt::TokioIo::new(socket), service),
                    )
                    .await;
                });
            }
        });
        let trusted =
            || oidc_reqwest::Certificate::from_pem(&std::fs::read(&cert).unwrap()).unwrap();
        // Public production destinations are validated before constructing this
        // builder. Loopback/high port is exclusively the owned TLS test fixture.
        let client = webhook_http_client("webhook-fixture.example", &[address])
            .add_root_certificate(trusted())
            .build()
            .unwrap();
        let url: Url = format!("https://webhook-fixture.example:{}/accept", address.port())
            .parse()
            .unwrap();
        let result = webhook_http_send(
            &client,
            url.clone(),
            Uuid::new_v4(),
            b"fixture".to_vec(),
            [0; 64],
        )
        .await;
        assert!(result.is_ok_and(|result| result.success));
        let untrusted = webhook_http_client("webhook-fixture.example", &[address])
            .build()
            .unwrap();
        assert!(
            webhook_http_send(
                &untrusted,
                url,
                Uuid::new_v4(),
                b"fixture".to_vec(),
                [0; 64]
            )
            .await
            .is_err()
        );
        let wrong = webhook_http_client("wrong-fixture.example", &[address])
            .add_root_certificate(trusted())
            .build()
            .unwrap();
        assert!(
            webhook_http_send(
                &wrong,
                format!("https://wrong-fixture.example:{}/accept", address.port())
                    .parse()
                    .unwrap(),
                Uuid::new_v4(),
                b"fixture".to_vec(),
                [0; 64]
            )
            .await
            .is_err()
        );
        let result = webhook_http_send(
            &client,
            format!(
                "https://webhook-fixture.example:{}/redirect",
                address.port()
            )
            .parse()
            .unwrap(),
            Uuid::new_v4(),
            b"fixture".to_vec(),
            [0; 64],
        )
        .await
        .unwrap_or_else(|_| panic!("TLS redirect request failed"));
        assert!(result.permanent && !result.success);
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "invalid TLS or redirects must never reach the receiver"
        );
        server.abort();
    }
}
