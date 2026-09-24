use super::*;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[tokio::test]
async fn control_diagnostics_use_private_management_routes() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let server = tokio::spawn(async move {
        let mut paths = Vec::new();
        for _ in 0..2 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                assert!(request.len() < 4096);
                request.push(socket.read_u8().await.unwrap());
            }
            let request = String::from_utf8(request).unwrap();
            let path = request.split_whitespace().nth(1).unwrap().to_owned();
            let status = if ["/livez", "/readyz"].contains(&path.as_str()) {
                "200 OK"
            } else {
                "404 Not Found"
            };
            socket
                .write_all(
                    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
            paths.push(path);
        }
        paths
    });
    let mut checks = Vec::new();
    diagnose_control_endpoints(&url, &mut checks).await;
    let paths = server.await.unwrap();
    assert_eq!(paths, ["/livez", "/readyz"]);
    assert!(checks.iter().all(|check| check.ok), "{checks:?}");
}
