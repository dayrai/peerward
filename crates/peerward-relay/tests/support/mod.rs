use std::net::SocketAddr;

use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream, lookup_host},
    sync::watch,
};

pub struct DatabaseFaultProxy {
    blocked: watch::Sender<bool>,
    shutdown: watch::Sender<bool>,
}

impl DatabaseFaultProxy {
    pub async fn start(database_url: &str) -> (Self, String) {
        let scheme = database_url.find("://").expect("database URL scheme") + 3;
        let path = database_url[scheme..].find('/').expect("database URL path") + scheme;
        let authority = &database_url[scheme..path];
        let host = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host);
        let target = lookup_host(host)
            .await
            .expect("database host lookup")
            .next()
            .expect("database host address");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let (blocked, blocked_rx) = watch::channel(false);
        let (shutdown, shutdown_rx) = watch::channel(false);
        tokio::spawn(run_proxy(listener, target, blocked_rx, shutdown_rx));

        let user = authority
            .rsplit_once('@')
            .map_or(String::new(), |(user, _)| format!("{user}@"));
        let proxied = format!(
            "{}{}{}{}",
            &database_url[..scheme],
            user,
            endpoint,
            &database_url[path..]
        );
        (Self { blocked, shutdown }, proxied)
    }

    pub fn set_blocked(&self, blocked: bool) {
        self.blocked.send_replace(blocked);
    }
}

impl Drop for DatabaseFaultProxy {
    fn drop(&mut self) {
        self.shutdown.send_replace(true);
    }
}

async fn run_proxy(
    listener: TcpListener,
    target: SocketAddr,
    mut blocked: watch::Receiver<bool>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((client, _)) = accepted else { return; };
                if *blocked.borrow() {
                    drop(client);
                    continue;
                }
                tokio::spawn(proxy_connection(
                    client,
                    target,
                    blocked.clone(),
                    shutdown.clone(),
                ));
            }
            changed = blocked.changed() => {
                if changed.is_err() { return; }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { return; }
            }
        }
    }
}

async fn proxy_connection(
    mut client: TcpStream,
    target: SocketAddr,
    mut blocked: watch::Receiver<bool>,
    mut shutdown: watch::Receiver<bool>,
) {
    let Ok(mut server) = TcpStream::connect(target).await else {
        return;
    };
    tokio::select! {
        _ = copy_bidirectional(&mut client, &mut server) => {}
        () = wait_true(&mut blocked) => {}
        () = wait_true(&mut shutdown) => {}
    }
}

async fn wait_true(receiver: &mut watch::Receiver<bool>) {
    while !*receiver.borrow() && receiver.changed().await.is_ok() {}
}
