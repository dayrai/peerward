use std::{
    future::Future,
    net::{SocketAddr, ToSocketAddrs},
    time::Duration,
};

use peerward_types::{MAX_STUN_SERVERS, StunEndpoint, valid_stun_destination};
use tokio::{sync::Semaphore, task::JoinSet};

// A timed-out libc lookup cannot be cancelled. Its permit stays inside the blocking
// worker until libc returns, so repeated network changes cannot grow DNS work forever.
static DNS_BUDGET: Semaphore = Semaphore::const_new(16);

/// Resolves the current underlay's STUN destinations afresh, within a one-second budget.
/// Failure is an empty discovery result; it never prevents Relay connectivity.
pub async fn resolve_stun_servers(servers: &[StunEndpoint], ipv4: bool) -> Vec<SocketAddr> {
    resolve_with(servers, ipv4, Duration::from_secs(1), |server| async move {
        if let Some(address) = server.socket_addr() {
            return vec![address];
        }
        let Ok(permit) = DNS_BUDGET.acquire().await else {
            return Vec::new();
        };
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            (server.host().as_str(), server.port())
                .to_socket_addrs()
                .map(|answers| answers.take(64).collect())
                .unwrap_or_default()
        })
        .await
        .unwrap_or_default()
    })
    .await
}

/// Bounded, fair discovery using a platform-protected resolver instead of libc.
pub async fn resolve_with<F, R>(
    servers: &[StunEndpoint],
    ipv4: bool,
    timeout: Duration,
    resolve: F,
) -> Vec<SocketAddr>
where
    F: Fn(StunEndpoint) -> R,
    R: Future<Output = Vec<SocketAddr>> + Send + 'static,
{
    let mut tasks = JoinSet::new();
    for (index, server) in servers.iter().take(MAX_STUN_SERVERS).enumerate() {
        let lookup = resolve(server.clone());
        tasks.spawn(async move { (index, lookup.await) });
    }
    let mut answers = vec![Vec::new(); servers.len().min(MAX_STUN_SERVERS)];
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    while !tasks.is_empty() {
        tokio::select! {
            biased;
            () = &mut deadline => break,
            result = tasks.join_next() => {
                if let Some(Ok((index, resolved))) = result {
                    let mut unique = std::collections::BTreeSet::new();
                    answers[index] = resolved.into_iter().take(64)
                        .filter(|address| address.is_ipv4() == ipv4 && valid_stun_destination(*address))
                        .filter(|address| unique.insert(*address))
                        .take(MAX_STUN_SERVERS).collect();
                }
            }
        }
    }
    let mut selected = Vec::new();
    // Give every configured server a slot before considering its additional DNS answers.
    for offset in 0..MAX_STUN_SERVERS {
        for server in &answers {
            if let Some(address) = server.get(offset)
                && !selected.contains(address)
            {
                selected.push(*address);
                if selected.len() == MAX_STUN_SERVERS {
                    return selected;
                }
            }
        }
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolution_is_bounded_fair_and_filters_each_address_family() {
        let servers = [
            "many.example:3478".parse().unwrap(),
            "other.example:443".parse().unwrap(),
        ];
        let resolve = |server: StunEndpoint| async move {
            if server.port() == 443 {
                return vec!["192.0.2.200:443".parse().unwrap()];
            }
            let mut answers = vec![
                "0.0.0.0:3478".parse().unwrap(),
                "224.0.0.1:3478".parse().unwrap(),
                "[2001:db8::1]:3478".parse().unwrap(),
            ];
            answers.extend(
                (1..=32).map(|i| format!("192.0.2.{i}:3478").parse::<SocketAddr>().unwrap()),
            );
            answers
        };
        let addresses = resolve_with(&servers, true, Duration::from_secs(1), resolve).await;
        assert_eq!(addresses.len(), 8);
        assert_eq!(addresses[0], "192.0.2.1:3478".parse().unwrap());
        assert_eq!(addresses[1], "192.0.2.200:443".parse().unwrap());
        assert_eq!(
            resolve_with(&servers, false, Duration::from_secs(1), resolve).await,
            vec!["[2001:db8::1]:3478".parse::<SocketAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn stalled_dns_does_not_discard_completed_results_or_block_discovery() {
        let servers = [
            "stall.example:3478".parse().unwrap(),
            "ready.example:443".parse().unwrap(),
        ];
        let addresses = resolve_with(
            &servers,
            true,
            Duration::from_millis(20),
            |server| async move {
                if server.port() == 3478 {
                    std::future::pending::<()>().await;
                }
                vec!["192.0.2.1:443".parse().unwrap(); 32]
            },
        )
        .await;
        assert_eq!(
            addresses,
            vec!["192.0.2.1:443".parse::<SocketAddr>().unwrap()]
        );
        assert!(resolve_stun_servers(&[], false).await.is_empty());
        assert_eq!(
            resolve_stun_servers(&["[::1]:3478".parse().unwrap()], false).await,
            vec!["[::1]:3478".parse::<SocketAddr>().unwrap()]
        );
    }
}
