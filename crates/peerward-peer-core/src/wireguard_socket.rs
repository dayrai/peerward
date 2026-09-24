//! All authenticated path-size probes must arrive without outer IP fragmentation.
use std::{io, os::fd::AsFd};

/// Disable IPv4 and IPv6 source fragmentation on a data socket before its first probe.
/// Android's IPv6 sockets can also send IPv4-mapped traffic, so set both options.
///
/// # Errors
/// Returns the socket option error; a socket without this guarantee must not be used.
pub fn configure_wireguard_udp(socket: &impl AsFd, ipv6: bool) -> io::Result<()> {
    use rustix::net::sockopt::{
        Ipv4PathMtuDiscovery, Ipv6PathMtuDiscovery, set_ip_mtu_discover, set_ipv6_mtu_discover,
    };
    set_ip_mtu_discover(socket, Ipv4PathMtuDiscovery::DO)?;
    if ipv6 {
        set_ipv6_mtu_discover(socket, Ipv6PathMtuDiscovery::DO)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::net::sockopt::{
        Ipv4PathMtuDiscovery, Ipv6PathMtuDiscovery, ip_mtu_discover, ipv6_mtu_discover,
    };

    #[test]
    fn both_socket_families_require_unfragmented_datagrams() {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let socket = std::net::UdpSocket::bind(bind).unwrap();
            let ipv6 = socket.local_addr().unwrap().is_ipv6();
            configure_wireguard_udp(&socket, ipv6).unwrap();
            assert_eq!(ip_mtu_discover(&socket).unwrap(), Ipv4PathMtuDiscovery::DO);
            if ipv6 {
                assert_eq!(
                    ipv6_mtu_discover(&socket).unwrap(),
                    Ipv6PathMtuDiscovery::DO
                );
            }
        }
    }
}
