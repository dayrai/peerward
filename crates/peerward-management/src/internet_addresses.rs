use std::net::{IpAddr, Ipv4Addr};

/// Internet grants cover public destinations, never local or infrastructure ranges.
/// Reviewed against the IANA special-purpose registries on 2026-09-14. This is an
/// authorization boundary, not a claim that an address is reachable from a gateway.
pub fn internet_destination(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => public_v4(address),
        IpAddr::V6(address) => {
            let segments = address.segments();
            let prefix = segments[0];
            let subnet = segments[1];
            // The well-known NAT64 prefix must not smuggle private IPv4 targets.
            if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                let bytes = address.octets();
                return public_v4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]));
            }
            if prefix & 0xe000 != 0x2000
                || prefix == 0x2002
                || (prefix == 0x2001 && subnet == 0xdb8)
                || (prefix == 0x3fff && subnet < 0x1000)
            {
                return false;
            }
            if prefix == 0x2001 && subnet < 0x200 {
                return (subnet == 1
                    && segments[2..7] == [0; 5]
                    && [1, 2, 3].contains(&segments[7]))
                    || subnet == 3
                    || (subnet == 4 && segments[2] == 0x112)
                    || (0x20..=0x3f).contains(&subnet);
            }
            true
        }
    }
}

fn public_v4(address: Ipv4Addr) -> bool {
    let [a, b, c, d] = address.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && c == 0 && ![9, 10].contains(&d))
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && [18, 19].contains(&b))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn internet_does_not_authorize_gateway_lan_or_metadata_even_through_nat64() {
        for ip in [
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "100.100.100.200",
            "169.254.169.254",
            "127.0.0.1",
            "0.0.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "192.0.2.1",
            "198.18.0.1",
            "fd00:ec2::254",
            "fe80::1",
            "::1",
            "::ffff:8.8.8.8",
            "2001:db8::1",
            "3fff::1",
            "64:ff9b::a9fe:a9fe",
        ] {
            assert!(!internet_destination(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "192.0.0.9",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "64:ff9b::808:808",
        ] {
            assert!(internet_destination(ip.parse().unwrap()), "{ip}");
        }
    }
}
