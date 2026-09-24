/// Linux non-persistent TUN reader owned by the packet runtime.
#[cfg(target_os = "linux")]
pub type LinuxTunnelReader = tokio::io::ReadHalf<tokio_tun::Tun>;

/// Linux non-persistent TUN writer owned by the packet runtime.
#[cfg(target_os = "linux")]
pub type LinuxTunnelWriter = tokio::io::WriteHalf<tokio_tun::Tun>;

/// Linux implementation of the platform-neutral packet-device contract.
#[cfg(target_os = "linux")]
pub struct LinuxTunnelDevice {
    device: tokio_tun::Tun,
    mtu: u16,
}

#[cfg(target_os = "linux")]
impl LinuxTunnelDevice {
    /// Creates one non-persistent TUN. Closing both returned halves destroys its lifetime.
    pub fn create(interface: &str, mtu: u16) -> Result<Self, PlatformError> {
        if !safe_name(interface) || !(576..=9_000).contains(&mtu) {
            return Err(PlatformError::InvalidName);
        }
        let mut devices = tokio_tun::TunBuilder::new()
            .name(interface)
            .build()
            .map_err(|error| PlatformError::Io(std::io::Error::other(error)))?;
        if devices.len() != 1 {
            return Err(PlatformError::Io(std::io::Error::other(
                "TUN builder returned an unexpected queue count",
            )));
        }
        Ok(Self {
            device: devices.pop().expect("exactly one checked TUN queue"),
            mtu,
        })
    }
}

#[cfg(target_os = "linux")]
impl TunnelDevice for LinuxTunnelDevice {
    type Reader = LinuxTunnelReader;
    type Writer = LinuxTunnelWriter;

    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn split(self) -> (Self::Reader, Self::Writer) {
        tokio::io::split(self.device)
    }
}
