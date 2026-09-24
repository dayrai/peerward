/// Mesh settings used to generate a signed initialization bundle.
#[derive(Debug, Args)]
pub struct BootstrapMeshOptions {
    /// Stable Mesh UUID; generated when omitted.
    #[arg(long)]
    mesh_id: Option<MeshId>,
    /// Human-readable Mesh name.
    #[arg(long, default_value = "Peerward Development")]
    name: String,
    /// Mesh address range.
    #[arg(long, default_value = "100.96.0.0/16")]
    address_cidr: ipnet::IpNet,
    /// Reserved Mesh gateway within the address range.
    #[arg(long, default_value = "100.96.0.1")]
    gateway: std::net::IpAddr,
    /// Lower-case split-DNS suffix.
    #[arg(long, default_value = "peerward.internal")]
    dns_suffix: String,
    /// Mesh packet MTU.
    #[arg(long, default_value_t = 1280, value_parser = clap::value_parser!(u16).range(1280..=9000))]
    mtu: u16,
    /// Initial policy decision for unmatched traffic.
    #[arg(long, default_value = "deny", value_parser = ["allow", "deny"])]
    default_policy: String,
    /// Released-address quarantine duration.
    #[arg(long, default_value_t = 3600, value_parser = clap::value_parser!(u64).range(0..=i64::MAX as u64))]
    quarantine_seconds: u64,
    /// Maximum credential rotation overlap duration.
    #[arg(long, default_value_t = 86400, value_parser = clap::value_parser!(u64).range(0..=604800))]
    rotation_overlap_seconds: u64,
    /// Explicit reserved address; may be repeated.
    #[arg(long)]
    reserved: Vec<std::net::IpAddr>,
}

impl BootstrapMeshOptions {
    fn resolve(self) -> Result<(MeshId, NewMesh), CliError> {
        if self.name.trim().is_empty()
            || self.name.len() > 128
            || !self.address_cidr.contains(&self.gateway)
            || self.address_cidr.addr() != self.address_cidr.network()
            || self.reserved.len() > 4096
            || self
                .reserved
                .iter()
                .any(|address| !self.address_cidr.contains(address))
            || !peerward_store::normalize_dns_suffix(&self.dns_suffix)
                .is_ok_and(|suffix| suffix == self.dns_suffix)
        {
            return Err(CliError::invalid("invalid bootstrap Mesh configuration"));
        }
        Ok((
            self.mesh_id.unwrap_or_default(),
            NewMesh {
                name: self.name,
                address_cidr: self.address_cidr,
                gateway: self.gateway,
                dns_suffix: self.dns_suffix,
                mtu: self.mtu,
                reserved: self.reserved,
                default_policy: if self.default_policy == "allow" {
                    DefaultPolicy::Allow
                } else {
                    DefaultPolicy::Deny
                },
                quarantine_seconds: self.quarantine_seconds,
                rotation_overlap_seconds: self.rotation_overlap_seconds,
            },
        ))
    }
}

#[cfg(test)]
impl Default for BootstrapMeshOptions {
    fn default() -> Self {
        let cli = Cli::try_parse_from([
            "peerward",
            "bootstrap",
            "generate",
            "--output-dir",
            "unused",
        ])
        .unwrap();
        match cli.command {
            Command::Bootstrap(BootstrapGroup {
                command: BootstrapCommand::Generate { mesh, .. },
            }) => mesh,
            _ => unreachable!(),
        }
    }
}
