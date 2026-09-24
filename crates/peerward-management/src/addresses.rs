use crate::ManagementError;
use ipnet::IpNet;

/// Validates exact TUN assignments and the families available to installed routes.
/// A missing secondary family must never silently send its traffic outside the VPN.
pub fn validate_assignments(
    primary: IpNet,
    secondary: Option<IpNet>,
    routes: &[IpNet],
) -> Result<(), ManagementError> {
    let assigned: Vec<_> = std::iter::once(primary).chain(secondary).collect();
    if secondary.is_some_and(|address| address.addr().is_ipv4() == primary.addr().is_ipv4())
        || assigned.iter().any(|address| {
            address.addr().is_unspecified()
                || address.addr().is_multicast()
                || !routes.iter().any(|route| route.contains(&address.addr()))
        })
        || routes.iter().any(|route| {
            !assigned
                .iter()
                .any(|address| address.addr().is_ipv4() == route.addr().is_ipv4())
        })
    {
        return Err(ManagementError::Invalid(
            "address assignments and route families",
        ));
    }
    Ok(())
}
