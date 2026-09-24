//! Bounded authoritative split-DNS service with guarded upstream forwarding.

include!("dns_protocol.rs");
include!("dns_runtime.rs");
include!("dns_names.rs");
include!("dns_bootstrap.rs");
#[cfg(test)]
#[path = "dns_bootstrap_tests.rs"]
mod bootstrap_tests;
#[cfg(test)]
#[path = "dns_tests.rs"]
mod tests;
