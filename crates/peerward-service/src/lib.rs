//! Protected local service management and loopback-only transport forwarding.

mod remote;
mod shutdown;

pub use remote::*;
pub use shutdown::shutdown_signal;

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use peerward_platform::{AtomicStateStore, PlatformError};
use peerward_types::ServiceId;
pub use peerward_types::ServiceProtocol;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream, UdpSocket, UnixListener, UnixStream},
    sync::{Mutex, mpsc, oneshot, watch},
};

include!("service_state.rs");
include!("management_socket.rs");
include!("management.rs");
include!("observability.rs");
include!("client_management.rs");
include!("observability_p2p.rs");
include!("forwarding.rs");
#[cfg(test)]
#[path = "client_management_tests.rs"]
mod client_management_tests;
#[cfg(test)]
mod forwarding_tests;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
