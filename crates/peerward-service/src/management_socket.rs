/// Removes the bound management socket on both normal shutdown and startup failure.
#[cfg(unix)]
struct BoundUnixSocket(Option<PathBuf>);

#[cfg(unix)]
impl BoundUnixSocket {
    fn remove(mut self) -> std::io::Result<()> {
        let result = std::fs::remove_file(self.0.as_ref().expect("bound socket path"));
        if result.is_ok() {
            self.0 = None;
        }
        result
    }
}

#[cfg(unix)]
impl Drop for BoundUnixSocket {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}
