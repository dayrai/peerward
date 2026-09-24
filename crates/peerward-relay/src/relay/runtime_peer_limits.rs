struct IpHandshakeLimiter {
    limit: usize,
    counts: StdMutex<BTreeMap<IpAddr, usize>>,
}

impl IpHandshakeLimiter {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            counts: StdMutex::new(BTreeMap::new()),
        }
    }

    fn try_acquire(self: &Arc<Self>, address: IpAddr) -> Option<IpHandshakePermit> {
        let mut counts = self.counts.lock().ok()?;
        let count = counts.entry(address).or_default();
        if *count >= self.limit {
            return None;
        }
        *count += 1;
        Some(IpHandshakePermit {
            limiter: Arc::clone(self),
            address,
        })
    }
}

struct IpHandshakePermit {
    limiter: Arc<IpHandshakeLimiter>,
    address: IpAddr,
}

impl Drop for IpHandshakePermit {
    fn drop(&mut self) {
        if let Ok(mut counts) = self.limiter.counts.lock()
            && let Some(count) = counts.get_mut(&self.address)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.address);
            }
        }
    }
}
