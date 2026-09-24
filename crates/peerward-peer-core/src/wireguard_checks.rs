use super::*;

impl Connectivity {
    /// The caller only sends checks when it can encrypt immediately; delayed probes are discarded.
    pub fn poll_with_mtu(
        &mut self,
        now: Instant,
        mtu: usize,
        address: impl Fn(&Key) -> Option<std::net::IpAddr>,
    ) -> Vec<Send> {
        for track in self.peers.values_mut() {
            track.pending.retain(|_, check| {
                let alive = now.saturating_duration_since(check.sent) < Duration::from_secs(1);
                if !alive && check.ciphertext_limit.is_none() {
                    track.quality.entry(check.route).or_default().failure();
                }
                if !alive
                    && check.ciphertext_limit.is_some()
                    && let Some(verified) =
                        track.verified.as_mut().filter(|v| v.route == check.route)
                {
                    verified
                        .mtu
                        .failed(now, check.ciphertext_limit.expect("MTU check"));
                }
                alive
            });
        }
        let mut available =
            MESH_CHECKS.saturating_sub(self.peers.values().map(|track| track.pending.len()).sum());
        let keys: Vec<_> = self.peers.keys().copied().collect();
        let mut output = Vec::new();
        for offset in 0..keys.len() {
            let key = keys[(self.cursor + offset) % keys.len()];
            let track = self.peers.get_mut(&key).expect("snapshot key");
            if !track.candidate_ack
                && track.candidate_sent.is_none_or(|sent| {
                    now.saturating_duration_since(sent) >= Duration::from_secs(2)
                })
            {
                track.candidate_sent = Some(now);
                output.push(Send {
                    local: track.local,
                    remote: key,
                    endpoint: None,
                    source: None,
                    coordination: Coordination {
                        generation: self.generation,
                        transaction: track.candidate_tx,
                        message: Message::Candidates(self.candidates.clone()),
                    },
                });
            }
            let idle = now.saturating_duration_since(track.last_activity) > Duration::from_secs(30);
            let interval = if idle {
                Duration::from_secs(25)
            } else {
                Duration::from_secs(1)
            };
            if track
                .last_check
                .is_some_and(|last| now.saturating_duration_since(last) < interval)
            {
                continue;
            }
            if available == 0 || track.pending.len() >= 4 {
                continue;
            }
            track.last_check = Some(now);
            let mut targets: Vec<_> = if let Some(verified) =
                track.verified.as_ref().filter(|verified| {
                    now.saturating_duration_since(verified.confirmed) < health_lifetime(track, now)
                }) {
                let mut targets = vec![(verified.route, Message::Probe, None)];
                if !idle
                    && track.last_alternative.is_none_or(|last| {
                        now.saturating_duration_since(last) >= Duration::from_secs(5)
                    })
                {
                    for _ in 0..track.pairs.len() {
                        let route = track.pairs[track.next % track.pairs.len()];
                        track.next = track.next.wrapping_add(1);
                        if route != verified.route
                            && !track.pending.values().any(|check| check.route == route)
                        {
                            targets.push((route, Message::Probe, None));
                            track.last_alternative = Some(now);
                            break;
                        }
                    }
                }
                targets
            } else {
                let mut targets = Vec::new();
                for _ in 0..track
                    .pairs
                    .len()
                    .min(4 - track.pending.len())
                    .min(available)
                {
                    let route = track.pairs[track.next % track.pairs.len()];
                    track.next = track.next.wrapping_add(1);
                    if !track.pending.values().any(|check| check.route == route) {
                        targets.push((route, Message::Probe, None));
                    }
                }
                targets
            };
            if let Some(verified) = track.verified.as_mut()
                && now.saturating_duration_since(verified.confirmed)
                    < interval + Duration::from_secs(2)
                && let Some(address) = address(&track.local)
                && let Some((message, limit)) =
                    verified.mtu.next(mtu, address.is_ipv6(), now, interval)
            {
                targets.push((verified.route, message, Some(limit)));
            }
            for (route, message, ciphertext_limit) in targets {
                if available == 0 || track.pending.len() >= 4 {
                    break;
                }
                let Some(permit) = Permit::acquire() else {
                    break;
                };
                if ciphertext_limit.is_some()
                    && let Some(verified) = track.verified.as_mut()
                {
                    verified.mtu.sent(now);
                }
                let transaction = transaction();
                track.pending.insert(
                    transaction,
                    Check {
                        route,
                        sent: now,
                        ciphertext_limit,
                        _permit: permit,
                    },
                );
                available -= 1;
                output.push(Send {
                    local: track.local,
                    remote: key,
                    endpoint: Some(route.endpoint),
                    source: route.source,
                    coordination: Coordination {
                        generation: self.generation,
                        transaction,
                        message,
                    },
                });
            }
        }
        self.cursor = self.cursor.wrapping_add(1);
        output
    }
    #[cfg(test)]
    pub fn poll(&mut self, now: Instant) -> Vec<Send> {
        self.poll_with_mtu(now, 1280, |_| Some(std::net::Ipv4Addr::LOCALHOST.into()))
    }
}
