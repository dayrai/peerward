//! Bounded in-process record pipe. No local codec bytes are sent on the network.
use super::{
    BoxStream,
    quic::{QuicLink, Received},
    records::{decode_local, encode_local},
};
use futures_util::task::AtomicWaker;
use peerward_wire::{ControlEnvelope, Record, control_envelope::Message as Kind};
use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

struct Written {
    end: u64,
    receipt: Option<u64>,
    deadline: Instant,
}
pub(super) fn bridge(mut link: QuicLink) -> BoxStream {
    let (application, pump) = tokio::io::duplex(65_536);
    let progress = Arc::new(Progress::default());
    let completion = progress.clone();
    let task = tokio::spawn(async move {
        let result = run(&mut link, pump, &completion).await;
        tracing::debug!(?result, "QUIC record bridge ended");
        completion.ended.store(true, Ordering::Release);
        completion.waker.wake();
    });
    Box::new(QuicIo {
        inner: application,
        task,
        progress,
    })
}
async fn run(link: &mut QuicLink, pump: DuplexStream, progress: &Progress) -> io::Result<()> {
    let (mut input, mut output) = tokio::io::split(pump);
    let mut frame = vec![0; 4];
    let mut read = 0;
    let mut written = 0_u64;
    let mut waiting: VecDeque<Written> = VecDeque::new();
    // One data frame plus one reliable control frame at most (2 * 65,539
    // bytes). Stop reading DATAGRAMs under backpressure, but continue processing
    // authenticated pings, pongs and receipts on the reliable stream.
    let mut pending: VecDeque<(Vec<u8>, usize, Option<u64>)> = VecDeque::new();
    let mut sweep = tokio::time::interval(Duration::from_millis(100));
    let mut activity = Instant::now();
    let mut last_probe = Instant::now();
    let mut probe: Option<(u64, Instant)> = None;
    let mut next_probe = 0_u64;
    let mut missed = 0;
    let mut last_ping = 0;
    let mut ping_window = (Instant::now(), 0_u8);
    loop {
        while waiting.front().is_some_and(|entry| entry.receipt.is_none()) {
            let done = waiting.pop_front().expect("ready entry");
            progress.flushed.store(done.end, Ordering::Release);
            progress.waker.wake();
        }
        if waiting
            .front()
            .is_some_and(|entry| entry.deadline <= Instant::now())
        {
            return Err(io::ErrorKind::TimedOut.into());
        }
        tokio::select! {
            count = input.read(&mut frame[read..]), if waiting.len() < 32 => {
                let count = count?;
                if count == 0 {
                    if read != 0 || !waiting.is_empty() { return Err(io::ErrorKind::UnexpectedEof.into()); }
                    progress.closed.store(true, Ordering::Release); progress.waker.wake(); return Ok(());
                }
                read += count;
                if read != frame.len() { continue; }
                if frame.len() == 4 {
                    let length = u32::from_be_bytes(frame[..4].try_into().expect("prefix")) as usize;
                    if length == 0 || length > 65_535 { return Err(super::invalid("local record bound")); }
                    frame.resize(length + 4, 0); continue;
                }
                let Record::Control(control) = decode_local(&frame).map_err(io::Error::other)? else { return Err(super::invalid("raw IP on Relay")); };
                let receipt = if super::quic_data::opaque(&control)?.is_some() {
                    activity = Instant::now();
                    link.send_datagram_control(&control)?; None
                } else {
                    link.send_control(control).await?; Some(link.sent_control())
                };
                written += u64::try_from(frame.len()).map_err(io::Error::other)?;
                waiting.push_back(Written { end: written, receipt, deadline: Instant::now() + Duration::from_secs(5) });
                frame.resize(4, 0); read = 0;
            }
            record = link.receive_with_data(pending.is_empty()), if pending.len() < 2 => {
                let (control, receipt) = match record? {
                    Received::Ping(sequence) => {
                        if ping_window.0.elapsed() >= Duration::from_secs(1) { ping_window = (Instant::now(), 0); }
                        ping_window.1 += 1;
                        if ping_window.1 > 4 || sequence <= last_ping { return Err(super::invalid("QUIC heartbeat rate or sequence")); }
                        last_ping = sequence;
                        link.heartbeat(sequence, true).await?;
                        continue;
                    }
                    Received::Pong(sequence) => {
                        if probe.is_some_and(|(expected, _)| expected == sequence) { probe = None; missed = 0; }
                        continue;
                    }
                    Received::Acknowledged(sequence) => {
                        for entry in &mut waiting { if entry.receipt.is_some_and(|id| id <= sequence) { entry.receipt = None; } }
                        continue;
                    }
                    Received::Control(control) => (control, Some(link.received_control())),
                    Received::Datagram(control) => { activity = Instant::now(); (control, None) },
                    Received::Opaque(frame) => { activity = Instant::now(); (ControlEnvelope { trace_context: None, message: Some(Kind::Opaque(frame)) }, None) },
                };
                pending.push_back((encode_local(&Record::Control(control)).map_err(io::Error::other)?, 0, receipt));
            }
            size = async { let (bytes, offset, _) = pending.front().expect("guarded pending"); output.write(&bytes[*offset..]).await }, if !pending.is_empty() => {
                let size = size?; if size == 0 { return Err(io::ErrorKind::WriteZero.into()); }
                let (bytes, offset, _) = pending.front_mut().expect("pending write"); *offset += size;
                if *offset == bytes.len() {
                    let (_, _, receipt) = pending.pop_front().expect("completed write");
                    if let Some(sequence) = receipt { link.acknowledge(sequence).await?; }
                }
            }
            _ = sweep.tick() => {
                let active = activity.elapsed() < Duration::from_secs(3);
                if probe.is_some_and(|(_, sent)| sent.elapsed() >= Duration::from_millis(750)) {
                    probe = None; missed += 1;
                    if missed >= 2 { return Err(io::ErrorKind::TimedOut.into()); }
                }
                let interval = if active || missed > 0 { Duration::from_millis(500) } else { Duration::from_secs(25) };
                if probe.is_none() && last_probe.elapsed() >= interval {
                    next_probe = next_probe.checked_add(1).ok_or_else(|| super::invalid("QUIC probe sequence exhausted"))?;
                    link.heartbeat(next_probe, false).await?;
                    last_probe = Instant::now(); probe = Some((next_probe, last_probe));
                }
            }
        }
    }
}

struct QuicIo {
    inner: DuplexStream,
    task: tokio::task::JoinHandle<()>,
    progress: Arc<Progress>,
}

#[derive(Default)]
struct Progress {
    written: AtomicU64,
    flushed: AtomicU64,
    ended: AtomicBool,
    closed: AtomicBool,
    waker: AtomicWaker,
}
impl Drop for QuicIo {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl AsyncRead for QuicIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}
impl AsyncWrite for QuicIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let count = std::task::ready!(Pin::new(&mut self.inner).poll_write(cx, bytes))?;
        self.progress
            .written
            .fetch_add(count as u64, Ordering::Release);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.progress.waker.register(cx.waker());
        if self.progress.flushed.load(Ordering::Acquire)
            >= self.progress.written.load(Ordering::Acquire)
        {
            Poll::Ready(Ok(()))
        } else if self.progress.ended.load(Ordering::Acquire) {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        } else {
            Poll::Pending
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        std::task::ready!(Pin::new(&mut self.inner).poll_shutdown(cx))?;
        self.progress.waker.register(cx.waker());
        if self.progress.closed.load(Ordering::Acquire) {
            Poll::Ready(Ok(()))
        } else if self.progress.ended.load(Ordering::Acquire) {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        } else {
            Poll::Pending
        }
    }
}

impl super::RelayIo for QuicIo {
    fn is_quic(&self) -> bool {
        true
    }
}
