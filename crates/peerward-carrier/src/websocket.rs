use super::{BoxStream, RelayIo};
use futures_util::{SinkExt, StreamExt, task::AtomicWaker};
use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};

/// Each direction has a 64 KiB pipe and one bounded WebSocket message. There
/// are no unbounded channels. Closing the owner cancels both directions and
/// closes the underlying protected TCP socket, even under backpressure.
pub(super) fn bridge<S: RelayIo + 'static>(socket: WebSocketStream<S>) -> BoxStream {
    let (application, pump) = tokio::io::duplex(65_536);
    let progress = Arc::new(Progress::default());
    let completion = Arc::clone(&progress);
    let task = tokio::spawn(async move {
        let (mut sink, mut source) = socket.split();
        let (mut reader, mut writer) = tokio::io::split(pump);
        let send = async {
            let mut buffer = [0; 16_384];
            loop {
                let count = reader.read(&mut buffer).await?;
                if count == 0 {
                    sink.close().await.map_err(io::Error::other)?;
                    completion.closed.store(true, Ordering::Release);
                    completion.waker.wake();
                    return Ok::<(), io::Error>(());
                }
                sink.send(Message::binary(buffer[..count].to_vec()))
                    .await
                    .map_err(io::Error::other)?;
                completion
                    .flushed
                    .fetch_add(count as u64, Ordering::Release);
                completion.waker.wake();
            }
        };
        let receive = async {
            while let Some(message) = source.next().await {
                match message.map_err(io::Error::other)? {
                    Message::Binary(bytes) => writer.write_all(&bytes).await?,
                    Message::Ping(_) | Message::Pong(_) => {}
                    Message::Close(_) => break,
                    _ => return Err(super::invalid("Relay WebSocket requires binary messages")),
                }
            }
            Ok::<(), io::Error>(())
        };
        // Either EOF/error closes the entire carrier; no orphan pump survives.
        tokio::select! { _ = send => {}, _ = receive => {} }
        completion.ended.store(true, Ordering::Release);
        completion.waker.wake();
    });
    Box::new(WebSocketIo {
        inner: application,
        task,
        progress,
    })
}

struct WebSocketIo {
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
impl Drop for WebSocketIo {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl AsyncRead for WebSocketIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}
impl AsyncWrite for WebSocketIo {
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

impl super::RelayIo for WebSocketIo {
    fn carrier(&self) -> &'static str {
        "wss"
    }
}
