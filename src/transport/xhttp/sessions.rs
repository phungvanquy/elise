use bytes::{Buf, Bytes};
use futures_util::task::AtomicWaker;
use http::StatusCode;
use hyper::body::{Body, Incoming};
use parking_lot::Mutex;
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::watch;

#[derive(Debug, Default)]
pub struct Sessions {
    entries: Mutex<HashMap<String, Arc<Session>>>,
}

#[derive(Debug)]
pub(super) struct Session {
    state: Mutex<State>,
    readable: AtomicWaker,
    pub closed: watch::Sender<bool>,
}

#[derive(Debug, Default)]
struct State {
    packets: BTreeMap<u64, Bytes>,
    next: u64,
    download: bool,
    streaming_upload: Option<bool>,
    incoming: Option<Incoming>,
    closed: bool,
}

impl Sessions {
    pub(super) fn get(self: &Arc<Self>, id: &str) -> Result<Arc<Session>, StatusCode> {
        let mut entries = self.entries.lock();
        if let Some(session) = entries.get(id) {
            return Ok(session.clone());
        }
        if entries.len() >= 4096 {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        let session = Arc::new(Session {
            state: Mutex::new(State::default()),
            readable: AtomicWaker::new(),
            closed: watch::channel(false).0,
        });
        entries.insert(id.to_owned(), session.clone());
        let registry = Arc::downgrade(self);
        let weak_session = Arc::downgrade(&session);
        let id = id.to_owned();
        // Uploads can precede their download request, but must not retain an orphan indefinitely.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            if let (Some(registry), Some(session)) = (registry.upgrade(), weak_session.upgrade()) {
                let mut entries = registry.entries.lock();
                let mut state = session.state.lock();
                if !state.download && entries.get(&id).is_some_and(|s| Arc::ptr_eq(s, &session)) {
                    entries.remove(&id);
                    state.closed = true;
                    session.closed.send_replace(true);
                    session.readable.wake();
                }
            }
        });
        Ok(session)
    }

    pub(super) fn guard(self: &Arc<Self>, id: String, session: Arc<Session>) -> SessionGuard {
        SessionGuard {
            registry: Arc::downgrade(self),
            id,
            session,
        }
    }
}

pub(super) struct SessionGuard {
    registry: Weak<Sessions>,
    id: String,
    session: Arc<Session>,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            let mut entries = registry.entries.lock();
            if entries
                .get(&self.id)
                .is_some_and(|s| Arc::ptr_eq(s, &self.session))
            {
                entries.remove(&self.id);
            }
        }
        self.session.close();
    }
}

impl Session {
    pub fn push(&self, seq: u64, data: Bytes, max_buffered: usize) -> Result<(), StatusCode> {
        let mut state = self.state.lock();
        if state.closed
            || state.streaming_upload == Some(true)
            || seq < state.next
            || seq == u64::MAX
            || state.packets.contains_key(&seq)
        {
            return Err(StatusCode::CONFLICT);
        }
        if state.packets.len() >= max_buffered {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        state.streaming_upload = Some(false);
        state.packets.insert(seq, data);
        drop(state);
        self.readable.wake();
        Ok(())
    }

    pub fn attach_upload(&self, body: Incoming) -> Result<(), StatusCode> {
        let mut state = self.state.lock();
        if state.closed || state.streaming_upload.is_some() {
            return Err(StatusCode::CONFLICT);
        }
        state.streaming_upload = Some(true);
        state.incoming = Some(body);
        drop(state);
        self.readable.wake();
        Ok(())
    }

    pub fn reader(self: &Arc<Self>) -> Result<SessionReader, StatusCode> {
        let mut state = self.state.lock();
        if state.closed || state.download {
            return Err(StatusCode::CONFLICT);
        }
        state.download = true;
        Ok(SessionReader {
            session: self.clone(),
            current: Bytes::new(),
        })
    }

    pub fn close(&self) {
        let mut state = self.state.lock();
        state.closed = true;
        state.packets.clear();
        state.incoming = None;
        drop(state);
        self.closed.send_replace(true);
        self.readable.wake();
    }
}

pub(super) struct SessionReader {
    session: Arc<Session>,
    current: Bytes,
}

impl AsyncRead for SessionReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.current.is_empty() {
                let len = self.current.len().min(output.remaining());
                output.put_slice(&self.current[..len]);
                self.current.advance(len);
                return Poll::Ready(Ok(()));
            }
            self.session.readable.register(cx.waker());
            let mut state = self.session.state.lock();
            if state.closed {
                return Poll::Ready(Ok(()));
            }
            if let Some(body) = state.incoming.as_mut() {
                match Pin::new(body).poll_frame(cx) {
                    Poll::Ready(Some(Ok(frame))) => {
                        drop(state);
                        if let Ok(data) = frame.into_data() {
                            self.current = data;
                        }
                    }
                    Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(io::Error::other(e))),
                    Poll::Ready(None) => return Poll::Ready(Ok(())),
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                let next = state.next;
                match state.packets.remove(&next) {
                    Some(data) => {
                        state.next += 1;
                        drop(state);
                        self.current = data;
                    }
                    None => return Poll::Pending,
                }
            }
        }
    }
}
