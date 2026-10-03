mod options;
mod sessions;

pub use sessions::Sessions;

use crate::conn::{AutoFlushingStream, BoxedStream, PrefixedStream};
use crate::transport::types::XHttpTransportConfig;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bytes::Bytes;
use futures_util::TryStreamExt;
use http::{Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use options::{cookie, header, DataPlacement, Options};
use parking_lot::Mutex;
use rand::Rng;
use sessions::{Session, SessionGuard};
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;
use tokio_util::io::StreamReader;

pub(crate) fn validate_config(config: &XHttpTransportConfig) -> Result<(), String> {
    Options::parse(config).map(|_| ())
}

pub async fn serve_xhttp<F, Fut>(
    mut stream: BoxedStream,
    config: &XHttpTransportConfig,
    handler: F,
) -> io::Result<()>
where
    F: FnMut(BoxedStream) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let options = Arc::new(
        Options::parse(config).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
    );
    let max_headers = options.max_headers;
    let sessions = config.sessions.clone();
    let handler = Arc::new(Mutex::new(handler));
    let service = service_fn(move |req| {
        let (options, sessions, handler) = (options.clone(), sessions.clone(), handler.clone());
        async move {
            Ok::<_, Infallible>(match handle(req, &options, &sessions, handler).await {
                Ok(response) => response,
                Err(status) => response(&options, status, ChannelBody::empty(), false),
            })
        }
    });
    let mut prefix = [0; 4];
    tokio::time::timeout(Duration::from_secs(15), stream.read_exact(&mut prefix)).await??;
    let stream = PrefixedStream::new(stream, Some(prefix.to_vec()));
    let io = TokioIo::new(AutoFlushingStream::new(stream));
    let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(15))
        .max_buf_size(max_headers.max(8192));
    builder
        .http2()
        .max_header_list_size(max_headers as u32)
        .max_concurrent_streams(128);
    builder
        .serve_connection(io, service)
        .await
        .map_err(io::Error::other)
}

async fn handle<F, Fut>(
    mut req: Request<Incoming>,
    options: &Options,
    sessions: &Arc<Sessions>,
    handler: Arc<Mutex<F>>,
) -> Result<Response<ChannelBody>, StatusCode>
where
    F: FnMut(BoxedStream) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    options.validate(&req)?;
    if req.method() == Method::OPTIONS {
        let mut response = response(options, StatusCode::OK, ChannelBody::empty(), false);
        for (target, source) in [
            ("access-control-allow-origin", "origin"),
            (
                "access-control-allow-methods",
                "access-control-request-method",
            ),
            (
                "access-control-allow-headers",
                "access-control-request-headers",
            ),
        ] {
            response.headers_mut().insert(
                target,
                req.headers()
                    .get(source)
                    .cloned()
                    .unwrap_or(http::HeaderValue::from_static("*")),
            );
        }
        return Ok(response);
    }
    let (session_id, seq) = options.metadata(&req);
    if session_id.len() > 256 {
        return Err(StatusCode::BAD_REQUEST);
    }
    if session_id.is_empty() {
        if !matches!(options.mode.as_str(), "auto" | "stream-one" | "stream-up") {
            return Err(StatusCode::BAD_REQUEST);
        }
        let reader =
            StreamReader::new(req.into_body().into_data_stream().map_err(io::Error::other));
        let body = stream_body(reader, handler, None);
        return Ok(response(options, StatusCode::OK, body, true));
    }
    if req.method() == Method::GET && seq.is_empty() {
        if options.mode == "stream-one" {
            return Err(StatusCode::BAD_REQUEST);
        }
        let session = sessions.get(&session_id)?;
        let reader = session.reader()?;
        let guard = sessions.guard(session_id, session);
        let body = stream_body(reader, handler, Some(guard));
        return Ok(response(options, StatusCode::OK, body, true));
    }
    if seq.is_empty() {
        if !matches!(options.mode.as_str(), "auto" | "stream-up") {
            return Err(StatusCode::BAD_REQUEST);
        }
        let session = sessions.get(&session_id)?;
        session.attach_upload(req.into_body())?;
        let guard = sessions.guard(session_id, session.clone());
        return Ok(response(
            options,
            StatusCode::OK,
            upload_body(options, session, guard),
            false,
        ));
    }
    if !matches!(options.mode.as_str(), "auto" | "packet-up") {
        return Err(StatusCode::BAD_REQUEST);
    }
    let seq = seq.parse::<u64>().map_err(|_| StatusCode::BAD_REQUEST)?;
    let data = tokio::time::timeout(Duration::from_secs(30), payload(&mut req, options))
        .await
        .map_err(|_| StatusCode::REQUEST_TIMEOUT)??;
    let session = sessions.get(&session_id)?;
    session.push(seq, data, options.max_buffered)?;
    Ok(response(
        options,
        StatusCode::OK,
        ChannelBody::empty(),
        false,
    ))
}

async fn payload(req: &mut Request<Incoming>, options: &Options) -> Result<Bytes, StatusCode> {
    let mut data = Vec::new();
    for placement in [DataPlacement::Header, DataPlacement::Cookie] {
        if options.data_placement != DataPlacement::Auto && options.data_placement != placement {
            continue;
        }
        let mut encoded = String::new();
        for index in 0.. {
            let chunk = match placement {
                DataPlacement::Header => {
                    header(req.headers(), &format!("{}-{index}", options.data_key))
                        .map(str::to_owned)
                }
                _ => cookie(req.headers(), &format!("{}_{index}", options.data_key)),
            };
            let Some(chunk) = chunk.filter(|s| !s.is_empty()) else {
                break;
            };
            encoded.push_str(&chunk);
            if encoded.len() > options.max_post.div_ceil(3) * 4 {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
        }
        data.extend(
            URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| StatusCode::BAD_REQUEST)?,
        );
        if data.len() > options.max_post {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
    }
    if matches!(
        options.data_placement,
        DataPlacement::Auto | DataPlacement::Body
    ) {
        while let Some(frame) = req.body_mut().frame().await {
            let frame = frame.map_err(|_| StatusCode::BAD_REQUEST)?;
            if let Ok(chunk) = frame.into_data() {
                if chunk.len() > options.max_post - data.len() {
                    return Err(StatusCode::PAYLOAD_TOO_LARGE);
                }
                data.extend_from_slice(&chunk);
            }
        }
    }
    Ok(Bytes::from(data))
}

fn response(
    options: &Options,
    status: StatusCode,
    body: ChannelBody,
    streaming: bool,
) -> Response<ChannelBody> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = options.response_headers(streaming);
    response
}

struct ChannelBody {
    receiver: mpsc::Receiver<Result<Frame<Bytes>, io::Error>>,
    task: Option<AbortHandle>,
}

impl ChannelBody {
    fn empty() -> Self {
        let (_, receiver) = mpsc::channel(1);
        Self {
            receiver,
            task: None,
        }
    }
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        self.receiver.poll_recv(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.receiver.is_closed() && self.receiver.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        if self.task.is_none() {
            SizeHint::with_exact(0)
        } else {
            SizeHint::default()
        }
    }
}

impl Drop for ChannelBody {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

fn stream_body<R, F, Fut>(
    reader: R,
    handler: Arc<Mutex<F>>,
    guard: Option<SessionGuard>,
) -> ChannelBody
where
    R: AsyncRead + Unpin + Send + 'static,
    F: FnMut(BoxedStream) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (writer, mut downstream) = tokio::io::duplex(64 * 1024);
    let stream = Box::new(tokio::io::join(reader, writer));
    let handle = handler.lock()(stream);
    let (sender, receiver) = mpsc::channel(4);
    let task = tokio::spawn(async move {
        let _guard = guard;
        let pump = async move {
            let mut buffer = vec![0; 16 * 1024];
            loop {
                match downstream.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if sender
                            .send(Ok(Frame::data(Bytes::copy_from_slice(&buffer[..n]))))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = sender.send(Err(e)).await;
                        break;
                    }
                }
            }
        };
        tokio::join!(handle, pump);
    });
    ChannelBody {
        receiver,
        task: Some(task.abort_handle()),
    }
}

fn upload_body(options: &Options, session: Arc<Session>, guard: SessionGuard) -> ChannelBody {
    let mut closed = session.closed.subscribe();
    let padding = options.padding.clone();
    let interval = options.stream_up_secs.clone();
    let (sender, receiver) = mpsc::channel(1);
    let task = tokio::spawn(async move {
        let _guard = guard;
        loop {
            if *closed.borrow() {
                break;
            }
            let data = Bytes::from("X".repeat(rand::thread_rng().gen_range(padding.clone())));
            if sender.send(Ok(Frame::data(data))).await.is_err() {
                break;
            }
            let delay = Duration::from_secs(rand::thread_rng().gen_range(interval.clone()) as u64);
            tokio::select! {
                _ = closed.changed() => break,
                _ = tokio::time::sleep(delay) => {},
            }
        }
    });
    ChannelBody {
        receiver,
        task: Some(task.abort_handle()),
    }
}

#[cfg(test)]
mod tests;
