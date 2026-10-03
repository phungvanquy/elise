use crate::transport::types::XHttpTransportConfig;
use http::{header::HeaderName, HeaderMap, HeaderValue, Method, Request, StatusCode};
use rand::Rng;
use serde_json::{Map, Value};
use std::ops::RangeInclusive;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Placement {
    Path,
    Header,
    Cookie,
    Query,
    QueryInHeader,
}

impl Placement {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "path" => Ok(Self::Path),
            "header" => Ok(Self::Header),
            "cookie" => Ok(Self::Cookie),
            "query" => Ok(Self::Query),
            "queryInHeader" => Ok(Self::QueryInHeader),
            _ => Err(format!("unsupported XHTTP placement: {value}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DataPlacement {
    Auto,
    Body,
    Header,
    Cookie,
}

#[derive(Debug, Clone)]
pub(super) struct Options {
    pub mode: String,
    pub path: String,
    pub host: Option<String>,
    pub headers: HeaderMap,
    pub padding: RangeInclusive<usize>,
    pub obfs: bool,
    pub padding_placement: Placement,
    pub padding_header: HeaderName,
    pub padding_key: String,
    pub data_placement: DataPlacement,
    pub data_key: String,
    pub max_post: usize,
    pub max_buffered: usize,
    pub max_headers: usize,
    pub stream_up_secs: RangeInclusive<usize>,
    pub no_sse: bool,
    pub session_placement: Placement,
    pub session_key: String,
    pub seq_placement: Placement,
    pub seq_key: String,
}

fn string<'a>(
    extra: &'a Map<String, Value>,
    key: &str,
    default: &'a str,
) -> Result<&'a str, String> {
    match extra.get(key) {
        None => Ok(default),
        Some(Value::String(s)) if s.is_empty() => Ok(default),
        Some(Value::String(s)) => Ok(s),
        _ => Err(format!("XHTTP {key} must be a string")),
    }
}

fn boolean(extra: &Map<String, Value>, key: &str) -> Result<bool, String> {
    match extra.get(key) {
        None => Ok(false),
        Some(Value::Bool(v)) => Ok(*v),
        _ => Err(format!("XHTTP {key} must be a boolean")),
    }
}

fn range(
    extra: &Map<String, Value>,
    key: &str,
    default: &str,
) -> Result<RangeInclusive<usize>, String> {
    let raw = match extra.get(key) {
        None => default.to_owned(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => return Err(format!("XHTTP {key} must be an integer or integer range")),
    };
    let (a, b) = raw.split_once('-').unwrap_or((&raw, &raw));
    let parse = |s: &str| {
        s.parse::<usize>()
            .ok()
            .filter(|v| *v > 0 && *v <= i32::MAX as usize)
            .ok_or_else(|| format!("XHTTP {key} must contain positive 32-bit integers"))
    };
    let (a, b) = (parse(a)?, parse(b)?);
    Ok(a.min(b)..=a.max(b))
}

fn meta(
    extra: &Map<String, Value>,
    prefix: &str,
    legacy: &str,
) -> Result<(Placement, String), String> {
    let placement_key = format!("{prefix}Placement");
    let legacy_placement_key = format!("{legacy}Placement");
    let placement = Placement::parse(string(
        extra,
        &placement_key,
        string(extra, &legacy_placement_key, "path")?,
    )?)?;
    if placement == Placement::QueryInHeader {
        return Err(format!(
            "XHTTP {placement_key} does not support queryInHeader"
        ));
    }
    let default_key = match (prefix, placement) {
        ("sessionID", Placement::Header) => "X-Session",
        ("sessionID", _) => "x_session",
        (_, Placement::Header) => "X-Seq",
        _ => "x_seq",
    };
    let key = string(
        extra,
        &format!("{prefix}Key"),
        string(extra, &format!("{legacy}Key"), default_key)?,
    )?
    .to_owned();
    if placement == Placement::Header {
        HeaderName::from_bytes(key.as_bytes()).map_err(|e| e.to_string())?;
    }
    Ok((placement, key))
}

impl Options {
    pub fn parse(config: &XHttpTransportConfig) -> Result<Self, String> {
        let empty = Map::new();
        let extra = match &config.extra {
            None => &empty,
            Some(Value::Object(map)) => map,
            _ => return Err("XHTTP extra must be an object".into()),
        };
        let mode = if config.mode.is_empty() {
            "auto"
        } else {
            &config.mode
        };
        if let Some(host) = config.host.as_deref().filter(|s| !s.trim().is_empty()) {
            host.trim()
                .parse::<http::uri::Authority>()
                .map_err(|e| format!("invalid XHTTP host: {e}"))?;
        }
        if !matches!(mode, "auto" | "packet-up" | "stream-up" | "stream-one") {
            return Err(format!("unsupported XHTTP mode: {mode}"));
        }
        let method = string(extra, "uplinkHTTPMethod", "POST")?.to_ascii_uppercase();
        Method::from_bytes(method.as_bytes()).map_err(|e| e.to_string())?;
        let data_placement = match string(extra, "uplinkDataPlacement", "auto")? {
            "auto" => DataPlacement::Auto,
            "body" => DataPlacement::Body,
            "header" => DataPlacement::Header,
            "cookie" => DataPlacement::Cookie,
            other => return Err(format!("unsupported XHTTP uplinkDataPlacement: {other}")),
        };
        if (method == "GET"
            || matches!(
                data_placement,
                DataPlacement::Header | DataPlacement::Cookie
            ))
            && mode != "packet-up"
        {
            return Err("XHTTP GET/header/cookie uploads require mode packet-up".into());
        }
        if string(extra, "xPaddingMethod", "repeat-x")? != "repeat-x" {
            return Err("Elise XHTTP currently supports xPaddingMethod repeat-x".into());
        }
        let padding_placement =
            Placement::parse(string(extra, "xPaddingPlacement", "queryInHeader")?)?;
        if padding_placement == Placement::Path {
            return Err("XHTTP padding cannot be placed in path".into());
        }
        let padding_key = string(extra, "xPaddingKey", "x_padding")?.to_owned();
        let default_data_key = if data_placement == DataPlacement::Cookie {
            "x_data"
        } else {
            "X-Data"
        };
        let data_key = string(extra, "uplinkDataKey", default_data_key)?.to_owned();
        HeaderName::from_bytes(format!("{data_key}-0").as_bytes()).map_err(|e| e.to_string())?;
        if !padding_key
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
        {
            return Err("XHTTP xPaddingKey must be an ASCII token".into());
        }
        let (session_placement, session_key) = meta(extra, "sessionID", "session")?;
        let (seq_placement, seq_key) = meta(extra, "seq", "seq")?;
        let mut path = config.path.split('?').next().unwrap_or("/").to_owned();
        if !path.starts_with('/') {
            path.insert(0, '/');
        }
        if (session_placement == Placement::Path || seq_placement == Placement::Path)
            && !path.ends_with('/')
        {
            path.push('/');
        }
        let mut headers = HeaderMap::new();
        let configured_headers = if config.extra.is_some() {
            extra
                .get("headers")
                .map(|v| serde_json::from_value(v.clone()))
                .transpose()
                .map_err(|e| e.to_string())?
                .unwrap_or_default()
        } else {
            config.headers.clone()
        };
        for (key, value) in configured_headers {
            let key = HeaderName::from_bytes(key.as_bytes()).map_err(|e| e.to_string())?;
            if matches!(
                key.as_str(),
                "content-length" | "transfer-encoding" | "connection" | "host"
            ) {
                return Err(format!("XHTTP headers cannot override {key}"));
            }
            headers.insert(
                key,
                HeaderValue::from_str(&value).map_err(|e| e.to_string())?,
            );
        }
        if extra.contains_key("uplinkChunkSize") {
            range(extra, "uplinkChunkSize", "2048")?;
        }
        Ok(Self {
            mode: mode.to_owned(),
            path,
            host: config.host.clone().filter(|s| !s.trim().is_empty()),
            headers,
            padding: range(extra, "xPaddingBytes", "100-1000")?,
            obfs: boolean(extra, "xPaddingObfsMode")?,
            padding_placement,
            padding_header: HeaderName::from_bytes(
                string(extra, "xPaddingHeader", "X-Padding")?.as_bytes(),
            )
            .map_err(|e| e.to_string())?,
            padding_key,
            data_placement,
            data_key,
            max_post: *range(extra, "scMaxEachPostBytes", "1000000")?.end(),
            max_buffered: *range(extra, "scMaxBufferedPosts", "30")?.end(),
            max_headers: *range(extra, "serverMaxHeaderBytes", "8192")?.end(),
            stream_up_secs: range(extra, "scStreamUpServerSecs", "20-80")?,
            no_sse: boolean(extra, "noSSEHeader")?,
            session_placement,
            session_key,
            seq_placement,
            seq_key,
        })
    }

    pub fn validate<B>(&self, req: &Request<B>) -> Result<(), StatusCode> {
        if let Some(expected) = &self.host {
            let actual = req
                .uri()
                .authority()
                .map(|a| a.as_str())
                .or_else(|| header(req.headers(), "host"));
            let host = |s: &str| {
                s.parse::<http::uri::Authority>()
                    .ok()
                    .map(|a| a.host().to_ascii_lowercase())
            };
            if actual.and_then(host) != host(expected.trim()) || actual.is_none() {
                return Err(StatusCode::NOT_FOUND);
            }
        }
        if !req.uri().path().starts_with(&self.path) {
            return Err(StatusCode::NOT_FOUND);
        }
        if req.uri().to_string().len()
            + req
                .headers()
                .iter()
                .map(|(k, v)| k.as_str().len() + v.len() + 4)
                .sum::<usize>()
            > self.max_headers
        {
            return Err(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
        }
        if req.method() == Method::OPTIONS {
            return Ok(());
        }
        let padding = if self.obfs {
            cookie(req.headers(), &self.padding_key)
                .or_else(|| {
                    header(req.headers(), self.padding_header.as_str()).and_then(|s| {
                        if self.padding_placement == Placement::Header {
                            Some(s.to_owned())
                        } else {
                            query(s, &self.padding_key)
                        }
                    })
                })
                .or_else(|| query(&req.uri().to_string(), &self.padding_key))
        } else {
            match header(req.headers(), "referer") {
                Some(s) => query(s, "x_padding"),
                None => query(&req.uri().to_string(), "x_padding"),
            }
        };
        if !padding.is_some_and(|s| self.padding.contains(&s.len())) {
            tracing::debug!("XHTTP request has missing or invalid padding");
            return Err(StatusCode::BAD_REQUEST);
        }
        Ok(())
    }

    pub fn metadata<B>(&self, req: &Request<B>) -> (String, String) {
        let mut parts = req
            .uri()
            .path()
            .strip_prefix(&self.path)
            .unwrap_or("")
            .split('/');
        let mut extract = |placement, key: &str| match placement {
            Placement::Path => parts.next().unwrap_or("").to_owned(),
            Placement::Header => header(req.headers(), key).unwrap_or("").to_owned(),
            Placement::Cookie => cookie(req.headers(), key).unwrap_or_default(),
            Placement::Query => query(&req.uri().to_string(), key).unwrap_or_default(),
            Placement::QueryInHeader => String::new(),
        };
        (
            extract(self.session_placement, &self.session_key),
            extract(self.seq_placement, &self.seq_key),
        )
    }

    pub fn response_headers(&self, streaming: bool) -> HeaderMap {
        let mut headers = self.headers.clone();
        headers.insert("cache-control", HeaderValue::from_static("no-store"));
        headers.insert("x-accel-buffering", HeaderValue::from_static("no"));
        if streaming && !self.no_sse {
            headers.insert(
                "content-type",
                HeaderValue::from_static("text/event-stream"),
            );
        }
        let padding = "X".repeat(rand::thread_rng().gen_range(self.padding.clone()));
        if !self.obfs {
            headers.insert("x-padding", HeaderValue::from_str(&padding).unwrap());
        } else {
            let value = match self.padding_placement {
                Placement::Header => padding,
                Placement::QueryInHeader => format!("?{}={padding}", self.padding_key),
                Placement::Cookie => {
                    headers.append(
                        "set-cookie",
                        HeaderValue::from_str(&format!("{}={padding}; Path=/", self.padding_key))
                            .unwrap(),
                    );
                    return headers;
                }
                _ => return headers,
            };
            headers.insert(
                self.padding_header.clone(),
                HeaderValue::from_str(&value).unwrap(),
            );
        }
        headers
    }
}

pub(super) fn header<'a>(headers: &'a HeaderMap, key: &str) -> Option<&'a str> {
    headers.get(key).and_then(|v| v.to_str().ok())
}

pub(super) fn cookie(headers: &HeaderMap, key: &str) -> Option<String> {
    headers
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|part| {
            let (name, value) = part.trim().split_once('=')?;
            (name == key).then(|| value.to_owned())
        })
}

fn query(url: &str, key: &str) -> Option<String> {
    url::form_urlencoded::parse(url.split_once('?')?.1.split('#').next()?.as_bytes())
        .find_map(|(k, v)| (k == key).then(|| v.into_owned()))
}
