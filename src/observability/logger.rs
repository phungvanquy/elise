use super::rolling::{LogLimits, RollingFile};
use regex::Regex;
use std::io::{self, Write};
use std::sync::{Arc, OnceLock};
use tracing_appender::non_blocking::{ErrorCounter, WorkerGuard};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::prelude::*;

pub struct LoggerGuard {
    _worker: Option<WorkerGuard>,
    dropped: Option<ErrorCounter>,
}

impl Drop for LoggerGuard {
    fn drop(&mut self) {
        if let Some(counter) = &self.dropped {
            let dropped = counter.dropped_lines();
            if dropped != 0 {
                eprintln!("Elise logging: dropped {dropped} runtime records because the bounded queue was full");
            }
        }
    }
}

/// Strip credential-bearing URL components and common credential fields, including
/// reqwest's Debug error representation. Do not rely on callers using Display.
pub(crate) fn redact(text: &str) -> String {
    static URL: OnceLock<Regex> = OnceLock::new();
    static SECRET: OnceLock<Regex> = OnceLock::new();
    static AUTH: OnceLock<Regex> = OnceLock::new();
    let text = URL
        .get_or_init(|| Regex::new(r#"(?i)(?:https?|redis|rediss)://[^\s"<>\\]+"#).unwrap())
        .replace_all(text, |caps: &regex::Captures<'_>| {
            match url::Url::parse(&caps[0]) {
                Ok(mut url) => {
                    let _ = url.set_username("");
                    let _ = url.set_password(None);
                    url.set_query(None);
                    url.set_fragment(None);
                    url.to_string()
                }
                Err(_) => "[redacted-url]".into(),
            }
        });
    let text = AUTH
        .get_or_init(|| {
            Regex::new(r#"(?i)\bauthorization([=:]\s*)(?:bearer|basic)\s+[^\s",}]+"#).unwrap()
        })
        .replace_all(&text, "authorization$1[redacted]");
    SECRET.get_or_init(|| Regex::new(r#"(?i)\b(token|api[_-]?key|secret[_-]?key|password|passwd|authorization)([=:]\s*)[^\s&"\\,}]+"#).unwrap())
        .replace_all(&text, "$1$2[redacted]").into_owned()
}

pub(crate) fn truncate(text: &mut String, limit: usize) {
    if text.len() > limit {
        let mut end = limit;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str(" [truncated]");
    }
}

struct SafeWriter<W> {
    inner: W,
    secrets: Arc<Vec<String>>,
}
impl<W: Write> Write for SafeWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut text = String::from_utf8_lossy(bytes).into_owned();
        for secret in self.secrets.iter() {
            text = text.replace(secret, "[redacted]");
        }
        text = redact(&text);
        let newline = text.ends_with('\n');
        text = text
            .trim_end_matches('\n')
            .chars()
            .flat_map(|ch| match ch {
                '\n' => "\\n".chars().collect::<Vec<_>>(),
                '\r' => "\\r".chars().collect(),
                c if c.is_control() => vec![' '],
                c => vec![c],
            })
            .collect();
        truncate(&mut text, 8192);
        if newline {
            text.push('\n');
        }
        self.inner.write_all(text.as_bytes())?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct FileWriter {
    inner: RollingFile,
    failures: u64,
}
impl Write for FileWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self.inner.write(bytes) {
            Ok(count) => {
                if self.failures > 0 {
                    eprintln!(
                        "Elise logging: runtime file writes recovered after {} failures",
                        self.failures
                    );
                    self.failures = 0;
                }
                Ok(count)
            }
            Err(error) => {
                self.failures = self.failures.saturating_add(1);
                if self.failures.is_power_of_two() {
                    eprintln!(
                        "Elise logging: runtime file write failed ({} failures): {}",
                        self.failures,
                        redact(&error.to_string())
                    );
                }
                Err(error)
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub fn init_logger(
    config: &crate::config::GlobalConfig,
) -> Result<LoggerGuard, Box<dyn std::error::Error + Send + Sync>> {
    let filter =
        EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new(&config.log_level))?;
    let mut secrets = Vec::new();
    for secret in [
        Some(config.api_key.as_str()),
        config.clickhouse_password.as_deref(),
    ]
    .into_iter()
    .flatten()
    .filter(|s| !s.is_empty())
    {
        secrets.push(secret.to_string());
        secrets.push(url::form_urlencoded::byte_serialize(secret.as_bytes()).collect());
        let escaped = serde_json::to_string(secret)?;
        secrets.push(escaped[1..escaped.len() - 1].to_string());
    }
    secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
    secrets.dedup();
    let secrets = Arc::new(secrets);
    let console_secrets = secrets.clone();
    let console = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_target(true)
        .with_writer(move || SafeWriter {
            inner: io::stderr(),
            secrets: console_secrets.clone(),
        });
    let (file, worker, dropped) = if let Some(path) = config.log_file.as_deref() {
        let writer = RollingFile::new(path, LogLimits::from_config(config))?;
        let (writer, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
            .buffered_lines_limit(1024)
            .lossy(true)
            .finish(FileWriter {
                inner: writer,
                failures: 0,
            });
        let dropped = writer.error_counter();
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_target(true)
            .with_writer(move || SafeWriter {
                inner: writer.clone(),
                secrets: secrets.clone(),
            });
        (Some(layer), Some(guard), Some(dropped))
    } else {
        (None, None, None)
    };
    tracing_subscriber::registry()
        .with(filter)
        .with(console)
        .with(file)
        .try_init()?;
    Ok(LoggerGuard {
        _worker: worker,
        dropped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authorization_headers_do_not_leave_bearer_tokens_behind() {
        assert!(!redact("Authorization: Bearer unknown-secret").contains("unknown-secret"));
        assert!(!redact("Authorization=Basic encoded-secret").contains("encoded-secret"));
    }
    #[test]
    fn secrets_urls_and_multiline_messages_are_safe() {
        let mut output = Vec::new();
        let mut writer = SafeWriter {
            inner: &mut output,
            secrets: Arc::new(vec!["known-secret".into()]),
        };
        writer.write_all(b"request failed https://admin:pass@example.com/api/user?token=abc#secret token=xyz known-secret\nforged\x1b[31m\n").unwrap();
        let text = String::from_utf8(output).unwrap();
        for secret in ["admin", "pass", "abc", "xyz", "known-secret", "\x1b"] {
            assert!(!text.contains(secret), "{text}");
        }
        assert!(text.contains("https://example.com/api/user"));
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("\\nforged"));
    }
}
