//! Bounded file storage shared by runtime and optional access logs.
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

#[derive(Clone, Copy)]
pub struct LogLimits {
    pub max_bytes: u64,
    pub max_files: usize,
    pub retention: Duration,
}

impl Default for LogLimits {
    fn default() -> Self {
        Self {
            max_bytes: 10 * 1024 * 1024,
            max_files: 5,
            retention: Duration::from_secs(7 * 86400),
        }
    }
}

impl LogLimits {
    pub fn from_config(config: &crate::config::GlobalConfig) -> Self {
        Self {
            max_bytes: config.log_max_size_mb.max(1).saturating_mul(1024 * 1024),
            max_files: config.log_max_files.clamp(1, 100) as usize,
            retention: Duration::from_secs(u64::from(config.log_retention_days.max(1)) * 86400),
        }
    }
}

pub(crate) struct RollingFile {
    path: PathBuf,
    file: Option<File>,
    size: u64,
    limits: LogLimits,
    day: chrono::NaiveDate,
}

impl RollingFile {
    pub fn new(path: &Path, limits: LogLimits) -> io::Result<Self> {
        if limits.max_bytes == 0 || limits.max_files == 0 {
            return Err(io::Error::other("Log limits must be positive"));
        }
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        let mut writer = Self {
            path: path.to_owned(),
            file: None,
            size: 0,
            limits,
            day: chrono::Utc::now().date_naive(),
        };
        writer.prune()?;
        writer.open()?;
        if writer.size > limits.max_bytes
            || writer
                .file
                .as_ref()
                .unwrap()
                .metadata()?
                .modified()?
                .elapsed()
                .unwrap_or_default()
                > limits.retention
        {
            writer.rotate()?;
        }
        Ok(writer)
    }

    fn backup(&self, index: usize) -> PathBuf {
        let mut name = self.path.as_os_str().to_os_string();
        name.push(format!(".{index}"));
        name.into()
    }

    fn open(&mut self) -> io::Result<()> {
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&self.path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        self.size = file.metadata()?.len();
        self.file = Some(file);
        Ok(())
    }

    fn prune(&self) -> io::Result<()> {
        let parent = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let prefix = format!(
            "{}.",
            self.path
                .file_name()
                .ok_or_else(|| io::Error::other("Log path needs a filename"))?
                .to_string_lossy()
        );
        for entry in fs::read_dir(parent)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(suffix) = name.strip_prefix(&prefix) else {
                continue;
            };
            let Ok(index) = suffix.parse::<usize>() else {
                continue;
            };
            if index == 0 || suffix != index.to_string() {
                continue;
            }
            let meta = entry.metadata()?;
            if index >= self.limits.max_files
                || meta.len() > self.limits.max_bytes
                || SystemTime::now()
                    .duration_since(meta.modified()?)
                    .unwrap_or_default()
                    > self.limits.retention
            {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.file.take();
        for index in (1..self.limits.max_files).rev() {
            let from = if index == 1 {
                self.path.clone()
            } else {
                self.backup(index - 1)
            };
            match fs::rename(from, self.backup(index)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        if self.limits.max_files == 1 {
            match fs::remove_file(&self.path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        self.open()?;
        self.prune()?;
        self.day = chrono::Utc::now().date_naive();
        Ok(())
    }
}

impl Write for RollingFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > self.limits.max_bytes {
            return Err(io::Error::other("Log record exceeds file limit"));
        }
        if self.file.is_none() {
            self.open()?;
        }
        if self.size.saturating_add(bytes.len() as u64) > self.limits.max_bytes
            || self.day != chrono::Utc::now().date_naive()
        {
            self.rotate()?;
        }
        let count = self.file.as_mut().unwrap().write(bytes)?;
        self.size += count as u64;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        if let Some(file) = &mut self.file {
            file.flush()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rotation_is_bounded_across_restarts_and_preserves_newest_records() {
        let dir = std::env::temp_dir().join(format!("elise-log-{}", uuid::Uuid::new_v4()));
        let path = dir.join("runtime.log");
        let limits = LogLimits {
            max_bytes: 8,
            max_files: 3,
            ..Default::default()
        };
        for chunk in [b"1111111\n", b"2222222\n", b"3333333\n", b"4444444\n"] {
            let mut writer = RollingFile::new(&path, limits).unwrap();
            writer.write_all(chunk).unwrap();
        }
        assert_eq!(fs::read(&path).unwrap(), b"4444444\n");
        assert_eq!(fs::read(dir.join("runtime.log.1")).unwrap(), b"3333333\n");
        assert_eq!(fs::read(dir.join("runtime.log.2")).unwrap(), b"2222222\n");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 3);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn retention_prunes_only_owned_archives() {
        let dir = std::env::temp_dir().join(format!("elise-log-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("runtime.log");
        let expired = dir.join("runtime.log.1");
        fs::write(&expired, b"old").unwrap();
        File::options()
            .write(true)
            .open(&expired)
            .unwrap()
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(SystemTime::now() - Duration::from_secs(9 * 86400)),
            )
            .unwrap();
        fs::write(dir.join("runtime.log.notes"), b"keep").unwrap();
        let _writer = RollingFile::new(&path, LogLimits::default()).unwrap();
        assert!(!expired.exists());
        assert!(dir.join("runtime.log.notes").exists());
        fs::remove_dir_all(dir).unwrap();
    }
}
