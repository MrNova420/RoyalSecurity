use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use tracing::{info, warn};

use crate::config::AppConfig;

pub struct ConfigWatcher {
    config_path: PathBuf,
    poll_interval: Duration,
    last_modified: AtomicU64,
    last_reload_count: AtomicU64,
}

impl ConfigWatcher {
    pub fn new(config_path: PathBuf, poll_interval: Duration) -> Self {
        Self {
            config_path,
            poll_interval,
            last_modified: AtomicU64::new(0),
            last_reload_count: AtomicU64::new(0),
        }
    }

    pub async fn watch(&self, callback: impl Fn(&AppConfig) + Send + Sync + 'static) {
        let callback = std::sync::Arc::new(callback);
        loop {
            let cb = callback.clone();
            match self.poll_and_reload(&*cb) {
                Ok(true) => {}
                Ok(false) => {}
                Err(e) => {
                    warn!(error = %e, "Config hot-reload failed");
                }
            }
            tokio::time::sleep(self.poll_interval).await;
        }
    }

    fn poll_and_reload(
        &self,
        callback: &dyn Fn(&AppConfig),
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let metadata = std::fs::metadata(&self.config_path)?;
        let modified = metadata
            .modified()?
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs();

        let prev = self.last_modified.load(Ordering::Relaxed);
        if modified <= prev {
            return Ok(false);
        }

        self.last_modified.store(modified, Ordering::Relaxed);

        let content = std::fs::read_to_string(&self.config_path)?;
        let config: AppConfig = toml::from_str(&content)?;

        self.last_reload_count.fetch_add(1, Ordering::Relaxed);
        info!(
            path = %self.config_path.display(),
            reload_count = self.last_reload_count.load(Ordering::Relaxed),
            "Config hot-reloaded"
        );

        callback(&config);
        Ok(true)
    }

    pub fn last_reload_count(&self) -> u64 {
        self.last_reload_count.load(Ordering::Relaxed)
    }

    pub fn last_modified_secs(&self) -> u64 {
        self.last_modified.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use tempfile::NamedTempFile;

    fn write_config(file: &NamedTempFile, av_enabled: bool) {
        let config = AppConfig::default();
        let mut cfg_str = toml::to_string_pretty(&config).unwrap();
        cfg_str = cfg_str.replace(
            "av_enabled = true",
            &format!("av_enabled = {}", av_enabled),
        );
        std::fs::write(file.path(), cfg_str).unwrap();
    }

    #[test]
    fn test_config_watcher_new() {
        let w = ConfigWatcher::new(PathBuf::from("test.toml"), Duration::from_secs(5));
        assert_eq!(w.config_path, PathBuf::from("test.toml"));
        assert_eq!(w.poll_interval, Duration::from_secs(5));
        assert_eq!(w.last_reload_count(), 0);
        assert_eq!(w.last_modified_secs(), 0);
    }

    #[test]
    fn test_poll_and_reload_detects_change() {
        let file = NamedTempFile::new().unwrap();
        write_config(&file, true);

        let w = ConfigWatcher::new(file.path().to_path_buf(), Duration::from_millis(10));
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = called.clone();

        let result = w.poll_and_reload(&|_cfg| {
            called_clone.store(true, Ordering::Relaxed);
        });
        assert!(result.unwrap());
        assert!(called.load(Ordering::Relaxed));
        assert_eq!(w.last_reload_count(), 1);
    }

    #[test]
    fn test_poll_no_change_returns_false() {
        let file = NamedTempFile::new().unwrap();
        write_config(&file, true);

        let w = ConfigWatcher::new(file.path().to_path_buf(), Duration::from_millis(10));
        // First poll registers the modified time
        w.poll_and_reload(&|_| {}).unwrap();
        // Second poll with same file -> no change
        let result = w.poll_and_reload(&|_| {}).unwrap();
        assert!(!result);
        assert_eq!(w.last_reload_count(), 1);
    }

    #[test]
    fn test_poll_missing_file_errors() {
        let w = ConfigWatcher::new(
            PathBuf::from("/nonexistent/config.toml"),
            Duration::from_millis(10),
        );
        let result = w.poll_and_reload(&|_| {});
        assert!(result.is_err());
    }
}
