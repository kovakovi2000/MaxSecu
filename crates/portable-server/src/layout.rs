//! Portable folder layout (Phase-6 Task 2). All server-side artifacts (TLS cert,
//! blobs, D5 key material, logs) live under a single portable `data_dir` root.
//! [`Layout::ensure`] creates the sub-directories idempotently.
use std::path::{Path, PathBuf};

/// Portable folder layout rooted at a `data_dir`.
#[derive(Debug, Clone)]
pub struct Layout {
    root: PathBuf,
}

impl Layout {
    /// Creates the portable sub-directories (`tls/`, `blobs/`, `config/`, `logs/`)
    /// under `data_dir` and returns the layout. Idempotent: re-running over an
    /// existing tree is a no-op.
    pub fn ensure(data_dir: &Path) -> std::io::Result<Layout> {
        let layout = Layout {
            root: data_dir.to_path_buf(),
        };
        for dir in [
            layout.tls_dir(),
            layout.blobs_dir(),
            layout.config_dir(),
            layout.logs_dir(),
        ] {
            std::fs::create_dir_all(&dir)?;
        }
        Ok(layout)
    }

    /// TLS material directory (`tls/`).
    pub fn tls_dir(&self) -> PathBuf {
        self.root.join("tls")
    }

    /// Blob store directory (`blobs/`).
    pub fn blobs_dir(&self) -> PathBuf {
        self.root.join("blobs")
    }

    /// Config directory (`config/`).
    pub fn config_dir(&self) -> PathBuf {
        self.root.join("config")
    }

    /// Logs directory (`logs/`).
    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }

    /// DER-encoded TLS certificate (`tls/cert.der`).
    pub fn cert_der_path(&self) -> PathBuf {
        self.tls_dir().join("cert.der")
    }

    /// DER-encoded TLS private key (`tls/key.der`).
    pub fn cert_key_path(&self) -> PathBuf {
        self.tls_dir().join("key.der")
    }

    /// Published D5 directory public key (`config/directory_pub.der`).
    pub fn d5_pub_path(&self) -> PathBuf {
        self.config_dir().join("directory_pub.der")
    }

    /// D5 directory secret key material (`config/d5_secret.bin`).
    pub fn d5_secret_path(&self) -> PathBuf {
        self.config_dir().join("d5_secret.bin")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ensure_creates_subdirs_and_paths_under_data_dir() {
        let tmp = std::env::temp_dir().join(format!("mxps-layout-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let l = Layout::ensure(&tmp).unwrap();
        for d in [l.tls_dir(), l.blobs_dir(), l.config_dir(), l.logs_dir()] {
            assert!(d.is_dir(), "{d:?} should exist");
        }
        assert!(l.cert_der_path().starts_with(&tmp));
        assert!(l.d5_pub_path().starts_with(&tmp));
        // idempotent
        assert!(Layout::ensure(&tmp).is_ok());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
