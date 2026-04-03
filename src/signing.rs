//! HMAC-SHA256 signing for evidence files.
//!
//! # Design
//!
//! After collection, for every evidence file we:
//!   1. Compute its SHA-256 digest (tamper detection on individual files).
//!   2. Assemble a sorted manifest `Vec<FileRecord>`.
//!   3. Compute HMAC-SHA256 over the *compact* JSON of that record list.
//!   4. Write `SIGNING-MANIFEST-<ts>.json` and `SIGNING-<ts>.key` to `out_dir`.
//!
//! # Verification
//!
//! Given the manifest and the key an auditor can:
//!   - Re-hash each file and compare against `sha256` in the manifest.
//!   - Re-compute the HMAC over the `files` JSON and compare against
//!     `manifest_hmac` to confirm the manifest itself is unmodified.
//!
//! # Key management
//!
//! The key is a cryptographically random 32-byte value generated per run.
//! It is written to `SIGNING-<ts>.key` and printed to stderr.  Move the
//! key file to a location separate from the evidence files (e.g. a password
//! manager) before sharing the evidence package.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

// ─── Hex helpers ──────────────────────────────────────────────────────────────

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn from_hex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        bail!("hex string has odd length ({})", s.len());
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .with_context(|| format!("invalid hex at position {}", i * 2))
        })
        .collect()
}

// ─── Signing Key ──────────────────────────────────────────────────────────────

/// A 256-bit HMAC signing key backed by OS-level randomness.
pub struct SigningKey([u8; 32]);

impl SigningKey {
    /// Generate a cryptographically secure random key using `/dev/urandom`.
    pub fn generate() -> Result<Self> {
        let mut key = [0u8; 32];
        std::fs::File::open("/dev/urandom")
            .context("cannot open /dev/urandom for key generation")?
            .read_exact(&mut key)
            .context("failed to read random bytes from /dev/urandom")?;
        Ok(Self(key))
    }

    /// Parse a 64-character lowercase hex string into a key.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = from_hex(s).context("invalid signing key hex")?;
        if bytes.len() != 32 {
            bail!(
                "signing key must be exactly 32 bytes (64 hex chars); got {}",
                bytes.len()
            );
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Encode as 64-character lowercase hex.
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }
}

// ─── Manifest structures ──────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct FileRecord {
    /// Path as written during collection (relative or absolute).
    pub path: String,
    /// SHA-256 of the file contents at collection time, hex-encoded.
    pub sha256: String,
    /// File size in bytes at collection time.
    pub size_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub tool: String,
    pub generated_at: String,
    pub signing_algorithm: String,
    /// HMAC-SHA256 over the *compact* JSON of `files` (sorted by path).
    /// Computed with the key stored in the companion `.key` file.
    pub manifest_hmac: String,
    pub files: Vec<FileRecord>,
    pub verification_note: String,
}

// ─── Internal: hashing ────────────────────────────────────────────────────────

fn sha256_file(path: &Path) -> Result<(String, u64)> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("cannot open {} for signing", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    let mut size = 0u64;
    loop {
        let n = file.read(&mut buf).with_context(|| {
            format!("read error on {} during signing", path.display())
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        size += n as u64;
    }
    Ok((to_hex(&hasher.finalize()), size))
}

fn hmac_of_records(records: &[FileRecord], key: &SigningKey) -> Result<String> {
    // Compact JSON — no extra whitespace — gives a deterministic byte string.
    let json = serde_json::to_string(records).context("failed to serialize file records")?;
    let mut mac = HmacSha256::new_from_slice(&key.0)
        .map_err(|e| anyhow::anyhow!("HMAC initialisation failed: {e}"))?;
    mac.update(json.as_bytes());
    Ok(to_hex(&mac.finalize().into_bytes()))
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Sign an explicit list of evidence file paths.
///
/// Writes two files into `out_dir`:
/// - `SIGNING-MANIFEST-<ts>.json` — hashes + HMAC
/// - `SIGNING-<ts>.key`           — the hex signing key (store separately!)
///
/// Returns `(manifest_path, key_file_path)`.
pub fn sign_files(
    files: &[String],
    timestamp: &str,
    key: &SigningKey,
    out_dir: &Path,
) -> Result<(PathBuf, PathBuf)> {
    // Hash every file, skipping ones that have already disappeared.
    let mut records: Vec<FileRecord> = files
        .iter()
        .filter_map(|p| {
            let path = Path::new(p);
            if !path.exists() {
                return None;
            }
            match sha256_file(path) {
                Ok((sha256, size_bytes)) => Some(FileRecord {
                    path: p.clone(),
                    sha256,
                    size_bytes,
                }),
                Err(e) => {
                    eprintln!("signing: skipping {p}: {e}");
                    None
                }
            }
        })
        .collect();

    records.sort_by(|a, b| a.path.cmp(&b.path));

    let manifest_hmac = hmac_of_records(&records, key)?;

    let manifest = Manifest {
        tool: env!("CARGO_PKG_NAME").to_string(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        signing_algorithm: "HMAC-SHA256".to_string(),
        manifest_hmac,
        files: records,
        verification_note: format!(
            "Store SIGNING-{ts}.key in secure storage separate from the evidence files. \
             Verify with: grabber --verify-manifest SIGNING-MANIFEST-{ts}.json \
             --signing-key $(cat SIGNING-{ts}.key)",
            ts = timestamp,
        ),
    };

    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("cannot create signing output dir {}", out_dir.display()))?;

    let manifest_name = format!("SIGNING-MANIFEST-{}.json", timestamp);
    let manifest_path = out_dir.join(&manifest_name);
    let json = serde_json::to_string_pretty(&manifest).context("failed to serialise manifest")?;
    std::fs::write(&manifest_path, json.as_bytes())
        .with_context(|| format!("failed to write {}", manifest_path.display()))?;

    let key_name = format!("SIGNING-{}.key", timestamp);
    let key_path = out_dir.join(&key_name);
    std::fs::write(&key_path, key.to_hex().as_bytes())
        .with_context(|| format!("failed to write {}", key_path.display()))?;

    Ok((manifest_path, key_path))
}

/// Collect all evidence files from `dir` recursively, excluding any signing
/// artifacts (files whose names start with `SIGNING-` or end with `.key`).
pub fn collect_dir_files(dir: &Path) -> Vec<String> {
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                if name.starts_with("SIGNING-") || name.ends_with(".key") {
                    continue;
                }
                files.push(path.to_string_lossy().into_owned());
            }
        }
    }
    files
}

// ─── Verification ─────────────────────────────────────────────────────────────

pub struct FileVerification {
    pub path: String,
    pub exists: bool,
    pub sha256_ok: bool,
    pub expected_sha256: String,
    pub actual_sha256: Option<String>,
}

pub struct VerifyReport {
    pub hmac_ok: bool,
    pub file_count: usize,
    pub ok_count: usize,
    pub missing_count: usize,
    pub tampered_count: usize,
    pub files: Vec<FileVerification>,
}

impl VerifyReport {
    pub fn all_ok(&self) -> bool {
        self.hmac_ok && self.missing_count == 0 && self.tampered_count == 0
    }

    /// Print a human-readable verification report to stderr.
    pub fn print(&self) {
        if self.hmac_ok {
            eprintln!("✓  Manifest HMAC verified — manifest is unmodified");
        } else {
            eprintln!("✗  Manifest HMAC FAILED — manifest may have been tampered with!");
        }
        eprintln!(
            "   Files: {} total  {} ok  {} missing  {} tampered",
            self.file_count, self.ok_count, self.missing_count, self.tampered_count
        );
        for f in &self.files {
            if !f.exists {
                eprintln!("   MISSING  {}", f.path);
            } else if !f.sha256_ok {
                eprintln!("   TAMPERED {}", f.path);
                eprintln!("     expected: {}", f.expected_sha256);
                if let Some(ref actual) = f.actual_sha256 {
                    eprintln!("     actual:   {actual}");
                }
            }
        }
        if self.all_ok() {
            eprintln!("\n✓  All {} evidence files verified successfully.", self.file_count);
        } else {
            eprintln!("\n✗  Verification FAILED.");
            std::process::exit(1);
        }
    }
}

/// Verify a manifest file against the provided signing key.
///
/// Checks:
/// 1. The HMAC over the stored `files` JSON matches `manifest_hmac`.
/// 2. Each listed file's current SHA-256 matches the recorded digest.
pub fn verify_manifest(manifest_path: &Path, key: &SigningKey) -> Result<VerifyReport> {
    let json = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("cannot read {}", manifest_path.display()))?;
    let manifest: Manifest = serde_json::from_str(&json)
        .with_context(|| format!("cannot parse {}", manifest_path.display()))?;

    // Re-derive HMAC over the stored file records (order is already canonical).
    let expected_hmac = hmac_of_records(&manifest.files, key)?;
    let hmac_ok = ct_eq_str(&expected_hmac, &manifest.manifest_hmac);

    let mut verifications = Vec::new();
    let mut ok_count = 0usize;
    let mut missing_count = 0usize;
    let mut tampered_count = 0usize;

    for record in &manifest.files {
        let path = Path::new(&record.path);
        let exists = path.exists();
        let (actual_sha256, sha256_ok) = if exists {
            match sha256_file(path) {
                Ok((actual, _)) => {
                    let ok = ct_eq_str(&actual, &record.sha256);
                    (Some(actual), ok)
                }
                Err(_) => (None, false),
            }
        } else {
            (None, false)
        };

        match (exists, sha256_ok) {
            (false, _) => missing_count += 1,
            (true, false) => tampered_count += 1,
            (true, true) => ok_count += 1,
        }

        verifications.push(FileVerification {
            path: record.path.clone(),
            exists,
            sha256_ok,
            expected_sha256: record.sha256.clone(),
            actual_sha256,
        });
    }

    Ok(VerifyReport {
        hmac_ok,
        file_count: manifest.files.len(),
        ok_count,
        missing_count,
        tampered_count,
        files: verifications,
    })
}

/// Constant-time string comparison (prevents timing side-channels).
fn ct_eq_str(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_temp(dir: &TempDir, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content).unwrap();
        path
    }

    #[test]
    fn hex_round_trip() {
        let bytes = b"\x00\xde\xad\xbe\xef\xff";
        assert_eq!(from_hex(&to_hex(bytes)).unwrap(), bytes);
    }

    #[test]
    fn key_hex_round_trip() {
        let key1 = SigningKey([0x42u8; 32]);
        let hex = key1.to_hex();
        let key2 = SigningKey::from_hex(&hex).unwrap();
        assert_eq!(key1.0, key2.0);
    }

    #[test]
    fn sign_and_verify_ok() {
        let dir = tempfile::tempdir().unwrap();
        write_temp(&dir, "a.csv", b"col1,col2\n1,2\n");
        write_temp(&dir, "b.json", b"{\"x\":1}");

        let files: Vec<String> = ["a.csv", "b.json"]
            .iter()
            .map(|n| dir.path().join(n).to_string_lossy().into_owned())
            .collect();

        let key = SigningKey([0x11u8; 32]);
        let (manifest_path, _key_path) =
            sign_files(&files, "test-ts", &key, dir.path()).unwrap();

        let report = verify_manifest(&manifest_path, &key).unwrap();
        assert!(report.all_ok());
        assert_eq!(report.file_count, 2);
    }

    #[test]
    fn verify_detects_tampered_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_temp(&dir, "evidence.csv", b"original");

        let files = vec![path.to_string_lossy().into_owned()];
        let key = SigningKey([0x22u8; 32]);
        let (manifest_path, _) = sign_files(&files, "ts", &key, dir.path()).unwrap();

        // Tamper with the file after signing.
        std::fs::write(&path, b"tampered content").unwrap();

        let report = verify_manifest(&manifest_path, &key).unwrap();
        assert!(report.hmac_ok);           // manifest itself is fine
        assert_eq!(report.tampered_count, 1);
        assert!(!report.all_ok());
    }

    #[test]
    fn verify_detects_wrong_key() {
        let dir = tempfile::tempdir().unwrap();
        write_temp(&dir, "f.csv", b"data");

        let files = vec![dir.path().join("f.csv").to_string_lossy().into_owned()];
        let key = SigningKey([0x33u8; 32]);
        let (manifest_path, _) = sign_files(&files, "ts2", &key, dir.path()).unwrap();

        let wrong_key = SigningKey([0x44u8; 32]);
        let report = verify_manifest(&manifest_path, &wrong_key).unwrap();
        assert!(!report.hmac_ok);
    }
}
