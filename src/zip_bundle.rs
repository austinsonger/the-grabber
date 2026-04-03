use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use zip::write::SimpleFileOptions;

fn zip_options() -> SimpleFileOptions {
    SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o644)
}

fn add_file_to_zip(
    zip: &mut zip::ZipWriter<BufWriter<File>>,
    arc_name: &str,
    path: &Path,
) {
    let opts = zip_options();
    if zip.start_file(arc_name, opts).is_ok() {
        if let Ok(data) = std::fs::read(path) {
            let _ = zip.write_all(&data);
        }
    }
}

/// Bundle an explicit list of files into a zip archive at `zip_path`.
///
/// Arc names inside the zip are derived by stripping `base_dir` from each
/// path (after canonicalization).  If stripping fails (e.g. the file lives
/// outside `base_dir`), the bare filename is used instead.
///
/// Used by the TUI path where we already know the exact written paths.
pub fn bundle_files(files: &[String], base_dir: &Path, zip_path: &Path) -> Result<()> {
    let file = File::create(zip_path)
        .with_context(|| format!("cannot create zip at {}", zip_path.display()))?;
    let mut zip = zip::ZipWriter::new(BufWriter::new(file));

    let base_canon = base_dir.canonicalize().unwrap_or_else(|_| base_dir.to_path_buf());

    for path_str in files {
        let path = Path::new(path_str);
        if !path.exists() {
            continue;
        }
        let canon = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let arc_name = canon
            .strip_prefix(&base_canon)
            .map(|r| r.to_string_lossy().into_owned())
            .unwrap_or_else(|_| {
                path.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path_str.clone())
            });
        add_file_to_zip(&mut zip, &arc_name, path);
    }

    zip.finish().context("failed to finalize zip")?;
    Ok(())
}

/// Bundle all files under `dir` recursively into a zip archive at `zip_path`.
///
/// Arc names are relative to `dir`.  The zip file itself is excluded if it
/// happens to reside inside `dir`.
///
/// Used by the CLI path where we collect by walking the output directory.
pub fn bundle_dir(dir: &Path, zip_path: &Path) -> Result<()> {
    let file = File::create(zip_path)
        .with_context(|| format!("cannot create zip at {}", zip_path.display()))?;
    let mut zip = zip::ZipWriter::new(BufWriter::new(file));

    let zip_canon = zip_path.canonicalize().unwrap_or_else(|_| zip_path.to_path_buf());

    let mut stack: Vec<PathBuf> = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = match std::fs::read_dir(&current) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                // Don't include the zip itself.
                let canon = path.canonicalize().unwrap_or_else(|_| path.clone());
                if canon == zip_canon {
                    continue;
                }
                let arc_name = path
                    .strip_prefix(dir)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .into_owned();
                add_file_to_zip(&mut zip, &arc_name, &path);
            }
        }
    }

    zip.finish().context("failed to finalize zip")?;
    Ok(())
}
