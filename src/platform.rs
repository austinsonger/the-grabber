/// Redirect stderr (fd 2) to `path`, returning a saved copy of the old fd.
/// Returns -1 if anything fails (stderr is left unchanged).
#[cfg(unix)]
pub fn redirect_stderr_to_file(path: &std::path::Path) -> i32 {
    use std::os::unix::io::IntoRawFd;
    let backup = unsafe { libc::dup(2) };
    if backup < 0 {
        return -1;
    }
    match std::fs::OpenOptions::new().create(true).append(true).open(path) {
        Ok(f) => {
            let fd = f.into_raw_fd();
            unsafe {
                libc::dup2(fd, 2);
                libc::close(fd);
            }
            backup
        }
        Err(_) => {
            unsafe { libc::close(backup); }
            -1
        }
    }
}

#[cfg(not(unix))]
pub fn redirect_stderr_to_file(_path: &std::path::Path) -> i32 {
    -1
}

/// Restore stderr from a previously saved fd. No-op if `saved` is -1.
#[cfg(unix)]
pub fn restore_stderr(saved: i32) {
    if saved >= 0 {
        unsafe {
            libc::dup2(saved, 2);
            libc::close(saved);
        }
    }
}

#[cfg(not(unix))]
pub fn restore_stderr(_saved: i32) {}
