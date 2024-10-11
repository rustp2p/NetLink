#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
mod unix;
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
pub use unix::*;
