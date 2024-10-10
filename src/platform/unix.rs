#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
pub fn dev_name_to_index(name: &str) -> std::io::Result<u32> {
    match std::ffi::CString::new(name) {
        Ok(name) => {
            let index = unsafe { libc::if_nametoindex(name.as_ptr()) as u32 };
            if index == 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(index)
            }
        }
        Err(_e) => Err(std::io::Error::new(std::io::ErrorKind::Other, "name error")),
    }
}
