use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex,
};

pub fn dev_name_to_index(name: &str) -> std::io::Result<u32> {
    let alias = name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut luid = unsafe { std::mem::zeroed() };
    unsafe {
        match ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) {
            0 => {
                let mut index = 0;
                match ConvertInterfaceLuidToIndex(&luid, &mut index) {
                    0 => Ok(index),
                    err => Err(std::io::Error::from_raw_os_error(err as _)),
                }
            }
            err => Err(std::io::Error::from_raw_os_error(err as _)),
        }
    }
}
