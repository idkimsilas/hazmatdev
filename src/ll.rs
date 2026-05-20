use std::ffi::{CStr, c_ulong};

use libc::__errno_location;

pub const BLKGETSIZE64: c_ulong = 0x80081272;

/// Return the current thread's `errno` message as UTF-8 text.
pub fn errno_message<'a>() -> &'a str {
    unsafe {
        let erro = *__errno_location();
        let message = libc::strerror(erro);

        CStr::from_ptr(message as *const i8)
            .to_str()
            .expect("corrupted errno message")
    }
}
