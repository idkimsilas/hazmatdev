pub const SIGNATURE_VER1: u128 = 0xde61af8ddd996602f4148ac83b9e506f;
pub const ALIGN_TO: u64 = 0x1000;

/// Fixed-size header written before the project-specific payload area.
#[repr(C)]
pub struct Header {
    pub signature: u128,
    pub starting_lba: u64,
    pub ending_lba: u64,
}

/// Serialize a project header for the inclusive LBA range reserved after the
/// cover FAT32 filesystem.
pub fn create_header(starting_lba: u64, ending_lba: u64) -> Vec<u8> {
    let header = Header {
        signature: SIGNATURE_VER1,
        starting_lba: starting_lba + 1,
        ending_lba,
    };

    let bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(&header as *const Header as *const u8, size_of::<Header>())
    };

    let mut buffer = vec![0u8; size_of::<Header>()];

    buffer.copy_from_slice(bytes);
    buffer
}

pub fn verify_header(buffer: &[u8]) -> anyhow::Result<Option<Header>> {
    anyhow::ensure!(buffer.len() >= size_of::<Header>());

    let header = unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const Header) };

    if header.signature != SIGNATURE_VER1 {
        return Ok(None);
    }

    Ok(Some(header))
}
