/// Print one aligned report row as `label....: value`.
pub fn print_report(label: &str, value: impl std::fmt::Display, width: usize) {
    println!("{label:.<width$}: {value}");
}

/// Read a little-endian u16 from an on-disk byte structure.
pub fn read_le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("u16 field"))
}

/// Read a little-endian u32 from an on-disk byte structure.
pub fn read_le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("u32 field"))
}

/// Read a little-endian u64 from an on-disk byte structure.
pub fn read_le_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("u64 field"))
}
