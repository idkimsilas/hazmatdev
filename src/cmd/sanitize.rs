use crate::io;
use crate::io::helpers::SanitizeDisk;

/// Overwrite `device` with random data without writing any disk structures.
pub fn sanitize(device: &str) -> anyhow::Result<()> {
    println!("sanitizing '{device}'");

    let io_device = io::IoDevice::new(device)?;

    io_device.display_stats();
    io_device.sanitize_disk()?;

    println!("done");

    Ok(())
}
