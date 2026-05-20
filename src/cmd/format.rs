use bytesize::ByteSize;

use crate::cipher::BlockCipher;
use crate::io::helpers::SanitizeDisk;
use crate::{constants, hazmat, io, msfat32};

// Reset the descriptor position and write the Windows-style GPT/FAT32 layout.
fn inserting_msfat32_structures(io_device: &io::IoDevice) -> anyhow::Result<(u64, u64)> {
    println!("inserting MSFAT32 structures");

    io_device.seek(0)?;
    msfat32::write_structures(io_device)
}

// Placeholder for project-specific structures that will be written after the
// cover FAT32 filesystem.
fn inserting_hazmat_structures(
    io_device: &io::IoDevice,
    block_cipher: BlockCipher,
    start_lba: u64,
    end_lba: u64,
) -> anyhow::Result<()> {
    println!("inserting hazmat layout for {start_lba}..{end_lba}");

    let header = hazmat::create_header(start_lba, end_lba);
    let mut block = vec![0u8; io_device.virtual_blk_size as usize];
    block[0..header.len()].copy_from_slice(&header);

    block_cipher.encrypt_sector(start_lba, &mut block);
    let byte_offset = start_lba
        .checked_mul(io_device.virtual_blk_size)
        .and_then(|offset| i64::try_from(offset).ok())
        .ok_or_else(|| anyhow::anyhow!("hazmat header LBA {start_lba} is too large to seek"))?;
    io_device.write_all_at(byte_offset, &block)?;

    Ok(())
}

// Read and confirm the new format password without echoing it.
fn password_read() -> anyhow::Result<String> {
    loop {
        let pass = rpassword::prompt_password("new password....: ")?;

        if pass.is_empty() {
            continue;
        }

        let pass_confirmation = rpassword::prompt_password("repeat password.: ")?;

        if pass != pass_confirmation {
            eprintln!("password doesn't match");
            continue;
        }

        return Ok(pass);
    }
}

/// Format `device` by randomizing it, writing the cover FAT32 structures, and
/// then inserting project-specific structures.
pub fn format(device: &str) -> anyhow::Result<()> {
    let pass = password_read()?;

    println!("deriving key");

    let block_cipher = BlockCipher::new(&pass)?;

    println!("formatting '{device}'");

    let io_device = io::IoDevice::new(device)?;

    io_device.display_stats();

    if io_device.total_size < constants::MINIMUM_SIZE {
        eprintln!(
            "the device size is {} while the minimum size needed is {}",
            ByteSize::b(io_device.total_size),
            ByteSize::b(constants::MINIMUM_SIZE)
        );

        return Ok(());
    }

    io_device.sanitize_disk()?;

    let (start_lba, end_lba) = inserting_msfat32_structures(&io_device)?;

    inserting_hazmat_structures(&io_device, block_cipher, start_lba, end_lba)?;

    println!("done");

    Ok(())
}
