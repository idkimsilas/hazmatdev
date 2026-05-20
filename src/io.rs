use std::ffi::{CString, c_ulonglong, c_void};
use std::mem;

use bytesize::ByteSize;
use libc::{BLKSSZGET, O_RDWR, S_IFBLK, S_IFREG, SEEK_SET, ioctl};

use crate::{ll, utils};

const REPORT_LABEL_WIDTH: usize = 16;
const ZERO_WRITE_BYTES: usize = 1024 * 1024;
const VIRTUAL_SECTOR_SIZE: u64 = 512;

// Open the target for read/write access. The caller is responsible for
// deciding whether the operation is destructive before constructing this.
fn open_file(path: &str) -> anyhow::Result<i32> {
    let c_path = CString::new(path)?;

    unsafe {
        let fd = libc::open(c_path.as_ptr(), O_RDWR);

        if fd < 0 {
            anyhow::bail!("failed to open '{path}': {}", ll::errno_message());
        }

        Ok(fd)
    }
}

// Read the size and physical/stat block size from the OS. For regular files,
// st_blksize is kept as the real write block used by the random-fill pass.
fn ll_stat(path: &str, fd: i32, is_blk: bool, st: &libc::stat) -> anyhow::Result<(u64, u64, u64)> {
    unsafe {
        let total_size = if is_blk {
            let mut total_size: c_ulonglong = 0;

            if let res = ioctl(fd, ll::BLKGETSIZE64, &mut total_size)
                && res == -1
            {
                anyhow::bail!(
                    "failed to ioctl with BLKGETSIZE64 on '{path}': {}",
                    ll::errno_message()
                );
            }

            total_size
        } else {
            st.st_size as u64
        };

        let blk_size = if is_blk {
            let mut blk_size: c_ulonglong = 0;

            if let res = ioctl(fd, BLKSSZGET, &mut blk_size)
                && res == -1
            {
                anyhow::bail!(
                    "failed to ioctl with BLKSSZGET on '{path}': {}",
                    ll::errno_message()
                );
            }

            blk_size
        } else {
            st.st_blksize as u64
        };

        let blk_count = total_size / blk_size;

        Ok((total_size, blk_size, blk_count))
    }
}

struct StatCheckFileResult {
    is_blk: bool,
    total_size: u64,
    blk_size: u64,
    blk_count: u64,
    virtual_blk_size: u64,
    virtual_blk_count: u64,
    virtual_usable_size: u64,
    usable_size: u64,
    usable_blk_count: u64,
}

// Build both real block accounting and virtual block accounting. The virtual
// block size is the logical disk sector size used by filesystem writers.
fn stat_check_file(path: &str, fd: i32) -> anyhow::Result<StatCheckFileResult> {
    unsafe {
        let mut st: libc::stat = mem::zeroed();

        if let res = libc::fstat(fd, &mut st)
            && res != 0
        {
            anyhow::bail!("failed to stat '{path}': {}", ll::errno_message());
        }

        // false possitive
        #[allow(unused_assignments)]
        let mut is_blk = false;

        if st.st_mode & S_IFBLK == S_IFBLK {
            is_blk = true;
        } else if st.st_mode & S_IFREG == S_IFREG {
            is_blk = false;
        } else {
            anyhow::bail!("the file '{path}' is not block or file");
        }

        let (total_size, blk_size, blk_count) = ll_stat(path, fd, is_blk, &st)?;
        let virtual_blk_size = VIRTUAL_SECTOR_SIZE;
        let virtual_usable_size = total_size - (total_size % virtual_blk_size);
        let virtual_blk_count = virtual_usable_size / virtual_blk_size;

        if total_size % blk_size != 0 {
            let usable_size = total_size - (total_size % blk_size);
            let usable_blk_count = usable_size / blk_size;

            return Ok(StatCheckFileResult {
                is_blk,
                total_size,
                blk_size,
                blk_count,
                virtual_blk_size,
                virtual_blk_count,
                virtual_usable_size,
                usable_size,
                usable_blk_count,
            });
        }

        let usable_size = total_size;
        let usable_blk_count = usable_size / blk_size;

        Ok(StatCheckFileResult {
            is_blk,
            total_size,
            blk_size,
            blk_count,
            virtual_blk_size,
            virtual_blk_count,
            virtual_usable_size,
            usable_size,
            usable_blk_count,
        })
    }
}

/// Open file or block device plus the size/accounting data used by commands.
///
/// `blk_*` fields describe the real OS block size used for streaming random
/// data. `virtual_*` fields describe the logical sector size used by disk
/// structure writers such as the MSFAT32 generator.
pub struct IoDevice {
    /// Raw file descriptor for the opened target.
    pub fd: i32,
    /// True when the target is a block device, false for a regular file.
    pub is_blk_device: bool,
    /// Full byte length reported by the OS.
    pub total_size: u64,
    /// Real block size used for streaming writes.
    pub blk_size: u64,
    /// Number of full real blocks in `total_size`.
    pub blk_count: u64,
    /// Logical sector size used by filesystem/layout code.
    pub virtual_blk_size: u64,
    /// Number of full virtual blocks in `total_size`.
    pub virtual_blk_count: u64,
    /// Byte length rounded down to `virtual_blk_size`.
    pub virtual_usable_size: u64,
    /// Byte length rounded down to `blk_size`.
    pub usable_size: u64,
    /// Number of full real blocks in `usable_size`.
    pub usable_blk_count: u64,
}

impl IoDevice {
    /// Open `path` and collect real and virtual block geometry.
    pub fn new(path: &str) -> anyhow::Result<Self> {
        let fd = open_file(path)?;
        let stats = stat_check_file(path, fd)?;

        Ok(IoDevice {
            fd,
            is_blk_device: stats.is_blk,
            total_size: stats.total_size,
            blk_size: stats.blk_size,
            blk_count: stats.blk_count,
            virtual_blk_size: stats.virtual_blk_size,
            virtual_blk_count: stats.virtual_blk_count,
            virtual_usable_size: stats.virtual_usable_size,
            usable_size: stats.usable_size,
            usable_blk_count: stats.usable_blk_count,
        })
    }

    /// Print the device geometry used by format/sanitize operations.
    pub fn display_stats(&self) {
        utils::print_report("is block", self.is_blk_device, REPORT_LABEL_WIDTH);
        utils::print_report(
            "total bytes",
            ByteSize::b(self.total_size),
            REPORT_LABEL_WIDTH,
        );
        utils::print_report("block size", self.blk_size, REPORT_LABEL_WIDTH);
        utils::print_report("total blocks", self.blk_count, REPORT_LABEL_WIDTH);
        utils::print_report("virtual block", self.virtual_blk_size, REPORT_LABEL_WIDTH);
        utils::print_report("virtual blocks", self.virtual_blk_count, REPORT_LABEL_WIDTH);

        if self.is_blk_device {
            utils::print_report(
                "available bytes",
                ByteSize::b(self.usable_size),
                REPORT_LABEL_WIDTH,
            );
            utils::print_report(
                "available blocks",
                self.usable_blk_count,
                REPORT_LABEL_WIDTH,
            );
        }
    }

    /// Seek the shared descriptor to an absolute byte offset.
    pub fn seek(&self, offset: i64) -> anyhow::Result<()> {
        unsafe {
            if let res = libc::lseek(self.fd, offset, SEEK_SET)
                && res == -1
            {
                anyhow::bail!("lseek failed; {}", ll::errno_message());
            }
        }

        Ok(())
    }

    /// Flush pending writes to the backing device or file.
    pub fn sync(&self) -> anyhow::Result<()> {
        unsafe {
            if libc::fsync(self.fd) == -1 {
                anyhow::bail!("fsync failed; {}", ll::errno_message());
            }
        }

        Ok(())
    }

    /// Write one buffer at the descriptor's current offset.
    ///
    /// This is a thin checked wrapper over `write(2)`: it may perform a
    /// partial write, but never returns `0` as success.
    pub fn write(&self, buf: &[u8]) -> anyhow::Result<isize> {
        unsafe {
            let res = libc::write(self.fd, buf.as_ptr() as *const c_void, buf.len());

            if res == -1 {
                anyhow::bail!("write failed; {}", ll::errno_message());
            }

            if res == 0 {
                anyhow::bail!("write wrote zero bytes");
            }

            Ok(res)
        }
    }

    /// Write the full buffer at the descriptor's current offset.
    pub fn write_all(&self, mut buf: &[u8]) -> anyhow::Result<()> {
        while !buf.is_empty() {
            let written = self.write(buf)?;
            buf = &buf[usize::try_from(written)?..];
        }

        Ok(())
    }

    /// Read one buffer from the descriptor's current offset.
    ///
    /// This is a thin checked wrapper over `read(2)`: it may perform a partial
    /// read, but never returns `0` as success.
    pub fn read(&self, buf: &mut [u8]) -> anyhow::Result<isize> {
        unsafe {
            let res = libc::read(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len());

            if res == -1 {
                anyhow::bail!("read failed; {}", ll::errno_message());
            }

            if res == 0 {
                anyhow::bail!("read reached end of device");
            }

            Ok(res)
        }
    }

    /// Read the full buffer from the descriptor's current offset.
    pub fn read_exact(&self, mut buf: &mut [u8]) -> anyhow::Result<()> {
        while !buf.is_empty() {
            let read = self.read(buf)?;
            buf = &mut buf[usize::try_from(read)?..];
        }

        Ok(())
    }

    /// Read one buffer at an absolute byte offset without changing seek state.
    ///
    /// This is a thin checked wrapper over `pread(2)`: it may perform a
    /// partial read, but never returns `0` as success.
    pub fn read_at(&self, offset: i64, buf: &mut [u8]) -> anyhow::Result<isize> {
        unsafe {
            let res = libc::pread(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len(), offset);

            if res == -1 {
                anyhow::bail!("read failed; {}", ll::errno_message());
            }

            if res == 0 {
                anyhow::bail!("read at offset {offset} reached end of device");
            }

            Ok(res)
        }
    }

    /// Read the full buffer at an absolute byte offset.
    pub fn read_exact_at(&self, offset: i64, mut buf: &mut [u8]) -> anyhow::Result<()> {
        let mut read_len = 0;

        while !buf.is_empty() {
            let read_offset = offset
                .checked_add(i64::try_from(read_len)?)
                .ok_or_else(|| anyhow::anyhow!("read offset overflow"))?;
            let res = self.read_at(read_offset, buf)?;

            let res = usize::try_from(res)?;
            buf = &mut buf[res..];
            read_len += res;
        }

        Ok(())
    }

    /// Write one buffer at an absolute byte offset without changing seek state.
    ///
    /// This is a thin checked wrapper over `pwrite(2)`: it may perform a
    /// partial write, but never returns `0` as success.
    pub fn write_at(&self, offset: i64, buf: &[u8]) -> anyhow::Result<isize> {
        unsafe {
            let res = libc::pwrite(self.fd, buf.as_ptr() as *const c_void, buf.len(), offset);

            if res == -1 {
                anyhow::bail!("write failed; {}", ll::errno_message());
            }

            if res == 0 {
                anyhow::bail!("write at offset {offset} wrote zero bytes");
            }

            Ok(res)
        }
    }

    /// Write the full buffer at an absolute byte offset.
    pub fn write_all_at(&self, offset: i64, buf: &[u8]) -> anyhow::Result<()> {
        let mut written = 0;

        while written < buf.len() {
            let write_offset = offset
                .checked_add(i64::try_from(written)?)
                .ok_or_else(|| anyhow::anyhow!("write offset overflow"))?;
            let res = self.write_at(write_offset, &buf[written..])?;

            written += usize::try_from(res)?;
        }

        Ok(())
    }

    /// Write `len` zero bytes at an absolute byte offset.
    pub fn write_zeroes_at(&self, offset: i64, len: u64) -> anyhow::Result<()> {
        let zeroes = vec![0u8; ZERO_WRITE_BYTES];
        let mut written = 0_u64;

        while written < len {
            let write_offset = offset
                .checked_add(i64::try_from(written)?)
                .ok_or_else(|| anyhow::anyhow!("zero write offset overflow"))?;
            let chunk_len = usize::try_from((len - written).min(zeroes.len() as u64))?;

            self.write_all_at(write_offset, &zeroes[..chunk_len])?;
            written += u64::try_from(chunk_len)?;
        }

        Ok(())
    }

    /// Write from a raw pointer at the descriptor's current offset.
    ///
    /// # Safety
    ///
    /// `ptr` must be valid for reads of `len` bytes for the duration of the
    /// call, and it must point to initialized memory.
    pub unsafe fn write_ptr(&self, ptr: *const c_void, len: usize) -> anyhow::Result<isize> {
        unsafe {
            let res = libc::write(self.fd, ptr, len);

            if res == -1 {
                anyhow::bail!("write failed; {}", ll::errno_message());
            }

            if res == 0 {
                anyhow::bail!("write wrote zero bytes");
            }

            Ok(res)
        }
    }
}

pub mod helpers {
    use indicatif::ProgressBar;
    use std::ffi::c_void;
    use std::io::Read;

    use crate::cipher::{self, FastRand};
    use crate::cmd;

    use super::IoDevice;

    pub trait SanitizeDisk {
        fn block_walk(
            &self,
            limit: u64,
            blk_size: usize,
            pb: &ProgressBar,
            rng: &mut FastRand,
        ) -> anyhow::Result<()>;

        fn sanitize_disk(&self) -> anyhow::Result<()>;
    }

    impl SanitizeDisk for IoDevice {
        // Stream random data over the target using the real OS block size.
        fn block_walk(
            &self,
            limit: u64,
            blk_size: usize,
            pb: &ProgressBar,
            rng: &mut FastRand,
        ) -> anyhow::Result<()> {
            let mut block = Box::new(vec![0u8; blk_size]);
            let block_ptr: *const c_void = block.as_ptr() as *const c_void;
            let mut last_progress_show: Option<std::time::SystemTime> = None;

            for offset in 0..limit {
                rng.read_exact(&mut block)?;

                let written = unsafe { self.write_ptr(block_ptr, blk_size)? };

                if written == 0 {
                    anyhow::bail!("write wrote zero bytes");
                }

                if last_progress_show.is_none()
                    || last_progress_show
                        .map(|v| {
                            v.elapsed()
                                .map(|v| v > std::time::Duration::from_secs(1))
                                .unwrap_or_default()
                        })
                        .unwrap_or_default()
                {
                    pb.set_position(offset * blk_size as u64);
                    last_progress_show = Some(std::time::SystemTime::now());
                }
            }

            Ok(())
        }

        // Fill the whole target with random data before laying down public disk
        // structures. Regular-file remainders are handled after full real blocks.
        fn sanitize_disk(&self) -> anyhow::Result<()> {
            println!("filling device with random binary data");

            let process_blk_count = if self.is_blk_device {
                self.usable_blk_count
            } else {
                self.blk_count
            };

            anyhow::ensure!(self.blk_size <= usize::MAX as u64);

            self.seek(0)?;

            let blk_size = self.blk_size as usize;
            let mut rng = cipher::fast_rand()?;
            let pb = cmd::create_progress_bar(process_blk_count * blk_size as u64);

            if blk_size as u64 <= self.usable_size {
                self.block_walk(process_blk_count, blk_size, &pb, &mut rng)?;
            }

            // Write any trailing bytes after the final full real block.
            if !self.is_blk_device {
                let size = (self.total_size - self.usable_size) as usize;
                if size > 0 {
                    let mut block = Box::new(vec![0u8; size]);

                    rng.read_exact(&mut block)?;

                    let written = self.write(&block)?;

                    if written == 0 {
                        anyhow::bail!("remaining data write wrote zero bytes");
                    }
                }
            }

            pb.finish_and_clear();
            self.sync()?;

            Ok(())
        }
    }
}
