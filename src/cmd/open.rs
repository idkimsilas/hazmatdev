use std::rc::Rc;
use std::sync::Arc;

use bytesize::ByteSize;
use libublk::ctrl::{UblkCtrl, UblkCtrlBuilder};
use libublk::helpers::IoBuf;
use libublk::io::{UblkDev, UblkQueue};
use libublk::{BufDesc, UblkError, UblkFlags};

use crate::cipher::BlockCipher;
use crate::{hazmat, io, msfat32};

const IO_BUFFER_LEN: u32 = 512 * 1024;

// Runtime state used by the userspace block-device callbacks. The exposed
// block device maps sector zero to `shadow_start_lba` in the backing target.
struct BlkDeviceOps {
    io_device: io::IoDevice,
    block_cipher: BlockCipher,
    shadow_start_lba: u64,
    shadow_size: u64,
}

impl BlkDeviceOps {
    // Convert an exposed-device byte range into an absolute backing byte
    // offset, rejecting unaligned or out-of-range requests from ublk.
    fn backing_offset(&self, offset: u64, len: usize) -> anyhow::Result<i64> {
        let len = u64::try_from(len)?;
        let sector_size = self.io_device.virtual_blk_size;

        anyhow::ensure!(
            offset % sector_size == 0 && len % sector_size == 0,
            "ublk request is not sector-aligned"
        );

        let end = offset
            .checked_add(len)
            .ok_or_else(|| anyhow::anyhow!("ublk request offset overflow"))?;
        anyhow::ensure!(end <= self.shadow_size, "ublk request is out of range");

        let relative_lba = offset / sector_size;
        let backing_lba = self
            .shadow_start_lba
            .checked_add(relative_lba)
            .ok_or_else(|| anyhow::anyhow!("backing LBA overflow"))?;

        backing_lba
            .checked_mul(sector_size)
            .and_then(|offset| i64::try_from(offset).ok())
            .ok_or_else(|| anyhow::anyhow!("backing offset is too large"))
    }

    // Encrypt or decrypt each sector using its real backing LBA as cipher
    // context, matching the format-time per-sector transform.
    fn transform_sectors(&self, offset: u64, data: &mut [u8], encrypt: bool) -> anyhow::Result<()> {
        let sector_size = usize::try_from(self.io_device.virtual_blk_size)?;
        anyhow::ensure!(
            data.len() % sector_size == 0,
            "ublk request length is not sector-aligned"
        );

        let first_lba = self
            .shadow_start_lba
            .checked_add(offset / self.io_device.virtual_blk_size)
            .ok_or_else(|| anyhow::anyhow!("cipher LBA overflow"))?;

        for (sector_index, sector) in data.chunks_exact_mut(sector_size).enumerate() {
            let lba = first_lba
                .checked_add(u64::try_from(sector_index)?)
                .ok_or_else(|| anyhow::anyhow!("cipher LBA overflow"))?;

            if encrypt {
                self.block_cipher.encrypt_sector(lba, sector);
            } else {
                self.block_cipher.decrypt_sector(lba, sector);
            }
        }

        Ok(())
    }

    // Read encrypted backing sectors and decrypt them into the ublk buffer.
    fn read_result(&self, offset: u64, data: &mut [u8]) -> anyhow::Result<i32> {
        let backing_offset = self.backing_offset(offset, data.len())?;

        self.io_device.read_exact_at(backing_offset, data)?;
        self.transform_sectors(offset, data, false)?;

        Ok(i32::try_from(data.len())?)
    }

    // Encrypt one ublk write request before writing it to the backing target.
    fn write_result(&self, offset: u64, data: &[u8]) -> anyhow::Result<i32> {
        let backing_offset = self.backing_offset(offset, data.len())?;
        let mut encrypted = data.to_vec();

        self.transform_sectors(offset, &mut encrypted, true)?;
        self.io_device.write_all_at(backing_offset, &encrypted)?;

        Ok(i32::try_from(data.len())?)
    }

    // Flush pending writes to the backing target.
    fn flush_result(&self) -> anyhow::Result<i32> {
        self.io_device.sync()?;
        Ok(0)
    }

    // Adapter used by `handle_io`: log rich errors, return kernel errno.
    fn read(&self, offset: u64, data: &mut [u8]) -> i32 {
        self.read_result(offset, data)
            .inspect_err(|err| eprintln!("ublk read failed at offset {offset}: {err}"))
            .unwrap_or(-libc::EIO)
    }

    // Adapter used by `handle_io`: log rich errors, return kernel errno.
    fn write(&self, offset: u64, data: &[u8]) -> i32 {
        self.write_result(offset, data)
            .inspect_err(|err| eprintln!("ublk write failed at offset {offset}: {err}"))
            .unwrap_or(-libc::EIO)
    }

    // Adapter used by `handle_io`: log rich errors, return kernel errno.
    fn flush(&self) -> i32 {
        self.flush_result()
            .inspect_err(|err| eprintln!("ublk flush failed: {err}"))
            .unwrap_or(-libc::EIO)
    }
}

// Dispatch one completed ublk request to the shadow-device operations.
fn handle_io(q: &UblkQueue<'_>, tag: u16, data: &mut [u8], blk_device_ops: &BlkDeviceOps) -> i32 {
    let iod = q.get_iod(tag);
    let op = iod.op_flags & 0xff;
    let offset = iod.start_sector << 9;
    let bytes = (iod.nr_sectors << 9) as usize;

    if bytes > data.len() {
        return -libc::EINVAL;
    }

    match op {
        libublk::sys::UBLK_IO_OP_READ => blk_device_ops.read(offset, &mut data[..bytes]),
        libublk::sys::UBLK_IO_OP_WRITE => blk_device_ops.write(offset, &data[..bytes]),
        libublk::sys::UBLK_IO_OP_FLUSH => blk_device_ops.flush(),
        _ => -libc::EINVAL,
    }
}

// Keep one queue tag active by repeatedly preparing, handling, and committing
// ublk commands with a reusable aligned buffer.
async fn io_task(
    q: &UblkQueue<'_>,
    tag: u16,
    blk_device_ops: Arc<BlkDeviceOps>,
) -> Result<(), UblkError> {
    let mut buf = IoBuf::<u8>::new(q.dev.dev_info.max_io_buf_bytes as usize);

    q.submit_io_prep_cmd(tag, BufDesc::Slice(buf.as_slice()), 0, Some(&buf))
        .await?;

    loop {
        let res = handle_io(q, tag, buf.as_mut_slice(), &blk_device_ops);

        q.submit_io_commit_cmd(tag, BufDesc::Slice(buf.as_slice()), res)
            .await?;
    }
}

// Run all tags for one ublk queue on a local executor.
fn queue_handler(qid: u16, dev: &UblkDev, blk_device_ops: Arc<BlkDeviceOps>) {
    let q = Rc::new(UblkQueue::new(qid, dev).expect("failed to create ublk queue"));
    let exe = Rc::new(smol::LocalExecutor::new());
    let runner = exe.clone();
    let mut tasks = Vec::new();

    for tag in 0..dev.dev_info.queue_depth {
        let q = q.clone();
        let blk_device_ops = blk_device_ops.clone();

        tasks.push(exe.spawn(async move {
            match io_task(&q, tag, blk_device_ops).await {
                Ok(()) | Err(UblkError::QueueIsDown) => {}
                Err(err) => eprintln!("queue {qid} tag {tag} failed: {err}"),
            }
        }));
    }

    smol::block_on(exe.run(async move {
        let run_tasks = || while runner.try_tick() {};
        let is_done = || tasks.iter().all(|task| task.is_finished());

        if let Err(err) = libublk::wait_and_handle_io_events(&q, Some(20), run_tasks, is_done).await
        {
            eprintln!("queue {qid} event loop failed: {err}");
        }
    }));
}

// Print the kernel device node created for the mounted shadow device.
fn dump_blk_info(ctrl: &UblkCtrl) {
    println!("mounted to '/dev/ublkb{}'", ctrl.dev_info().dev_id);
}

// Create an unstarted ublk controller configured for hazmat shadow I/O.
fn create_blk_device() -> anyhow::Result<Arc<UblkCtrl>> {
    let ctrl = UblkCtrlBuilder::default()
        .name("hazmat")
        .id(-1)
        .nr_queues(4)
        .depth(64)
        .io_buf_bytes(IO_BUFFER_LEN)
        .dev_flags(UblkFlags::UBLK_DEV_F_ADD_DEV)
        .build()?;

    Ok(Arc::new(ctrl))
}

// Locate, decrypt, and validate the hazmat header hidden after the cover FAT32
// root cluster.
fn read_header(
    io_device: &io::IoDevice,
    block_cipher: &BlockCipher,
) -> anyhow::Result<hazmat::Header> {
    let mut buffer = vec![0u8; usize::try_from(io_device.virtual_blk_size)?];
    let first_unused_lba = msfat32::first_unused_cluster_lba(io_device)?;

    let header_lba = first_unused_lba;

    let header_offset = header_lba
        .checked_mul(io_device.virtual_blk_size)
        .and_then(|offset| i64::try_from(offset).ok())
        .ok_or_else(|| anyhow::anyhow!("hazmat header LBA {header_lba} is too large to seek"))?;

    println!("checking for hazmat signature at LBA {header_lba}");

    io_device.read_exact_at(header_offset, &mut buffer)?;
    block_cipher.decrypt_sector(header_lba, &mut buffer);

    hazmat::verify_header(&buffer)?.ok_or_else(|| {
        anyhow::anyhow!(
            "hazmat signature was not found at LBA {header_lba} or the password is wrong"
        )
    })
}

// Read and confirm the new format password without echoing it.
fn password_read() -> anyhow::Result<String> {
    loop {
        let pass = rpassword::prompt_password("password: ")?;

        if pass.is_empty() {
            continue;
        }

        return Ok(pass);
    }
}

// Open `drive`, verify the hazmat header, and expose the encrypted payload
// range as a userspace block device.
pub fn open(drive: &str) -> anyhow::Result<()> {
    println!("opening drive '{drive}'");

    let password = password_read()?;
    let block_cipher = BlockCipher::new(&password)?;
    let io_device = io::IoDevice::new(drive)?;
    let header = read_header(&io_device, &block_cipher)?;
    let hazmat_size = header
        .ending_lba
        .checked_sub(header.starting_lba)
        .and_then(|sectors| sectors.checked_add(1))
        .and_then(|sectors| sectors.checked_mul(io_device.virtual_blk_size))
        .ok_or_else(|| anyhow::anyhow!("hazmat payload size overflow"))?;

    println!(
        "hazmat payload range: {}..{} ({})",
        header.starting_lba,
        header.ending_lba,
        ByteSize::b(hazmat_size)
    );

    let blk_device_ops = Arc::new(BlkDeviceOps {
        shadow_start_lba: header.starting_lba,
        shadow_size: hazmat_size,
        io_device,
        block_cipher,
    });

    let blk_device_ops_queue = blk_device_ops.clone();

    create_blk_device()?.run_target(
        move |dev| {
            dev.set_default_params(hazmat_size);

            Ok(())
        },
        move |qid, dev| queue_handler(qid, dev, blk_device_ops_queue.clone()),
        |ctrl| dump_blk_info(ctrl),
    )?;

    Ok(())
}
