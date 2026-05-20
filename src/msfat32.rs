use std::io::Read;

use crate::{io, utils};

const SECTOR_SIZE: u64 = 512;
const GPT_ENTRY_ARRAY_SECTORS: u64 = 32;
const GPT_ENTRY_COUNT: u32 = 128;
const GPT_ENTRY_SIZE: u32 = 128;
const GPT_HEADER_SIZE: usize = 92;
const MIN_TRAILING_GAP_SECTORS: u64 = 4_096;

const MSR_START_LBA: u64 = 34;
const FAT32_START_LBA: u64 = 32_768;
const FAT32_MIN_RESERVED_SECTORS: u64 = 32;
const FAT32_SECTORS_PER_CLUSTER: u64 = 8;
const FAT32_FATS: u64 = 2;
const HAZMAT_CLUSTER_GAP: u64 = 1000;
const FIRST_UNUSED_CLUSTER: u64 = 3 + HAZMAT_CLUSTER_GAP;
const FAT32_ALLOCATED_CLUSTERS: u64 = 1;
const SECONDS_PER_DAY: u64 = 86_400;
const UNIX_DAYS_TO_2000_01_01: u64 = 10_957;
const REPORT_LABEL_WIDTH: usize = 27;

#[derive(Clone, Copy)]
struct Fat32Geometry {
    partition_len: u64,
    partition_end_lba: u64,
    reserved_sectors: u64,
    sectors_per_fat: u64,
    first_fat_lba: u64,
    second_fat_lba: u64,
    data_start_lba: u64,
    total_clusters: u64,
    first_unused_sector_lba: u64,
}

struct Blob {
    start_lba: u64,
    bytes: &'static [u8],
}

#[derive(Clone, Copy)]
struct Fat32DiskLayout {
    sectors_per_cluster: u64,
    data_start_lba: u64,
    total_clusters: u64,
}

const FIXED_BLOBS: &[Blob] = &[Blob {
    start_lba: MSR_START_LBA,
    bytes: include_bytes!("../msfat32-blobs/msr_partition_prefix.bin"),
}];

struct GeneratedIds {
    disk_guid: Guid,
    msr_guid: Guid,
    basic_guid: Guid,
    fat_volume_id: u32,
    volume_label_time: FatTimestamp,
}

impl GeneratedIds {
    // Generate identity-bearing values that should differ between formatted
    // disks, while preserving the Windows-style structural templates.
    fn new() -> anyhow::Result<Self> {
        let mut volume_id = [0u8; 4];
        fill_random(&mut volume_id)?;
        let fat_volume_id = u32::from_le_bytes(volume_id);

        Ok(Self {
            disk_guid: Guid::new_v4()?,
            msr_guid: Guid::new_v4()?,
            basic_guid: Guid::new_v4()?,
            fat_volume_id,
            volume_label_time: FatTimestamp::random_before_today()?,
        })
    }
}

#[derive(Clone, Copy)]
struct Guid {
    canonical: [u8; 16],
}

impl Guid {
    // Generate an RFC 4122 version 4 GUID in canonical byte order.
    fn new_v4() -> anyhow::Result<Self> {
        let mut canonical = [0u8; 16];
        fill_random(&mut canonical)?;
        canonical[6] = (canonical[6] & 0x0f) | 0x40;
        canonical[8] = (canonical[8] & 0x3f) | 0x80;
        Ok(Self { canonical })
    }

    // GPT stores the first three GUID fields little-endian on disk.
    fn gpt_bytes(self) -> [u8; 16] {
        let b = self.canonical;
        [
            b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13],
            b[14], b[15],
        ]
    }
}

impl std::fmt::Display for Guid {
    // Render the canonical GUID string used in reports.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = self.canonical;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0],
            b[1],
            b[2],
            b[3],
            b[4],
            b[5],
            b[6],
            b[7],
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15]
        )
    }
}

// Compute the FAT32 geometry for the partition while matching the observed
// Windows layout rule that aligns the data area to a power-of-two sector
// offset.
fn fat32_geometry(partition_end_lba: u64) -> anyhow::Result<Fat32Geometry> {
    let partition_len = partition_end_lba - FAT32_START_LBA + 1;
    anyhow::ensure!(
        partition_len <= u64::from(u32::MAX),
        "FAT32 partition is too large for this FAT32 BPB writer"
    );

    let mut sectors_per_fat = 1;

    loop {
        let fat_area_sectors = FAT32_FATS * sectors_per_fat;
        let data_offset_sectors = (fat_area_sectors + FAT32_MIN_RESERVED_SECTORS)
            .checked_next_power_of_two()
            .ok_or_else(|| anyhow::anyhow!("FAT32 data offset overflow"))?;
        anyhow::ensure!(
            data_offset_sectors < partition_len,
            "partition is too small for FAT32"
        );

        let data_sectors = partition_len - data_offset_sectors;
        let total_clusters = data_sectors / FAT32_SECTORS_PER_CLUSTER;
        let required_fat_sectors = ((total_clusters + 2) * 4).div_ceil(SECTOR_SIZE);

        if required_fat_sectors == sectors_per_fat {
            anyhow::ensure!(total_clusters >= 65_525, "partition is too small for FAT32");
            anyhow::ensure!(
                total_clusters <= u64::from(u32::MAX) - 2,
                "FAT32 partition has too many clusters"
            );
            anyhow::ensure!(
                sectors_per_fat <= u64::from(u32::MAX),
                "FAT32 sectors-per-FAT is too large"
            );

            let data_start_lba = FAT32_START_LBA + data_offset_sectors;
            return Ok(Fat32Geometry {
                partition_len,
                partition_end_lba,
                reserved_sectors: data_offset_sectors - fat_area_sectors,
                sectors_per_fat,
                first_fat_lba: FAT32_START_LBA + data_offset_sectors - fat_area_sectors,
                second_fat_lba: FAT32_START_LBA + data_offset_sectors - sectors_per_fat,
                data_start_lba,
                total_clusters,
                first_unused_sector_lba: data_start_lba
                    + (FIRST_UNUSED_CLUSTER - 2) * FAT32_SECTORS_PER_CLUSTER,
            });
        }

        sectors_per_fat = required_fat_sectors;
    }
}

// Patch the protective MBR partition length for the target disk size.
fn patched_protective_mbr(disk_sectors: u64) -> [u8; SECTOR_SIZE as usize] {
    let mut mbr = *include_bytes!("../msfat32-blobs/lba0_mbr.bin");
    let protective_size = u32::try_from(disk_sectors - 1).unwrap_or(u32::MAX);
    mbr[458..462].copy_from_slice(&protective_size.to_le_bytes());
    mbr
}

// Patch GPT partition entries with fresh partition GUIDs and the computed
// FAT32 partition end LBA.
fn patched_gpt_entries(fat32_end_lba: u64, ids: &GeneratedIds) -> Vec<u8> {
    let mut entries = include_bytes!("../msfat32-blobs/gpt_primary_entries.bin").to_vec();
    entries[16..32].copy_from_slice(&ids.msr_guid.gpt_bytes());
    entries[128 + 16..128 + 32].copy_from_slice(&ids.basic_guid.gpt_bytes());
    write_u64(&mut entries, 128 + 40, fat32_end_lba);
    entries
}

// Patch a primary or backup GPT header and recompute its CRC after all fields
// are in their final on-disk form.
fn patched_gpt_header(
    template: &[u8; SECTOR_SIZE as usize],
    ids: &GeneratedIds,
    current_lba: u64,
    backup_lba: u64,
    last_usable_lba: u64,
    partition_entries_lba: u64,
    entries_crc: u32,
) -> [u8; SECTOR_SIZE as usize] {
    let mut header = *template;

    write_u32(&mut header, 16, 0);
    write_u64(&mut header, 24, current_lba);
    write_u64(&mut header, 32, backup_lba);
    write_u64(&mut header, 40, MSR_START_LBA);
    write_u64(&mut header, 48, last_usable_lba);
    header[56..72].copy_from_slice(&ids.disk_guid.gpt_bytes());
    write_u64(&mut header, 72, partition_entries_lba);
    write_u32(&mut header, 80, u64::from(GPT_ENTRY_COUNT));
    write_u32(&mut header, 84, u64::from(GPT_ENTRY_SIZE));
    write_u32(&mut header, 88, u64::from(entries_crc));

    let header_crc = crc32(&header[..GPT_HEADER_SIZE]);
    write_u32(&mut header, 16, u64::from(header_crc));
    header
}

// Build the FAT32 reserved region from the Windows template, resizing it for
// the computed reserved-sector count and patching boot/FSInfo values.
fn patched_fat32_reserved_region(fat32: Fat32Geometry, ids: &GeneratedIds) -> Vec<u8> {
    let reserved_len = usize::try_from(fat32.reserved_sectors * SECTOR_SIZE)
        .expect("reserved region must fit in memory");
    let template = include_bytes!("../msfat32-blobs/fat32_reserved_region.bin");
    let mut reserved = vec![0u8; reserved_len];
    let copied_len = reserved.len().min(template.len());
    reserved[..copied_len].copy_from_slice(&template[..copied_len]);

    patch_boot_sector(&mut reserved[0..SECTOR_SIZE as usize], fat32, ids);
    patch_fsinfo_sector(
        &mut reserved[SECTOR_SIZE as usize..SECTOR_SIZE as usize * 2],
        fat32,
    );
    let backup_offset = SECTOR_SIZE as usize * 6;
    patch_boot_sector(
        &mut reserved[backup_offset..backup_offset + SECTOR_SIZE as usize],
        fat32,
        ids,
    );
    reserved
}

// Patch BPB fields that depend on disk geometry or per-format identity.
fn patch_boot_sector(boot: &mut [u8], fat32: Fat32Geometry, ids: &GeneratedIds) {
    write_u16(boot, 14, fat32.reserved_sectors);
    write_u32(boot, 32, fat32.partition_len);
    write_u32(boot, 36, fat32.sectors_per_fat);
    write_u32(boot, 28, FAT32_START_LBA);
    write_u32(boot, 67, u64::from(ids.fat_volume_id));
}

// Patch FSInfo free-cluster accounting for the empty filesystem.
fn patch_fsinfo_sector(fsinfo: &mut [u8], fat32: Fat32Geometry) {
    write_u32(fsinfo, 488, fat32.total_clusters - FAT32_ALLOCATED_CLUSTERS);
    write_u32(fsinfo, 492, FIRST_UNUSED_CLUSTER);
}

// Build the FAT prefix for both FAT copies, including the end marker for the
// first invalid cluster when it falls inside the prefix blob.
fn patched_fat_prefix(total_clusters: u64) -> Vec<u8> {
    let mut fat = include_bytes!("../msfat32-blobs/fat32_fat_prefix.bin").to_vec();
    let next_invalid_cluster = total_clusters + 2;
    let offset = next_invalid_cluster as usize * 4;
    if offset + 4 <= fat.len() {
        fat[offset..offset + 4].copy_from_slice(&0x0fff_ffff_u32.to_le_bytes());
    }
    fat
}

// Build the root-directory cluster and update its volume-label timestamp.
fn patched_root_cluster(ids: &GeneratedIds) -> Vec<u8> {
    let mut cluster = include_bytes!("../msfat32-blobs/fat32_root_cluster.bin").to_vec();
    patch_short_entry_timestamps(&mut cluster, 0x00, ids.volume_label_time);
    cluster
}

// Patch FAT short-entry create/access/write timestamps at a directory-entry
// offset.
fn patch_short_entry_timestamps(cluster: &mut [u8], entry_offset: usize, timestamp: FatTimestamp) {
    cluster[entry_offset + 13] = timestamp.tenth;
    cluster[entry_offset + 14..entry_offset + 16].copy_from_slice(&timestamp.time.to_le_bytes());
    cluster[entry_offset + 16..entry_offset + 18].copy_from_slice(&timestamp.date.to_le_bytes());
    cluster[entry_offset + 18..entry_offset + 20].copy_from_slice(&timestamp.date.to_le_bytes());
    cluster[entry_offset + 22..entry_offset + 24].copy_from_slice(&timestamp.time.to_le_bytes());
    cluster[entry_offset + 24..entry_offset + 26].copy_from_slice(&timestamp.date.to_le_bytes());
}

// Write a template blob at its fixed LBA using the active virtual sector size.
fn write_fixed_blob(io_device: &io::IoDevice, sector_size: u64, blob: &Blob) -> anyhow::Result<()> {
    write_at_lba(io_device, sector_size, blob.start_lba, blob.bytes)
}

// Convert an LBA range to bytes and delegate the actual zero write to IoDevice.
fn write_zeroes_at_lba(
    io_device: &io::IoDevice,
    sector_size: u64,
    start_lba: u64,
    sector_count: u64,
) -> anyhow::Result<()> {
    if sector_count == 0 {
        return Ok(());
    }

    let byte_offset = start_lba
        .checked_mul(sector_size)
        .and_then(|offset| i64::try_from(offset).ok())
        .ok_or_else(|| anyhow::anyhow!("LBA {start_lba} is too large to seek"))?;
    let len = sector_count
        .checked_mul(sector_size)
        .ok_or_else(|| anyhow::anyhow!("zero range at LBA {start_lba} is too large"))?;
    io_device.write_zeroes_at(byte_offset, len)
}

// Convert one LBA to a byte offset and write the full buffer there.
fn write_at_lba(
    io_device: &io::IoDevice,
    sector_size: u64,
    lba: u64,
    bytes: &[u8],
) -> anyhow::Result<()> {
    let byte_offset = lba
        .checked_mul(sector_size)
        .and_then(|offset| i64::try_from(offset).ok())
        .ok_or_else(|| anyhow::anyhow!("LBA {lba} is too large to seek"))?;
    io_device.write_all_at(byte_offset, bytes)
}

// Read a full logical sector by LBA.
fn read_lba(
    io_device: &io::IoDevice,
    sector_size: u64,
    lba: u64,
    bytes: &mut [u8],
) -> anyhow::Result<()> {
    let byte_offset = lba
        .checked_mul(sector_size)
        .and_then(|offset| i64::try_from(offset).ok())
        .ok_or_else(|| anyhow::anyhow!("LBA {lba} is too large to seek"))?;
    io_device.read_exact_at(byte_offset, bytes)
}

// Parse the FAT32 boot sector fields needed to map cluster numbers to LBAs.
fn read_fat32_disk_layout(io_device: &io::IoDevice) -> anyhow::Result<Fat32DiskLayout> {
    let mut boot = [0u8; SECTOR_SIZE as usize];
    read_lba(
        io_device,
        io_device.virtual_blk_size,
        FAT32_START_LBA,
        &mut boot,
    )?;

    anyhow::ensure!(
        boot[510] == 0x55 && boot[511] == 0xaa,
        "FAT32 boot sector signature was not found at LBA {FAT32_START_LBA}"
    );

    let bytes_per_sector = u64::from(utils::read_le_u16(&boot, 11));
    let sectors_per_cluster = u64::from(boot[13]);
    let reserved_sectors = u64::from(utils::read_le_u16(&boot, 14));
    let fats = u64::from(boot[16]);
    let total_sectors_16 = u64::from(utils::read_le_u16(&boot, 19));
    let fat_size_16 = u64::from(utils::read_le_u16(&boot, 22));
    let total_sectors_32 = u64::from(utils::read_le_u32(&boot, 32));
    let fat_size_32 = u64::from(utils::read_le_u32(&boot, 36));

    anyhow::ensure!(
        bytes_per_sector == SECTOR_SIZE && bytes_per_sector == io_device.virtual_blk_size,
        "MSFAT32 open requires a {SECTOR_SIZE}-byte FAT32 sector"
    );
    anyhow::ensure!(
        sectors_per_cluster != 0,
        "FAT32 sectors-per-cluster is zero"
    );

    let total_sectors = if total_sectors_16 != 0 {
        total_sectors_16
    } else {
        total_sectors_32
    };
    let sectors_per_fat = if fat_size_16 != 0 {
        fat_size_16
    } else {
        fat_size_32
    };

    anyhow::ensure!(total_sectors != 0, "FAT32 total sector count is zero");
    anyhow::ensure!(sectors_per_fat != 0, "FAT32 sectors-per-FAT is zero");
    anyhow::ensure!(fats != 0, "FAT32 FAT count is zero");

    let fat_area_sectors = fats
        .checked_mul(sectors_per_fat)
        .ok_or_else(|| anyhow::anyhow!("FAT32 FAT area overflow"))?;
    let data_offset_sectors = reserved_sectors
        .checked_add(fat_area_sectors)
        .ok_or_else(|| anyhow::anyhow!("FAT32 data offset overflow"))?;
    anyhow::ensure!(
        data_offset_sectors < total_sectors,
        "FAT32 data area is outside the partition"
    );

    let data_sectors = total_sectors - data_offset_sectors;
    let total_clusters = data_sectors / sectors_per_cluster;
    anyhow::ensure!(total_clusters >= 65_525, "partition is not FAT32-sized");

    Ok(Fat32DiskLayout {
        sectors_per_cluster,
        data_start_lba: FAT32_START_LBA + data_offset_sectors,
        total_clusters,
    })
}

// Write a checked little-endian u32 into an on-disk structure.
fn write_u32(bytes: &mut [u8], offset: usize, value: u64) {
    let value = u32::try_from(value).expect("value must fit in u32");
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

// Write a checked little-endian u16 into an on-disk structure.
fn write_u16(bytes: &mut [u8], offset: usize, value: u64) {
    let value = u16::try_from(value).expect("value must fit in u16");
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

// Write a little-endian u64 into an on-disk structure.
fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

// Fill a byte slice with kernel-provided random data.
fn fill_random(bytes: &mut [u8]) -> anyhow::Result<()> {
    std::fs::File::open("/dev/urandom")?.read_exact(bytes)?;
    Ok(())
}

#[derive(Clone, Copy)]
struct FatTimestamp {
    year: u32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    date: u16,
    time: u16,
    tenth: u8,
}

impl FatTimestamp {
    // Generate a FAT timestamp between 2000-01-01 and yesterday. Avoiding
    // today's date keeps generated images from sharing an obvious fresh
    // formatting timestamp.
    fn random_before_today() -> anyhow::Result<Self> {
        let now_days = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
            / SECONDS_PER_DAY;
        let latest_day = now_days.saturating_sub(1);
        anyhow::ensure!(
            latest_day >= UNIX_DAYS_TO_2000_01_01,
            "system clock is too early for random timestamp generation"
        );

        let day_span = latest_day - UNIX_DAYS_TO_2000_01_01 + 1;
        let day_index = UNIX_DAYS_TO_2000_01_01 + (random_u64()? % day_span);
        let seconds = random_u64()? % SECONDS_PER_DAY;
        let (year, month, day) = civil_from_unix_days(day_index as i64);
        let hour = (seconds / 3600) as u32;
        let minute = ((seconds % 3600) / 60) as u32;
        let second = ((seconds % 60) & !1) as u32;
        let tenth = (random_u64()? % 200) as u8;

        let fat_year = year - 1980;
        let date = ((fat_year as u16) << 9) | ((month as u16) << 5) | day as u16;
        let time = ((hour as u16) << 11) | ((minute as u16) << 5) | (second as u16 / 2);

        Ok(Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            date,
            time,
            tenth,
        })
    }
}

impl std::fmt::Display for FatTimestamp {
    // Render the decoded timestamp for the format report.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

// Read a random little-endian u64.
fn random_u64() -> anyhow::Result<u64> {
    let mut bytes = [0u8; 8];
    fill_random(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

// Convert days since the Unix epoch to a Gregorian date without depending on
// timezone or libc date formatting.
fn civil_from_unix_days(days: i64) -> (u32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };

    (year as u32, m as u32, d as u32)
}

// Compute the CRC-32 variant used by GPT headers and partition-entry arrays.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;

    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }

    !crc
}

// Round a byte size down to the active FAT32 virtual sector size.
fn fat32_usable_size(total_size: u64, sector_size: u64) -> u64 {
    total_size - (total_size % sector_size)
}

/// Return the planned hazmat header LBA inside the FAT32 free-cluster area.
///
/// The header is intentionally placed past the first free clusters so Windows'
/// automatic cover-filesystem metadata writes have room before the hidden
/// region. Do not derive this from the current FAT allocation state: mounting
/// the cover filesystem can legitimately move the first free cluster.
pub fn first_unused_cluster_lba(io_device: &io::IoDevice) -> anyhow::Result<u64> {
    let layout = read_fat32_disk_layout(io_device)?;
    anyhow::ensure!(
        FIRST_UNUSED_CLUSTER < layout.total_clusters + 2,
        "configured hazmat header cluster is outside the FAT32 data area"
    );

    Ok(layout.data_start_lba + (FIRST_UNUSED_CLUSTER - 2) * layout.sectors_per_cluster)
}

/// Write the Windows-style GPT + FAT32 structures into an already randomized
/// target.
///
/// The layout uses `io_device.virtual_blk_size` as its logical sector size and
/// currently requires that value to be 512 bytes. It returns the first unused
/// FAT32 sector where the hazmat header should be written and the inclusive end
/// of the FAT32 data area.
pub fn write_structures(io_device: &io::IoDevice) -> anyhow::Result<(u64, u64)> {
    let sector_size = io_device.virtual_blk_size;

    anyhow::ensure!(
        sector_size == SECTOR_SIZE,
        "MSFAT32 requires a {SECTOR_SIZE}-byte virtual block size"
    );

    let usable_size = fat32_usable_size(io_device.virtual_usable_size, sector_size);

    let disk_sectors = usable_size / sector_size;
    anyhow::ensure!(
        disk_sectors > FAT32_START_LBA + MIN_TRAILING_GAP_SECTORS + GPT_ENTRY_ARRAY_SECTORS,
        "disk is too small for the Windows FAT32 layout"
    );

    let disk_bytes = disk_sectors * sector_size;
    let last_lba = disk_sectors - 1;
    let backup_entries_lba = last_lba - GPT_ENTRY_ARRAY_SECTORS;
    let last_usable_lba = backup_entries_lba - 1;
    let fat32_end_lba = disk_sectors - MIN_TRAILING_GAP_SECTORS - 1;

    anyhow::ensure!(
        fat32_end_lba <= last_usable_lba,
        "FAT32 partition overlaps backup GPT area"
    );

    let ids = GeneratedIds::new()?;
    let fat32 = fat32_geometry(fat32_end_lba)?;
    let gpt_entries = patched_gpt_entries(fat32.partition_end_lba, &ids);
    let entries_crc = crc32(&gpt_entries);

    let primary_header = patched_gpt_header(
        include_bytes!("../msfat32-blobs/gpt_primary_header.bin"),
        &ids,
        1,
        last_lba,
        last_usable_lba,
        2,
        entries_crc,
    );
    let backup_header = patched_gpt_header(
        include_bytes!("../msfat32-blobs/gpt_backup_header.bin"),
        &ids,
        last_lba,
        1,
        last_usable_lba,
        backup_entries_lba,
        entries_crc,
    );

    let protective_mbr = patched_protective_mbr(disk_sectors);
    let fat32_reserved = patched_fat32_reserved_region(fat32, &ids);
    let fat_prefix = patched_fat_prefix(fat32.total_clusters);
    let root_cluster = patched_root_cluster(&ids);
    let post_partition_gap_lba = fat32.partition_end_lba + 1;

    write_zeroes_at_lba(
        io_device,
        sector_size,
        MSR_START_LBA,
        FAT32_START_LBA - MSR_START_LBA,
    )?;
    write_zeroes_at_lba(
        io_device,
        sector_size,
        fat32.first_fat_lba,
        fat32.sectors_per_fat,
    )?;
    write_zeroes_at_lba(
        io_device,
        sector_size,
        fat32.second_fat_lba,
        fat32.sectors_per_fat,
    )?;
    write_zeroes_at_lba(
        io_device,
        sector_size,
        post_partition_gap_lba,
        backup_entries_lba - post_partition_gap_lba,
    )?;

    write_at_lba(io_device, sector_size, 0, &protective_mbr)?;
    write_at_lba(io_device, sector_size, 1, &primary_header)?;
    write_at_lba(io_device, sector_size, 2, &gpt_entries)?;
    write_fixed_blob(io_device, sector_size, &FIXED_BLOBS[0])?;
    write_at_lba(io_device, sector_size, FAT32_START_LBA, &fat32_reserved)?;
    write_at_lba(io_device, sector_size, fat32.first_fat_lba, &fat_prefix)?;
    write_at_lba(io_device, sector_size, fat32.second_fat_lba, &fat_prefix)?;
    write_at_lba(io_device, sector_size, fat32.data_start_lba, &root_cluster)?;
    write_at_lba(io_device, sector_size, backup_entries_lba, &gpt_entries)?;
    write_at_lba(io_device, sector_size, last_lba, &backup_header)?;

    io_device.sync()?;

    let fat32_data_zero_end_lba = fat32.data_start_lba + FAT32_SECTORS_PER_CLUSTER - 1;
    let fat32_data_end_lba =
        fat32.data_start_lba + fat32.total_clusters * FAT32_SECTORS_PER_CLUSTER - 1;

    utils::print_report(
        "disk",
        format!("{disk_sectors} sectors ({disk_bytes} bytes)"),
        REPORT_LABEL_WIDTH,
    );
    utils::print_report("virtual block size", sector_size, REPORT_LABEL_WIDTH);
    utils::print_report(
        "FAT32 partition",
        format!(
            "start LBA {FAT32_START_LBA}, end LBA {}, length {} sectors",
            fat32.partition_end_lba, fat32.partition_len
        ),
        REPORT_LABEL_WIDTH,
    );
    utils::print_report(
        "backup GPT entries",
        format!("LBA {backup_entries_lba}..{}", last_lba - 1),
        REPORT_LABEL_WIDTH,
    );
    utils::print_report(
        "backup GPT header",
        format!("LBA {last_lba}"),
        REPORT_LABEL_WIDTH,
    );
    utils::print_report(
        "FAT32 reserved sectors",
        fat32.reserved_sectors,
        REPORT_LABEL_WIDTH,
    );
    utils::print_report(
        "FAT32 sectors/FAT",
        fat32.sectors_per_fat,
        REPORT_LABEL_WIDTH,
    );
    utils::print_report(
        "FAT32 total clusters",
        fat32.total_clusters,
        REPORT_LABEL_WIDTH,
    );
    utils::print_report(
        "first unused FAT32 cluster",
        format!("cluster {FIRST_UNUSED_CLUSTER}"),
        REPORT_LABEL_WIDTH,
    );
    utils::print_report(
        "first unused sector",
        format!("LBA {}", fat32.first_unused_sector_lba),
        REPORT_LABEL_WIDTH,
    );
    utils::print_report(
        "FAT32 data zero end",
        format!("LBA {fat32_data_zero_end_lba}"),
        REPORT_LABEL_WIDTH,
    );
    utils::print_report(
        "FAT32 data end",
        format!("LBA {fat32_data_end_lba}"),
        REPORT_LABEL_WIDTH,
    );
    utils::print_report("GPT disk GUID", ids.disk_guid, REPORT_LABEL_WIDTH);
    utils::print_report("MSR partition GUID", ids.msr_guid, REPORT_LABEL_WIDTH);
    utils::print_report(
        "Basic Data partition GUID",
        ids.basic_guid,
        REPORT_LABEL_WIDTH,
    );
    utils::print_report(
        "FAT32 volume ID",
        format!("0x{:08x}", ids.fat_volume_id),
        REPORT_LABEL_WIDTH,
    );
    utils::print_report(
        "volume label timestamp",
        ids.volume_label_time,
        REPORT_LABEL_WIDTH,
    );

    Ok((fat32.first_unused_sector_lba, fat32_data_end_lba))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verify the CRC implementation against the standard test vector.
    #[test]
    fn crc32_matches_gpt_known_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    // Verify the four-GiB geometry against the observed Windows disk image.
    #[test]
    fn geometry_fits_four_gib_disk() {
        let disk_sectors = 4 * 1024 * 1024 * 1024_u64 / SECTOR_SIZE;
        let fat32_end_lba = disk_sectors - MIN_TRAILING_GAP_SECTORS - 1;
        let geometry = fat32_geometry(fat32_end_lba).unwrap();

        assert_eq!(geometry.partition_end_lba, fat32_end_lba);
        assert_eq!(
            geometry.data_start_lba,
            FAT32_START_LBA + geometry.reserved_sectors + FAT32_FATS * geometry.sectors_per_fat
        );
        assert_eq!(geometry.reserved_sectors, 102);
        assert_eq!(geometry.sectors_per_fat, 8_141);
        assert_eq!(geometry.data_start_lba, 49_152);
        assert!(geometry.total_clusters >= 65_525);
    }

    // Ensure file-backed images use 512-byte virtual sectors, not the host
    // filesystem block size.
    #[test]
    fn fat32_usable_size_uses_virtual_512_byte_sectors() {
        let four_kib = 4 * 1024_u64;
        assert_eq!(
            fat32_usable_size(four_kib + SECTOR_SIZE, SECTOR_SIZE),
            four_kib + SECTOR_SIZE
        );
        assert_eq!(
            fat32_usable_size(four_kib + SECTOR_SIZE + 1, SECTOR_SIZE),
            four_kib + SECTOR_SIZE
        );
    }
}
