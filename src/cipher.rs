use std::io::BufReader;

use aes::Aes256;
use aes::cipher::{KeyIvInit, StreamCipher};
use argon2::{Argon2, Params};
use ctr::Ctr64LE;

/// Buffered `/dev/urandom` reader used for large sequential random fills.
pub type FastRand = BufReader<std::fs::File>;

/// Open `/dev/urandom` as a buffered reader for fast streaming random bytes.
pub fn fast_rand() -> anyhow::Result<FastRand> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(false)
        .append(false)
        .create_new(false)
        .open("/dev/urandom")?;

    Ok(BufReader::new(file))
}

type Aes256Ctr = Ctr64LE<Aes256>;

/// Password-derived sector cipher used for project-specific encrypted blocks.
///
/// The password is stretched with Argon2id into three independent values:
/// a 256-bit AES key, a 128-bit CTR IV, and a 64-bit XOR seed. Encryption first
/// applies AES-256-CTR and then folds in the sector LBA through `xor_walk`.
/// Decryption performs the same reversible operations in the opposite order.
pub struct BlockCipher {
    key: aes::cipher::Key<Aes256Ctr>,
    iv: aes::cipher::Iv<Aes256Ctr>,
    xor_key: u64,
}

impl BlockCipher {
    const VER1_SALT: [u8; 64] = [
        0x8f, 0x4e, 0xed, 0x36, 0x7a, 0x66, 0xaf, 0x12, 0x5c, 0x41, 0x7e, 0x3a, 0x6b, 0x6c, 0x1d,
        0xc8, 0x11, 0x15, 0x1a, 0x8a, 0x0c, 0x7a, 0x25, 0xb5, 0x6c, 0x71, 0x92, 0x23, 0x9f, 0xda,
        0xa8, 0x79, 0x2e, 0x7f, 0xb6, 0x0b, 0x5d, 0x06, 0xa7, 0x54, 0x4f, 0xeb, 0x26, 0x28, 0x74,
        0x28, 0xd4, 0x82, 0x8d, 0x98, 0xc5, 0x4a, 0x51, 0x17, 0x4b, 0xc2, 0xc9, 0xd3, 0x6d, 0x11,
        0x54, 0x9f, 0x92, 0xb1,
    ];

    /// Derive the AES key, CTR IV, and XOR seed from `password`.
    ///
    /// The fixed salt makes this a deterministic format-version-1 derivation:
    /// the same password must produce the same block transform each time the
    /// device is opened.
    fn derive_key(password: &str) -> anyhow::Result<([u8; 32], [u8; 16], u64)> {
        let mut result = [0u8; 56];
        // will be version based some day
        let salt = Self::VER1_SALT;

        let params = Params::new(256 * 1024, 4, 4, Some(size_of_val(&result)))
            .expect("invalid argon2 params");

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        argon2
            .hash_password_into(password.as_bytes(), &salt, &mut result)
            .map_err(|_| anyhow::anyhow!("failed to derive key out of the password"))?;

        let mut key = [0u8; 32];
        let mut iv = [0u8; 16];
        let mut xor_key = [0u8; 8];

        key.copy_from_slice(&result[..32]);
        iv.copy_from_slice(&result[32..48]);
        xor_key.copy_from_slice(&result[48..56]);

        Ok((key, iv, u64::from_le_bytes(xor_key)))
    }

    /// Build a cipher instance from a user password.
    pub fn new(password: &str) -> anyhow::Result<BlockCipher> {
        let (key, iv, xor_key) = Self::derive_key(password)?;

        Ok(Self {
            key: key.into(),
            iv: iv.into(),
            xor_key,
        })
    }
}

impl BlockCipher {
    /// Mix a block with a deterministic 64-bit stream derived from `lba`.
    ///
    /// This pass makes two equal plaintext sectors encrypt differently at
    /// different LBAs, while remaining reversible because XOR is its own inverse.
    fn xor_walk(&self, lba: u64, block: &mut [u8]) {
        const WORD_SIZE: usize = size_of::<u64>();

        assert_eq!(block.len() % WORD_SIZE, 0);

        let word_count = block.len() / WORD_SIZE;
        let ptr = block.as_mut_ptr();
        let base_key = self.xor_key.wrapping_add(lba);

        for offset in 0..word_count {
            let xor_key = base_key.wrapping_add(offset as u64);

            unsafe {
                let word_ptr = ptr.add(offset * WORD_SIZE).cast::<u64>();
                let word = std::ptr::read_unaligned(word_ptr);
                std::ptr::write_unaligned(word_ptr, word ^ xor_key);
            }
        }
    }

    /// Encrypt one sector in place.
    ///
    /// `lba` must be the logical block address of `block`; using a different
    /// LBA during decryption will not recover the original bytes.
    pub fn encrypt_sector(&self, lba: u64, block: &mut [u8]) {
        assert_eq!(block.len() % size_of::<u64>(), 0);

        let mut aes = Aes256Ctr::new(&self.key, &self.iv);

        aes.apply_keystream(block);
        self.xor_walk(lba, block);
    }

    /// Decrypt one sector in place using the same LBA passed to encryption.
    pub fn decrypt_sector(&self, lba: u64, block: &mut [u8]) {
        assert_eq!(block.len() % size_of::<u64>(), 0);

        let mut aes = Aes256Ctr::new(&self.key, &self.iv);

        self.xor_walk(lba, block);
        aes.apply_keystream(block);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sector_encryption_round_trips_without_overwriting_memory() {
        let cipher = BlockCipher::new("test password").unwrap();
        let original = [0x5a; 512];
        let mut block = original;

        cipher.encrypt_sector(42, &mut block);
        assert_ne!(block, original);

        cipher.decrypt_sector(42, &mut block);
        assert_eq!(block, original);
    }
}
