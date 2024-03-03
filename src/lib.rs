//! A simple Rust crate to exploit CBC-PKCS7 padding oracles.
//! See [decrypt] or the examples on how to use.

#![no_std]
#![cfg_attr(not(feature="std"), feature(error_in_core))]

extern crate alloc;
use alloc::vec::Vec;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid ciphertext size. The length should be a multiple of {blocksize}, but the length is {found}")]
    WrongSize { blocksize: usize, found: usize },

    #[error(
        "couldn't decrypt the data. Make sure your oracle is valid and that PKCS7 padding is used"
    )]
    InvalidPadding,
}

type Result<T> = core::result::Result<T, Error>;

/// Decrypt a ciphertext using an oracle function.
/// Note that this assumes the IV is prepended to the ciphertext.
/// If that's not the case, the first block won't be decrypted.
///
/// # Example
/// ```
/// use aes::cipher::{
///     block_padding::{Pkcs7, RawPadding},
///     BlockDecryptMut, BlockEncryptMut, KeyIvInit,
/// };
///
/// type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
/// type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
///
/// const KEY: [u8; 16] = [0u8; 16];
/// const IV: [u8; 16] = [0u8; 16];
///
/// fn oracle(ciphertext: &[u8]) -> bool {
///     let mut buf = ciphertext.to_vec();
///
///     Aes128CbcDec::new(&KEY.into(), &IV.into())
///         .decrypt_padded_mut::<Pkcs7>(&mut buf)
///         .is_ok()
/// }
///
/// # let plaintext = b"000000Now that the party is jumping";
/// #
/// # let mut ciphertext = vec![0u8; (plaintext.len() / 16 + 1) * 16];
/// #
/// # ciphertext[..plaintext.len()].copy_from_slice(plaintext);
/// # let ciphertext = Aes128CbcEnc::new(&KEY.into(), &IV.into())
/// #    .encrypt_padded_mut::<Pkcs7>(&mut ciphertext, plaintext.len())
/// #    .unwrap();
/// #
/// # let mut iv = IV.to_vec();
/// #
/// # iv.extend_from_slice(ciphertext);
/// # let ciphertext = iv;
/// #
/// // Perform the attack
/// let plaintext = padding_oracle::decrypt(&ciphertext, 16, oracle).unwrap();
///```

pub fn decrypt(ciphertext: &[u8], blocksize: usize, oracle: fn(&[u8]) -> bool) -> Result<Vec<u8>> {
    // Returns if ciphertext length does not align with blocks
    if ciphertext.len() % blocksize != 0 {
        return Err(Error::WrongSize {
            blocksize,
            found: ciphertext.len(),
        });
    }

    let mut plaintext = b"".to_vec();
    let mut ciphertext = ciphertext.to_vec();

    for _ in 0..ciphertext.len() / blocksize - 1 {
        // Loop to bruteforce one block
        for i in 1..=blocksize {
            let offset = ciphertext.len() - blocksize - i;
            let initial_byte = ciphertext[offset];

            let mut ciphertext = ciphertext.to_vec();

            // Fix remaining bytes of the padding
            for j in 1..i {
                ciphertext[offset + j] = i as u8 ^ plaintext[j - 1] ^ ciphertext[offset + j];
            }

            match (0..=255u8).find_map(|k| {
                ciphertext[offset] = k;

                if oracle(&ciphertext) {
                    // Make sure this is the padding we're looking for
                    // See https://crypto.stackexchange.com/questions/40800/is-the-padding-oracle-attack-deterministic

                    if offset % blocksize == 0 || {
                        let mut ciphertext = ciphertext.clone();
                        ciphertext[offset - 1] = !ciphertext[offset - 1];

                        oracle(&ciphertext)
                    } {
                        return Some(k);
                    };
                }

                None
            }) {
                Some(k) => plaintext.insert(0, initial_byte ^ k ^ i as u8),
                None => return Err(Error::InvalidPadding)
            }
        }

        // Cut the last block
        ciphertext.truncate(ciphertext.len() - blocksize);
    }

    Ok(plaintext)
}
