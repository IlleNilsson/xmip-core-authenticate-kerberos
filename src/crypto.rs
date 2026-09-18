//! `aes256-cts-hmac-sha1-96`, RFC 3962 with the RFC 3961 machinery beneath it.
//!
//! Encryption type 18 is AES-256 in CBC mode with ciphertext stealing, keyed
//! by a subkey derived from the ticket's key, with an HMAC-SHA1 truncated to
//! ninety-six bits for integrity. To open a ticket the node derives the two
//! subkeys — Ke for the cipher, Ki for the checksum — from the base key with
//! the key-derivation function (RFC 3961 section 5.1), decrypts the
//! confounder and plaintext, recomputes the checksum and refuses where it
//! does not match. `n`-fold, DK/DR and CBC-CTS are all here, small and
//! tested against the RFC's own vectors; only the one encryption type is
//! implemented, and any other is refused by name where a ticket names it.

use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit as _};
use authenticate::AuthenticateError;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use sha1::Sha1;

/// HMAC-SHA1 keyed by `key`, over `data`.
fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// `aes256-cts-hmac-sha1-96`, RFC 3962.
pub const AES256_CTS_HMAC_SHA1_96: u32 = 18;
/// The key usage RFC 4120 gives a ticket's `enc-part`.
pub const TICKET_KEY_USAGE: u32 = 2;
/// Bytes in an AES-256 key, and the CBC block size.
const KEY_LENGTH: usize = 32;
const BLOCK: usize = 16;
/// The checksum an etype-18 message carries, truncated to ninety-six bits.
const MAC_LENGTH: usize = 12;

/// Decrypt an etype-18 ciphertext under `base_key` for `usage`, checksum and
/// confounder removed.
///
/// # Errors
///
/// Where the ciphertext is too short to hold a confounder and a checksum, or
/// its checksum does not match — the reason names which.
pub fn decrypt(base_key: &[u8], usage: u32, message: &[u8]) -> Result<Vec<u8>, AuthenticateError> {
    if message.len() < BLOCK + MAC_LENGTH {
        return Err(AuthenticateError::new(
            "the Kerberos ciphertext is too short to hold a confounder and its checksum",
        ));
    }
    let base = cipher(base_key)?;
    let ke = derive(&base, usage, 0xAA)?;
    let ki = derive(&base, usage, 0x55)?;

    let (ciphertext, mac) = message.split_at(message.len() - MAC_LENGTH);
    let plaintext = cbc_cts_decrypt(&cipher(&ke)?, ciphertext)?;

    if hmac_sha1(&ki, &plaintext)[..MAC_LENGTH] != *mac {
        return Err(AuthenticateError::new(
            "the Kerberos ticket's checksum does not match: it was not sealed under this key",
        ));
    }
    Ok(plaintext[BLOCK..].to_vec())
}

/// The base key a password and salt derive to, RFC 3962 section 4:
/// PBKDF2-HMAC-SHA1 to a tentative key, then DK with the string `kerberos`.
///
/// # Errors
///
/// Never in practice; the signature is fallible so a caller handles a key
/// that will not initialize a cipher.
pub fn string_to_key(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<Vec<u8>, AuthenticateError> {
    let mut tentative = [0u8; KEY_LENGTH];
    pbkdf2::<Hmac<Sha1>>(password, salt, iterations, &mut tentative)
        .map_err(|_| AuthenticateError::new("the PBKDF2 output length is wrong"))?;
    let cipher = cipher(&tentative)?;
    derive_from(&cipher, b"kerberos")
}

fn cipher(key: &[u8]) -> Result<Aes256, AuthenticateError> {
    if key.len() != KEY_LENGTH {
        return Err(AuthenticateError::new(
            "an aes256-cts-hmac-sha1-96 key is thirty-two bytes",
        ));
    }
    Ok(Aes256::new(GenericArray::from_slice(key)))
}

/// DK(base, usage as four bytes then `variant`), RFC 3961 section 5.1.
fn derive(base: &Aes256, usage: u32, variant: u8) -> Result<Vec<u8>, AuthenticateError> {
    let mut constant = usage.to_be_bytes().to_vec();
    constant.push(variant);
    derive_from(base, &constant)
}

/// DK(base, constant): DR then, for AES, an identity random-to-key.
fn derive_from(base: &Aes256, constant: &[u8]) -> Result<Vec<u8>, AuthenticateError> {
    let mut block: [u8; BLOCK] = n_fold(constant, BLOCK)
        .try_into()
        .map_err(|_| AuthenticateError::new("n-fold produced the wrong length"))?;
    let mut material = Vec::with_capacity(KEY_LENGTH);
    while material.len() < KEY_LENGTH {
        let mut cipher_block = GenericArray::clone_from_slice(&block);
        base.encrypt_block(&mut cipher_block);
        block = cipher_block.into();
        material.extend_from_slice(&block);
    }
    material.truncate(KEY_LENGTH);
    Ok(material)
}

/// The `n`-fold of `input` to `out_len` bytes, RFC 3961 section 5.1.
fn n_fold(input: &[u8], out_len: usize) -> Vec<u8> {
    let in_len = input.len();
    let lcm = out_len / gcd(out_len, in_len) * in_len;
    let mut stretched = vec![0u8; lcm];
    for (rep, chunk) in stretched.chunks_mut(in_len).enumerate() {
        chunk.copy_from_slice(&rotate_right(input, 13 * rep));
    }
    let mut sum = vec![0u8; out_len];
    for chunk in stretched.chunks(out_len) {
        ones_complement_add(&mut sum, chunk);
    }
    sum
}

/// `input` as a big-endian bit string, rotated right by `bits`.
fn rotate_right(input: &[u8], bits: usize) -> Vec<u8> {
    let total = input.len() * 8;
    let bits = bits % total;
    let mut out = vec![0u8; input.len()];
    for target in 0..total {
        let source = (target + total - bits) % total;
        let bit = (input[source / 8] >> (7 - source % 8)) & 1;
        out[target / 8] |= bit << (7 - target % 8);
    }
    out
}

/// Add `addend` to `sum` with end-around carry, both big-endian.
fn ones_complement_add(sum: &mut [u8], addend: &[u8]) {
    let width = sum.len();
    let mut carry = 0u16;
    for index in (0..width).rev() {
        let total = u16::from(sum[index]) + u16::from(addend[index]) + carry;
        sum[index] = total.to_le_bytes()[0];
        carry = total >> 8;
    }
    let mut index = width;
    while carry != 0 {
        index = if index == 0 { width } else { index } - 1;
        let total = u16::from(sum[index]) + carry;
        sum[index] = total.to_le_bytes()[0];
        carry = total >> 8;
    }
}

const fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

fn aes_decrypt_block(cipher: &Aes256, block: &[u8]) -> [u8; BLOCK] {
    let mut buffer = GenericArray::clone_from_slice(block);
    cipher.decrypt_block(&mut buffer);
    buffer.into()
}

fn xor(a: [u8; BLOCK], b: &[u8]) -> [u8; BLOCK] {
    let mut out = a;
    for (byte, other) in out.iter_mut().zip(b) {
        *byte ^= other;
    }
    out
}

/// CBC decryption with ciphertext stealing, RFC 3962, IV of zero.
fn cbc_cts_decrypt(cipher: &Aes256, data: &[u8]) -> Result<Vec<u8>, AuthenticateError> {
    let length = data.len();
    if length < BLOCK {
        return Err(AuthenticateError::new(
            "the Kerberos ciphertext is shorter than one block",
        ));
    }
    if length == BLOCK {
        return Ok(aes_decrypt_block(cipher, data).to_vec());
    }

    let blocks = length.div_ceil(BLOCK);
    let last = if length.is_multiple_of(BLOCK) {
        BLOCK
    } else {
        length % BLOCK
    };
    let mut ordered: Vec<[u8; BLOCK]> = Vec::with_capacity(blocks);
    for index in 0..blocks - 2 {
        let mut block = [0u8; BLOCK];
        block.copy_from_slice(&data[index * BLOCK..index * BLOCK + BLOCK]);
        ordered.push(block);
    }

    let penultimate = &data[(blocks - 2) * BLOCK..(blocks - 2) * BLOCK + BLOCK];
    let mut penultimate_block = [0u8; BLOCK];
    penultimate_block.copy_from_slice(penultimate);
    let truncated = &data[(blocks - 1) * BLOCK..(blocks - 1) * BLOCK + last];

    let recovered = aes_decrypt_block(cipher, &penultimate_block);
    let mut second_to_last = [0u8; BLOCK];
    second_to_last[..last].copy_from_slice(truncated);
    second_to_last[last..].copy_from_slice(&recovered[last..]);
    ordered.push(second_to_last);
    ordered.push(penultimate_block);

    let mut previous = [0u8; BLOCK];
    let mut plaintext = Vec::with_capacity(blocks * BLOCK);
    for block in &ordered {
        plaintext.extend_from_slice(&xor(aes_decrypt_block(cipher, block), &previous));
        previous = *block;
    }
    plaintext.truncate(length);
    Ok(plaintext)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The inverse of [`cbc_cts_decrypt`], to mint a ticket in a test.
    fn cbc_cts_encrypt(cipher: &Aes256, plaintext: &[u8]) -> Vec<u8> {
        let length = plaintext.len();
        let encrypt = |block: [u8; BLOCK]| {
            let mut buffer = GenericArray::from(block);
            cipher.encrypt_block(&mut buffer);
            <[u8; BLOCK]>::from(buffer)
        };
        if length == BLOCK {
            return encrypt(plaintext.try_into().expect("a block")).to_vec();
        }
        let blocks = length.div_ceil(BLOCK);
        let last = if length.is_multiple_of(BLOCK) {
            BLOCK
        } else {
            length % BLOCK
        };
        let mut encrypted: Vec<[u8; BLOCK]> = Vec::with_capacity(blocks);
        let mut previous = [0u8; BLOCK];
        for index in 0..blocks {
            let mut block = [0u8; BLOCK];
            let start = index * BLOCK;
            let end = (start + BLOCK).min(length);
            block[..end - start].copy_from_slice(&plaintext[start..end]);
            let cipher_block = encrypt(super::xor(block, &previous));
            encrypted.push(cipher_block);
            previous = cipher_block;
        }
        let mut out = Vec::with_capacity(length);
        for block in &encrypted[..blocks - 2] {
            out.extend_from_slice(block);
        }
        out.extend_from_slice(&encrypted[blocks - 1]);
        out.extend_from_slice(&encrypted[blocks - 2][..last]);
        out
    }

    /// Seal a plaintext as an etype-18 message would be, for a test ticket.
    pub(crate) fn encrypt(
        base_key: &[u8],
        usage: u32,
        confounder: [u8; 16],
        data: &[u8],
    ) -> Vec<u8> {
        let cipher = super::cipher(base_key).expect("a key");
        let ke = derive(&cipher, usage, 0xAA).expect("Ke");
        let ki = derive(&cipher, usage, 0x55).expect("Ki");
        let mut plaintext = confounder.to_vec();
        plaintext.extend_from_slice(data);
        let mut message = cbc_cts_encrypt(&super::cipher(&ke).expect("Ke"), &plaintext);
        message.extend_from_slice(&super::hmac_sha1(&ki, &plaintext)[..MAC_LENGTH]);
        message
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write;
        bytes.iter().fold(String::new(), |mut text, byte| {
            write!(text, "{byte:02x}").expect("a String takes writes");
            text
        })
    }

    #[test]
    fn n_fold_matches_the_rfc_3961_vector() {
        // RFC 3961 Appendix A: 64-fold("012345") = be072631276b1955.
        assert_eq!(hex(&n_fold(b"012345", 8)), "be072631276b1955");
        // 56-fold("password") = 78a07b6caf85fa.
        assert_eq!(hex(&n_fold(b"password", 7)), "78a07b6caf85fa");
    }

    #[test]
    fn ciphertext_stealing_is_its_own_inverse_at_every_length() {
        let cipher = super::cipher(&[7u8; 32]).expect("a key");
        for length in [16usize, 17, 31, 32, 33, 48, 61] {
            let plaintext: Vec<u8> = (0..length)
                .map(|byte| u8::try_from(byte).unwrap_or(0))
                .collect();
            let ciphertext = cbc_cts_encrypt(&cipher, &plaintext);

            assert_eq!(ciphertext.len(), length);
            assert_eq!(
                cbc_cts_decrypt(&cipher, &ciphertext).expect("plain"),
                plaintext
            );
        }
    }

    #[test]
    fn a_message_sealed_under_a_key_decrypts_under_the_same_key() {
        let key = [9u8; 32];
        let message = encrypt(&key, TICKET_KEY_USAGE, [3u8; 16], b"the sealed ticket part");

        let plaintext = decrypt(&key, TICKET_KEY_USAGE, &message).expect("plain");

        assert_eq!(plaintext, b"the sealed ticket part");
    }

    #[test]
    fn a_message_sealed_under_another_key_fails_its_checksum() {
        let message = encrypt(&[9u8; 32], TICKET_KEY_USAGE, [3u8; 16], b"secret");

        let failure = decrypt(&[1u8; 32], TICKET_KEY_USAGE, &message).expect_err("refused");

        assert!(failure.message.contains("checksum does not match"));
    }

    #[test]
    fn a_password_and_salt_derive_a_thirty_two_byte_key() {
        let key = string_to_key(b"correct horse", b"EXAMPLE.COMalice", 4096).expect("a key");
        let same = string_to_key(b"correct horse", b"EXAMPLE.COMalice", 4096).expect("a key");
        let other = string_to_key(b"battery staple", b"EXAMPLE.COMalice", 4096).expect("a key");

        assert_eq!(key.len(), 32);
        assert_eq!(key, same);
        assert_ne!(key, other);
    }
}
