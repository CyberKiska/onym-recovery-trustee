//! SLIP-0039 single-share validation for the Onym Shamir profile.
//!
//! One share only: word list, RS1024 checksum, padding and the profile's
//! fixed parameters. There is deliberately no interpolation, splitting,
//! combining, PBKDF2 or Feistel code here; a trustee never reconstructs.
//!
//! `wordlist.txt` is the SLIP-0039 word list as shipped by the MIT-licensed
//! Trezor reference implementation (python-shamir-mnemonic, © 2019
//! SatoshiLabs), byte-identical to the list in the SLIP-0039 specification.

use std::sync::LazyLock;

use zeroize::Zeroizing;

/// A 256-bit master secret gives 33 words: 7 of metadata and checksum, 26
/// carrying 4 padding bits plus the 256-bit share value.
const WORD_COUNT: usize = 33;
/// The longest list word has 8 letters, so 33 words with single spaces
/// never exceed this.
const MAX_MNEMONIC_BYTES: usize = WORD_COUNT * 8 + (WORD_COUNT - 1);

static WORDLIST: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| include_str!("wordlist.txt").lines().collect());

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareError {
    /// Not a SLIP-0039 share: length, word, checksum or padding.
    Malformed,
    /// A well-formed share outside the Onym profile.
    Unsupported,
}

/// Every metadata field of one share, as the specification names them.
/// Thresholds and counts are actual values, not their stored `value - 1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fields {
    pub identifier: u16,
    pub extendable: bool,
    pub iteration_exponent: u8,
    pub group_index: u8,
    pub group_threshold: u8,
    pub group_count: u8,
    pub member_index: u8,
    pub member_threshold: u8,
}

/// What the envelope checks a profile-valid share against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Share {
    pub member_index: u8,
    pub member_threshold: u8,
}

/// Validate one share in canonical form (33 lowercase words, single spaces)
/// against the profile: 256-bit, not extendable, exponent 0, one group,
/// member threshold at least 2.
pub fn validate(mnemonic: &str) -> Result<Share, ShareError> {
    let fields = decode(mnemonic)?;
    let in_profile = !fields.extendable
        && fields.iteration_exponent == 0
        && fields.group_index == 0
        && fields.group_threshold == 1
        && fields.group_count == 1
        && fields.member_threshold >= 2;
    if !in_profile {
        return Err(ShareError::Unsupported);
    }
    Ok(Share {
        member_index: fields.member_index,
        member_threshold: fields.member_threshold,
    })
}

/// Decode a 33-word share, checking only what makes it a share at all.
/// No trimming, case folding, prefix matching or correction: anything but
/// exact list words joined by single spaces is malformed.
pub fn decode(mnemonic: &str) -> Result<Fields, ShareError> {
    if mnemonic.len() > MAX_MNEMONIC_BYTES {
        return Err(ShareError::Malformed);
    }
    let mut indices = Zeroizing::new([0u16; WORD_COUNT]);
    let mut words = mnemonic.split(' ');
    for index in indices.iter_mut() {
        let word = words.next().ok_or(ShareError::Malformed)?;
        let position = WORDLIST
            .binary_search(&word)
            .map_err(|_| ShareError::Malformed)?;
        *index = position as u16;
    }
    if words.next().is_some() {
        return Err(ShareError::Malformed);
    }

    // Words 0-1: identifier (15 bits), extendable flag, iteration exponent.
    let id_exp = (u32::from(indices[0]) << 10) | u32::from(indices[1]);
    let extendable = (id_exp >> 4) & 1 == 1;
    let customization: &[u8] = if extendable {
        b"shamir_extendable"
    } else {
        b"shamir"
    };
    if rs1024_polymod(customization, &indices[..]) != 1 {
        return Err(ShareError::Malformed);
    }
    // The share value is left-padded to a multiple of 10 bits; the 4
    // padding bits sit at the top of word 4 and must be zero.
    if indices[4] >> 6 != 0 {
        return Err(ShareError::Malformed);
    }

    // Words 2-3: five 4-bit fields.
    let params = (u32::from(indices[2]) << 10) | u32::from(indices[3]);
    let nibble = |shift: u32| ((params >> shift) & 0xF) as u8;
    Ok(Fields {
        identifier: (id_exp >> 5) as u16,
        extendable,
        iteration_exponent: (id_exp & 0xF) as u8,
        group_index: nibble(16),
        group_threshold: nibble(12) + 1,
        group_count: nibble(8) + 1,
        member_index: nibble(4),
        member_threshold: nibble(0) + 1,
    })
}

/// RS1024 over GF(1024), as in the specification: valid shares give 1.
fn rs1024_polymod(customization: &[u8], indices: &[u16]) -> u32 {
    const GENERATOR: [u32; 10] = [
        0xE0E040, 0x1C1C080, 0x3838100, 0x7070200, 0xE0E0009, 0x1C0C2412, 0x38086C24, 0x3090FC48,
        0x21B1F890, 0x3F3F120,
    ];
    let values = customization
        .iter()
        .map(|&b| u32::from(b))
        .chain(indices.iter().map(|&i| u32::from(i)));
    let mut checksum = 1u32;
    for value in values {
        let top = checksum >> 20;
        checksum = ((checksum & 0xFFFFF) << 10) ^ value;
        for (bit, generator) in GENERATOR.iter().enumerate() {
            if (top >> bit) & 1 == 1 {
                checksum ^= generator;
            }
        }
    }
    checksum
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn wordlist_is_the_pinned_reference_list() {
        let digest = Sha256::digest(include_bytes!("wordlist.txt"));
        assert_eq!(
            hex::encode(digest),
            "bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3"
        );
        assert_eq!(WORDLIST.len(), 1024);
        assert!(
            WORDLIST.windows(2).all(|pair| pair[0] < pair[1]),
            "binary search needs sorted words"
        );
        assert!(WORDLIST.iter().all(|word| word.len() <= 8));
    }

    #[test]
    fn refuses_empty_and_oversized_input() {
        assert_eq!(decode(""), Err(ShareError::Malformed));
        assert_eq!(decode(&"academic ".repeat(40)), Err(ShareError::Malformed));
    }
}
