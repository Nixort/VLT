// Copyright Nixort & Itan Winter <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 or later.

//! A deliberately narrow deterministic CBOR encoder and decoder for Manifests.
//!
//! The writer emits one definite-length integer-keyed map. The reader accepts
//! only that exact shape, rejects duplicate or unknown keys and verifies
//! shortest-form unsigned integers. This is intentionally smaller than a
//! general CBOR implementation because a VLT/1 Manifest has no need for one.

use crate::{
    error::{Result, VaultError},
    format::{Manifest, ObjectId, VersionId},
};

const MAP_FIELDS: u8 = 8;

/// Encodes a Manifest into the VLT/1 canonical deterministic representation.
#[must_use]
pub fn encode_manifest(manifest: &Manifest) -> Vec<u8> {
    let mut output = Vec::with_capacity(128);
    output.push(0xa0 | MAP_FIELDS);
    put_uint(&mut output, 1, u64::from(manifest.format_version));
    put_bytes(&mut output, 2, manifest.object_id.as_bytes());
    put_bytes(&mut output, 3, manifest.version_id.as_bytes());
    put_uint(&mut output, 4, manifest.plaintext_len);
    put_uint(&mut output, 5, u64::from(manifest.chunk_size));
    put_uint(&mut output, 6, u64::from(manifest.chunk_count));
    put_bytes(&mut output, 7, &manifest.chunk_digest);
    put_uint(&mut output, 8, 1);
    output
}

/// Decodes and validates the exact VLT/1 Manifest representation.
///
/// # Errors
///
/// Returns [`VaultError::InvalidFormat`] when the input is truncated,
/// non-canonical, malformed or does not match the VLT/1 Manifest profile.
pub fn decode_manifest(input: &[u8]) -> Result<Manifest> {
    let mut decoder = Decoder::new(input);
    let initial = decoder.take()?;
    if initial != (0xa0 | MAP_FIELDS) {
        return Err(VaultError::invalid_format(
            "manifest must be an eight-field map",
        ));
    }

    let mut format_version = None;
    let mut object_id = None;
    let mut version_id = None;
    let mut plaintext_len = None;
    let mut chunk_size = None;
    let mut chunk_count = None;
    let mut chunk_digest = None;

    for expected_key in 1..=MAP_FIELDS {
        let key = decoder.read_uint()?;
        if key != u64::from(expected_key) {
            return Err(VaultError::invalid_format(
                "manifest keys must be ordered and unique",
            ));
        }
        match key {
            1 => {
                let value = decoder.read_uint()?;
                format_version = Some(
                    u32::try_from(value)
                        .map_err(|_| VaultError::invalid_format("format version exceeds u32"))?,
                );
            }
            2 => object_id = Some(ObjectId::from_slice(decoder.read_bytes_exact(16)?)?),
            3 => version_id = Some(VersionId::from_slice(decoder.read_bytes_exact(16)?)?),
            4 => plaintext_len = Some(decoder.read_uint()?),
            5 => {
                let value = decoder.read_uint()?;
                chunk_size = Some(
                    u32::try_from(value)
                        .map_err(|_| VaultError::invalid_format("chunk size exceeds u32"))?,
                );
            }
            6 => {
                let value = decoder.read_uint()?;
                chunk_count = Some(
                    u32::try_from(value)
                        .map_err(|_| VaultError::invalid_format("chunk count exceeds u32"))?,
                );
            }
            7 => {
                let bytes = decoder.read_bytes_exact(32)?;
                let mut digest = [0u8; 32];
                digest.copy_from_slice(bytes);
                chunk_digest = Some(digest);
            }
            8 => {
                if decoder.read_uint()? != 1 {
                    return Err(VaultError::invalid_format(
                        "manifest profile marker is invalid",
                    ));
                }
            }
            _ => unreachable!("keys are bounded by MAP_FIELDS"),
        }
    }

    if !decoder.finished() {
        return Err(VaultError::invalid_format("trailing manifest bytes"));
    }

    Ok(Manifest {
        format_version: format_version
            .ok_or(VaultError::invalid_format("missing format version"))?,
        object_id: object_id.ok_or(VaultError::invalid_format("missing object ID"))?,
        version_id: version_id.ok_or(VaultError::invalid_format("missing version ID"))?,
        plaintext_len: plaintext_len
            .ok_or(VaultError::invalid_format("missing plaintext length"))?,
        chunk_size: chunk_size.ok_or(VaultError::invalid_format("missing chunk size"))?,
        chunk_count: chunk_count.ok_or(VaultError::invalid_format("missing chunk count"))?,
        chunk_digest: chunk_digest.ok_or(VaultError::invalid_format("missing chunk digest"))?,
    })
}

fn put_uint(output: &mut Vec<u8>, key: u8, value: u64) {
    output.push(key);
    put_major_uint(output, 0, value);
}

fn put_bytes(output: &mut Vec<u8>, key: u8, bytes: &[u8]) {
    output.push(key);
    let length = u64::try_from(bytes.len()).expect("usize length must fit in u64");
    put_major_uint(output, 2, length);
    output.extend_from_slice(bytes);
}

fn put_major_uint(output: &mut Vec<u8>, major: u8, value: u64) {
    let bytes = value.to_be_bytes();
    match value {
        0..=0x17 => output.push((major << 5) | bytes[7]),
        0x18..=0xff => output.extend_from_slice(&[(major << 5) | 0x18, bytes[7]]),
        0x100..=0xffff => {
            output.push((major << 5) | 0x19);
            output.extend_from_slice(&bytes[6..]);
        }
        0x1_0000..=0xffff_ffff => {
            output.push((major << 5) | 0x1a);
            output.extend_from_slice(&bytes[4..]);
        }
        _ => {
            output.push((major << 5) | 0x1b);
            output.extend_from_slice(&bytes);
        }
    }
}

struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn take(&mut self) -> Result<u8> {
        let value = *self
            .input
            .get(self.offset)
            .ok_or(VaultError::invalid_format("truncated manifest"))?;
        self.offset += 1;
        Ok(value)
    }

    fn read_uint(&mut self) -> Result<u64> {
        self.read_major_uint(0)
    }

    fn read_bytes_exact(&mut self, expected_len: usize) -> Result<&'a [u8]> {
        let len = self.read_major_uint(2)?;
        let len = usize::try_from(len)
            .map_err(|_| VaultError::invalid_format("byte string length exceeds usize"))?;
        if len != expected_len {
            return Err(VaultError::invalid_format("unexpected byte string length"));
        }
        let end = self
            .offset
            .checked_add(len)
            .ok_or(VaultError::invalid_format("byte string length overflow"))?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(VaultError::invalid_format("truncated byte string"))?;
        self.offset = end;
        Ok(bytes)
    }

    fn read_major_uint(&mut self, expected_major: u8) -> Result<u64> {
        let initial = self.take()?;
        if initial >> 5 != expected_major {
            return Err(VaultError::invalid_format("unexpected CBOR major type"));
        }
        let additional = initial & 0x1f;
        let value = match additional {
            0..=23 => u64::from(additional),
            24 => u64::from(self.take()?),
            25 => {
                let bytes: [u8; 2] = self.read_fixed()?;
                u64::from(u16::from_be_bytes(bytes))
            }
            26 => {
                let bytes: [u8; 4] = self.read_fixed()?;
                u64::from(u32::from_be_bytes(bytes))
            }
            27 => {
                let bytes: [u8; 8] = self.read_fixed()?;
                u64::from_be_bytes(bytes)
            }
            _ => {
                return Err(VaultError::invalid_format(
                    "indefinite or reserved CBOR length",
                ))
            }
        };
        if canonical_additional(value) != additional {
            return Err(VaultError::invalid_format("non-canonical integer encoding"));
        }
        Ok(value)
    }

    fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(VaultError::invalid_format("fixed read overflow"))?;
        let bytes: [u8; N] = self
            .input
            .get(self.offset..end)
            .ok_or(VaultError::invalid_format("truncated integer"))?
            .try_into()
            .map_err(|_| VaultError::invalid_format("invalid fixed integer"))?;
        self.offset = end;
        Ok(bytes)
    }

    const fn finished(&self) -> bool {
        self.offset == self.input.len()
    }
}

const fn canonical_additional(value: u64) -> u8 {
    if value <= 0x17 {
        value.to_be_bytes()[7]
    } else if value <= 0xff {
        0x18
    } else if value <= 0xffff {
        0x19
    } else if value <= 0xffff_ffff {
        0x1a
    } else {
        0x1b
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{decode_manifest, encode_manifest};
    use crate::format::{Manifest, ObjectId, VersionId, FORMAT_VERSION};

    fn sample_manifest() -> Manifest {
        Manifest {
            format_version: FORMAT_VERSION,
            object_id: ObjectId::from_slice(&[1u8; 16]).expect("valid object ID"),
            version_id: VersionId::from_slice(&[2u8; 16]).expect("valid version ID"),
            plaintext_len: 1024,
            chunk_size: 512,
            chunk_count: 2,
            chunk_digest: [3u8; 32],
        }
    }

    #[test]
    fn canonical_manifest_bytes_match_the_fixed_wire_vector() {
        let manifest = Manifest {
            format_version: 1,
            object_id: ObjectId::from_slice(&(0u8..16).collect::<Vec<_>>())
                .expect("fixed object ID"),
            version_id: VersionId::from_slice(&(16u8..32).collect::<Vec<_>>())
                .expect("fixed version ID"),
            plaintext_len: 0x0102,
            chunk_size: 4096,
            chunk_count: 2,
            chunk_digest: [0xa5; 32],
        };
        let expected = [
            &[0xa8, 0x01, 0x01, 0x02, 0x50][..],
            &(0u8..16).collect::<Vec<_>>(),
            &[0x03, 0x50][..],
            &(16u8..32).collect::<Vec<_>>(),
            &[
                0x04, 0x19, 0x01, 0x02, 0x05, 0x19, 0x10, 0x00, 0x06, 0x02, 0x07, 0x58, 0x20,
            ][..],
            &[0xa5; 32],
            &[0x08, 0x01][..],
        ]
        .concat();

        assert_eq!(encode_manifest(&manifest), expected);
        assert_eq!(
            decode_manifest(&expected).expect("decode fixed vector"),
            manifest
        );
    }

    #[test]
    fn manifest_encoding_is_deterministic_and_round_trips() {
        let manifest = sample_manifest();
        let encoded_once = encode_manifest(&manifest);
        let encoded_twice = encode_manifest(&manifest);
        assert_eq!(encoded_once, encoded_twice);
        assert_eq!(
            decode_manifest(&encoded_once).expect("decode manifest"),
            manifest
        );
    }

    proptest! {
        #[test]
        fn canonical_encoding_round_trips_arbitrary_manifest_fields(
            format_version in any::<u32>(),
            object_id in any::<[u8; 16]>(),
            version_id in any::<[u8; 16]>(),
            plaintext_len in any::<u64>(),
            chunk_size in any::<u32>(),
            chunk_count in any::<u32>(),
            chunk_digest in any::<[u8; 32]>(),
        ) {
            let manifest = Manifest {
                format_version,
                object_id: ObjectId::from_slice(&object_id).expect("fixed object ID"),
                version_id: VersionId::from_slice(&version_id).expect("fixed version ID"),
                plaintext_len,
                chunk_size,
                chunk_count,
                chunk_digest,
            };
            let encoded = encode_manifest(&manifest);
            prop_assert_eq!(decode_manifest(&encoded).expect("decode encoded manifest"), manifest);
        }
    }

    #[test]
    fn manifest_rejects_non_canonical_integer_encoding() {
        let manifest = sample_manifest();
        let mut encoded = encode_manifest(&manifest);
        // Change the map field count from canonical 8 to a non-matching form.
        encoded[0] = 0xb8;
        assert!(decode_manifest(&encoded).is_err());
    }
}
