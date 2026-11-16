// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::Ext4;
use crate::checksum::Checksum;
use crate::error::{CorruptKind, Ext4Error};
use crate::format::format_bytes_debug;
use crate::inode::{Inode, InodeIndex};
use crate::util::{read_u16le, read_u32le, usize_from_u32};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{self, Debug, Formatter};

/// Magic number at the start of an extended attribute block, and at the
/// start of the extended attribute area within an inode.
const XATTR_MAGIC: u32 = 0xea02_0000;

/// Size in bytes of the header at the start of an extended attribute
/// block.
const BLOCK_HEADER_SIZE: usize = 32;

/// Offset of the `h_checksum` field within the block header.
const BLOCK_CHECKSUM_OFFSET: usize = 0x10;

/// Size in bytes of the fixed part of an entry, before the name.
const ENTRY_HEADER_SIZE: usize = 16;

/// Size in bytes of the inode fields present in every inode. Larger
/// inodes have additional fields after these, followed by space for
/// extended attributes.
const GOOD_OLD_INODE_SIZE: usize = 128;

/// An extended attribute.
///
/// Extended attributes are name/value pairs associated with a file. See
/// [xattr(7)][xattr] for more details.
///
/// [xattr]: https://www.man7.org/linux/man-pages/man7/xattr.7.html
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Xattr {
    name: Vec<u8>,
    value: Vec<u8>,
}

impl Xattr {
    /// Get the attribute's full name, including its namespace prefix.
    ///
    /// For example: `user.comment` or `security.capability`.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Get the attribute's value.
    ///
    /// The value is returned exactly as it is stored on disk. For most
    /// attributes this matches what the Linux kernel returns from
    /// [getxattr(2)][getxattr], but the kernel converts some attributes
    /// in the `system.` namespace. In particular, POSIX ACLs
    /// (`system.posix_acl_access` and `system.posix_acl_default`) are
    /// stored in a more compact format than the kernel's
    /// `posix_acl_xattr` format.
    ///
    /// [getxattr]: https://www.man7.org/linux/man-pages/man2/getxattr.2.html
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

impl Debug for Xattr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        struct Bytes<'a>(&'a [u8]);

        impl Debug for Bytes<'_> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                format_bytes_debug(self.0, f)
            }
        }

        f.debug_struct("Xattr")
            .field("name", &Bytes(&self.name))
            .field("value", &Bytes(&self.value))
            .finish()
    }
}

/// Get the name prefix for an entry's `e_name_index` field.
///
/// Returns `None` for unknown indices. Index 9 (the fscrypt
/// encryption context) is intentionally unknown; like the Linux
/// kernel, this library does not expose it as an attribute.
fn name_prefix(name_index: u8) -> Option<&'static [u8]> {
    match name_index {
        0 => Some(b""),
        1 => Some(b"user."),
        2 => Some(b"system.posix_acl_access"),
        3 => Some(b"system.posix_acl_default"),
        4 => Some(b"trusted."),
        5 => Some(b"lustre."),
        6 => Some(b"security."),
        7 => Some(b"system."),
        8 => Some(b"system.richacl"),
        10 => Some(b"gnu."),
        _ => None,
    }
}

/// Parse a table of extended attribute entries and append the
/// attributes to `xattrs`.
///
/// `entries` starts with the first entry. The table must end with four
/// zero bytes. Each entry's value offset is relative to the start of
/// `values`.
fn parse_entries(
    inode: InodeIndex,
    entries: &[u8],
    values: &[u8],
    xattrs: &mut Vec<Xattr>,
) -> Result<(), Ext4Error> {
    let err = || Ext4Error::from(CorruptKind::XattrEntry(inode));

    let mut rest = entries;
    loop {
        let terminator = rest.get(..4).ok_or_else(err)?;
        if terminator == [0; 4] {
            return Ok(());
        }

        let header = rest.get(..ENTRY_HEADER_SIZE).ok_or_else(err)?;
        let e_name_len = header[0];
        let e_name_index = header[1];
        let e_value_offs = read_u16le(header, 0x2);
        let e_value_inum = read_u32le(header, 0x4);
        let e_value_size = read_u32le(header, 0x8);

        // Values stored in a separate inode require the `ea_inode`
        // feature, which is rejected when loading the filesystem.
        if e_value_inum != 0 {
            return Err(err());
        }

        // OK to unwrap: `ENTRY_HEADER_SIZE` is 16 and `e_name_len` is at
        // most 255.
        let name_end = ENTRY_HEADER_SIZE
            .checked_add(usize::from(e_name_len))
            .unwrap();
        let name = rest.get(ENTRY_HEADER_SIZE..name_end).ok_or_else(err)?;

        let value_start = usize::from(e_value_offs);
        let value_end = value_start
            .checked_add(usize_from_u32(e_value_size))
            .ok_or_else(err)?;
        let value = values.get(value_start..value_end).ok_or_else(err)?;

        if let Some(prefix) = name_prefix(e_name_index) {
            xattrs.push(Xattr {
                name: [prefix, name].concat(),
                value: value.to_vec(),
            });
        }

        // Entries are padded to a multiple of four bytes. OK to unwrap:
        // `name_end` is at most 271.
        let entry_len = name_end.checked_next_multiple_of(4).unwrap();
        rest = rest.get(entry_len..).ok_or_else(err)?;
    }
}

/// Parse the extended attributes stored in the raw inode `data`.
fn parse_inode_body(
    inode: InodeIndex,
    data: &[u8],
    xattrs: &mut Vec<Xattr>,
) -> Result<(), Ext4Error> {
    // Inodes of the original size have no space for attributes.
    if data.len() <= GOOD_OLD_INODE_SIZE {
        return Ok(());
    }
    let extra = &data[GOOD_OLD_INODE_SIZE..];

    // The `i_extra_isize` field holds the size of the additional
    // inode fields. The attribute area starts after those fields.
    let err = || Ext4Error::from(CorruptKind::InodeExtraSize(inode));
    let i_extra_isize =
        usize::from(read_u16le(extra.get(..2).ok_or_else(err)?, 0));
    if i_extra_isize % 4 != 0 {
        return Err(err());
    }
    let area = extra.get(i_extra_isize..).ok_or_else(err)?;

    // If the area does not start with the magic number, there are no
    // attributes stored in the inode.
    match area.get(4..) {
        Some(entries) if read_u32le(area, 0) == XATTR_MAGIC => {
            // Value offsets are relative to the first entry.
            parse_entries(inode, entries, entries, xattrs)
        }
        _ => Ok(()),
    }
}

/// Read the extended attributes stored in the inode's attribute block.
fn read_block_xattrs(
    ext4: &Ext4,
    inode: &Inode,
    xattrs: &mut Vec<Xattr>,
) -> Result<(), Ext4Error> {
    let block_index = inode.xattr_block;
    let mut block = vec![0; ext4.0.superblock.block_size.to_usize()];
    ext4.read_from_block(block_index, 0, &mut block)?;

    let h_magic = read_u32le(&block, 0x0);
    let h_blocks = read_u32le(&block, 0x8);
    if h_magic != XATTR_MAGIC || h_blocks != 1 {
        return Err(CorruptKind::XattrBlockHeader(inode.index).into());
    }

    if ext4.has_metadata_checksums() {
        let expected_checksum = read_u32le(&block, BLOCK_CHECKSUM_OFFSET);

        // The checksum covers the block index and the whole block, with
        // the checksum field treated as zero.
        let mut checksum = Checksum::with_seed(ext4.0.superblock.checksum_seed);
        checksum.update(&block_index.to_le_bytes());
        checksum.update(&block[..BLOCK_CHECKSUM_OFFSET]);
        checksum.update_u32_le(0);
        checksum.update(&block[BLOCK_CHECKSUM_OFFSET + 4..]);

        if checksum.finalize() != expected_checksum {
            return Err(CorruptKind::XattrBlockChecksum(inode.index).into());
        }
    }

    // Value offsets are relative to the start of the block.
    parse_entries(inode.index, &block[BLOCK_HEADER_SIZE..], &block, xattrs)
}

/// Read all extended attributes of an inode.
pub(crate) fn read_xattrs(
    ext4: &Ext4,
    inode: &Inode,
) -> Result<Vec<Xattr>, Ext4Error> {
    let mut xattrs = Vec::new();
    let data = Inode::read_bytes(ext4, inode.index)?;
    parse_inode_body(inode.index, &data, &mut xattrs)?;
    if inode.xattr_block != 0 {
        read_block_xattrs(ext4, inode, &mut xattrs)?;
    }
    Ok(xattrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INODE: InodeIndex = InodeIndex::new(12).unwrap();

    /// Create an entry header with no value inode and a zero hash.
    fn entry(
        name_index: u8,
        name: &[u8],
        value_offs: u16,
        value_size: u32,
    ) -> Vec<u8> {
        let mut bytes = vec![u8::try_from(name.len()).unwrap(), name_index];
        bytes.extend(value_offs.to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        bytes.extend(value_size.to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        bytes.extend(name);
        while bytes.len() % 4 != 0 {
            bytes.push(0);
        }
        bytes
    }

    fn xattr(name: &[u8], value: &[u8]) -> Xattr {
        Xattr {
            name: name.to_vec(),
            value: value.to_vec(),
        }
    }

    fn parse(entries: &[u8], values: &[u8]) -> Result<Vec<Xattr>, Ext4Error> {
        let mut xattrs = Vec::new();
        parse_entries(INODE, entries, values, &mut xattrs)?;
        Ok(xattrs)
    }

    #[test]
    fn test_parse_entries() {
        let mut entries = entry(1, b"abc", 0, 2);
        entries.extend(entry(6, b"capability", 2, 3));
        // Unknown name index, skipped.
        entries.extend(entry(9, b"c", 0, 1));
        entries.extend(entry(2, b"", 5, 0));
        entries.extend([0; 4]);
        let values = b"xyz12";

        assert_eq!(
            parse(&entries, values).unwrap(),
            [
                xattr(b"user.abc", b"xy"),
                xattr(b"security.capability", b"z12"),
                xattr(b"system.posix_acl_access", b""),
            ]
        );

        // Empty table.
        assert_eq!(parse(&[0; 4], &[]).unwrap(), []);
    }

    #[test]
    fn test_parse_entries_errors() {
        let err = CorruptKind::XattrEntry(INODE);

        // Missing terminator.
        assert_eq!(parse(&[], &[]).unwrap_err(), err);
        assert_eq!(parse(&entry(1, b"a", 0, 0), &[]).unwrap_err(), err);

        // Truncated entry header.
        assert_eq!(parse(&[1, 1, 0, 0, 0, 0], &[]).unwrap_err(), err);

        // Truncated name.
        let mut entries = entry(1, b"abcd", 0, 0);
        entries.truncate(ENTRY_HEADER_SIZE + 2);
        assert_eq!(parse(&entries, &[]).unwrap_err(), err);

        // Value out of bounds.
        let mut entries = entry(1, b"a", 1, 2);
        entries.extend([0; 4]);
        assert_eq!(parse(&entries, b"ab").unwrap_err(), err);

        // Value size overflows.
        let mut entries = entry(1, b"a", 1, u32::MAX);
        entries.extend([0; 4]);
        assert_eq!(parse(&entries, b"ab").unwrap_err(), err);

        // Value stored in a separate inode.
        let mut entries = entry(1, b"a", 0, 0);
        entries[4] = 1;
        entries.extend([0; 4]);
        assert_eq!(parse(&entries, &[]).unwrap_err(), err);
    }

    /// Create a 256-byte inode with `i_extra_isize` set to 32, followed
    /// by `body`.
    fn inode_with_body(body: &[u8]) -> Vec<u8> {
        let mut data = vec![0; 256];
        data[0x80..0x82].copy_from_slice(&32u16.to_le_bytes());
        data[160..160 + body.len()].copy_from_slice(body);
        data
    }

    fn parse_inode(data: &[u8]) -> Result<Vec<Xattr>, Ext4Error> {
        let mut xattrs = Vec::new();
        parse_inode_body(INODE, data, &mut xattrs)?;
        Ok(xattrs)
    }

    #[test]
    fn test_parse_inode_body() {
        // Value offsets are relative to the first entry.
        let mut body = XATTR_MAGIC.to_le_bytes().to_vec();
        body.extend(entry(1, b"a", 24, 2));
        body.extend([0; 4]);
        body.extend(b"vv");
        assert_eq!(
            parse_inode(&inode_with_body(&body)).unwrap(),
            [xattr(b"user.a", b"vv")]
        );

        // No magic, so no attributes.
        assert_eq!(parse_inode(&inode_with_body(&[])).unwrap(), []);

        // Inode too small to hold attributes.
        assert_eq!(parse_inode(&[0; 128]).unwrap(), []);

        // Attribute area too small to hold the magic.
        let mut data = vec![0; 256];
        data[0x80..0x82].copy_from_slice(&128u16.to_le_bytes());
        assert_eq!(parse_inode(&data).unwrap(), []);
    }

    #[test]
    fn test_parse_inode_body_errors() {
        let err = CorruptKind::InodeExtraSize(INODE);

        // `i_extra_isize` is not a multiple of four.
        let mut data = vec![0; 256];
        data[0x80..0x82].copy_from_slice(&30u16.to_le_bytes());
        assert_eq!(parse_inode(&data).unwrap_err(), err);

        // `i_extra_isize` is larger than the inode.
        data[0x80..0x82].copy_from_slice(&132u16.to_le_bytes());
        assert_eq!(parse_inode(&data).unwrap_err(), err);

        // Inode too small to hold `i_extra_isize`.
        assert_eq!(parse_inode(&[0; 129]).unwrap_err(), err);

        // Invalid entry.
        let mut body = XATTR_MAGIC.to_le_bytes().to_vec();
        body.extend(entry(1, b"a", 200, 2));
        body.extend([0; 4]);
        assert_eq!(
            parse_inode(&inode_with_body(&body)).unwrap_err(),
            CorruptKind::XattrEntry(INODE)
        );
    }

    /// Load the xattrs test disk, modify the attribute block of
    /// `/block_xattr` with `modify`, then read the file's attributes.
    #[cfg(feature = "std")]
    fn read_modified_block(
        modify: impl FnOnce(&mut [u8]),
    ) -> Result<Vec<Xattr>, Ext4Error> {
        use crate::path::Path;
        use crate::resolve::FollowSymlinks;
        use alloc::boxed::Box;

        let mut data =
            crate::test_util::load_compressed_data("test_disk_xattrs.bin.zst");
        let fs = Ext4::load(Box::new(data.clone())).unwrap();
        let inode = fs
            .path_to_inode(Path::new("/block_xattr"), FollowSymlinks::All)
            .unwrap();
        let block_size = fs.0.superblock.block_size.to_usize();
        let start = usize::try_from(inode.xattr_block).unwrap() * block_size;
        modify(&mut data[start..start + block_size]);

        let fs = Ext4::load(Box::new(data)).unwrap();
        fs.xattrs("/block_xattr")
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_block_errors() {
        let inode = InodeIndex::new(14).unwrap();

        // Unmodified.
        assert_eq!(read_modified_block(|_| {}).unwrap().len(), 2);

        // Invalid magic.
        assert_eq!(
            read_modified_block(|block| block[3] = 0).unwrap_err(),
            CorruptKind::XattrBlockHeader(inode)
        );

        // Invalid block count.
        assert_eq!(
            read_modified_block(|block| block[8] = 2).unwrap_err(),
            CorruptKind::XattrBlockHeader(inode)
        );

        // Invalid checksum.
        assert_eq!(
            read_modified_block(|block| {
                let last = block.len() - 1;
                block[last] ^= 0xff;
            })
            .unwrap_err(),
            CorruptKind::XattrBlockChecksum(inode)
        );
    }

    #[test]
    fn test_xattr_debug() {
        assert_eq!(
            format!("{:?}", xattr(b"user.a", b"\x01b")),
            r#"Xattr { name: "user.a", value: "\u{1}b" }"#
        );
    }
}
