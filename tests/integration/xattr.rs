// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::test_util::load_compressed_filesystem;
use ext4_view::{Ext4, Ext4Error};

fn load_xattrs() -> Ext4 {
    load_compressed_filesystem("test_disk_xattrs.bin.zst")
}

/// Get the extended attributes of `path` as sorted (name, value) pairs.
fn xattrs(fs: &Ext4, path: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    pairs(fs.xattrs(path).unwrap())
}

/// Get the extended attributes of `path`, not following a final
/// symlink, as sorted (name, value) pairs.
fn symlink_xattrs(fs: &Ext4, path: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    pairs(fs.symlink_xattrs(path).unwrap())
}

fn pairs(xattrs: Vec<ext4_view::Xattr>) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut pairs: Vec<_> = xattrs
        .iter()
        .map(|x| (x.name().to_vec(), x.value().to_vec()))
        .collect();
    pairs.sort();
    pairs
}

fn pair(name: &[u8], value: &[u8]) -> (Vec<u8>, Vec<u8>) {
    (name.to_vec(), value.to_vec())
}

#[test]
fn test_no_xattrs() {
    let fs = load_xattrs();
    assert_eq!(xattrs(&fs, "/no_xattrs"), []);
    assert_eq!(xattrs(&fs, "/"), []);
}

#[test]
fn test_inode_xattr() {
    let fs = load_xattrs();
    assert_eq!(xattrs(&fs, "/inode_xattr"), [pair(b"user.a", b"hello")]);
}

#[test]
fn test_block_xattr() {
    let fs = load_xattrs();
    assert_eq!(
        xattrs(&fs, "/block_xattr"),
        [
            pair(b"user.big", "x".repeat(600).as_bytes()),
            pair(b"user.small", b"1"),
        ]
    );
}

#[test]
fn test_privileged_xattrs() {
    let fs = load_xattrs();
    assert_eq!(
        xattrs(&fs, "/privileged_xattrs"),
        [
            pair(
                b"security.capability",
                &[
                    0x01, 0x00, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ]
            ),
            pair(b"trusted.t", b"trusted value"),
        ]
    );
}

/// ACLs are returned in the format stored on disk, not the format used
/// by the kernel's `getxattr`.
#[test]
fn test_acl_xattrs() {
    let fs = load_xattrs();

    assert_eq!(
        xattrs(&fs, "/acl_file"),
        [pair(
            b"system.posix_acl_access",
            &[
                // Version.
                0x01, 0x00, 0x00, 0x00, //
                // Owner: rw.
                0x01, 0x00, 0x06, 0x00, //
                // User 1000: r.
                0x02, 0x00, 0x04, 0x00, 0xe8, 0x03, 0x00, 0x00, //
                // Group: r.
                0x04, 0x00, 0x04, 0x00, //
                // Group 2000: rw.
                0x08, 0x00, 0x06, 0x00, 0xd0, 0x07, 0x00, 0x00, //
                // Mask: rw.
                0x10, 0x00, 0x06, 0x00, //
                // Other: r.
                0x20, 0x00, 0x04, 0x00,
            ]
        )]
    );

    assert_eq!(
        xattrs(&fs, "/acl_dir"),
        [pair(
            b"system.posix_acl_default",
            &[
                // Version.
                0x01, 0x00, 0x00, 0x00, //
                // Owner: rwx.
                0x01, 0x00, 0x07, 0x00, //
                // User 1000: rx.
                0x02, 0x00, 0x05, 0x00, 0xe8, 0x03, 0x00, 0x00, //
                // Group: rx.
                0x04, 0x00, 0x05, 0x00, //
                // Mask: rx.
                0x10, 0x00, 0x05, 0x00, //
                // Other: rx.
                0x20, 0x00, 0x05, 0x00,
            ]
        )]
    );
}

#[test]
fn test_symlink_xattrs() {
    let fs = load_xattrs();

    // `xattrs` follows the symlink.
    assert_eq!(xattrs(&fs, "/symlink"), [pair(b"user.a", b"hello")]);

    // `symlink_xattrs` does not.
    assert_eq!(
        symlink_xattrs(&fs, "/symlink"),
        [pair(b"trusted.link", b"on the link")]
    );

    // For a path that isn't a symlink, the two are the same.
    assert_eq!(
        symlink_xattrs(&fs, "/inode_xattr"),
        [pair(b"user.a", b"hello")]
    );
}

#[test]
fn test_xattrs_errors() {
    let fs = load_xattrs();

    // Error: malformed path.
    assert!(matches!(
        fs.xattrs("\0").unwrap_err(),
        Ext4Error::MalformedPath
    ));
    assert!(matches!(
        fs.symlink_xattrs("\0").unwrap_err(),
        Ext4Error::MalformedPath
    ));

    // Error: path is not absolute.
    assert!(matches!(
        fs.xattrs("not_absolute").unwrap_err(),
        Ext4Error::NotAbsolute
    ));
    assert!(matches!(
        fs.symlink_xattrs("not_absolute").unwrap_err(),
        Ext4Error::NotAbsolute
    ));

    // Error: does not exist.
    assert!(matches!(
        fs.xattrs("/does_not_exist").unwrap_err(),
        Ext4Error::NotFound
    ));
    assert!(matches!(
        fs.symlink_xattrs("/does_not_exist").unwrap_err(),
        Ext4Error::NotFound
    ));
}

#[test]
fn test_metadata_ino_nlink() {
    let fs = load_xattrs();

    // The root directory is always inode 2. Its link count is two plus
    // one for the `..` entry of each of its three subdirectories
    // (`acl_dir`, `dir`, and `lost+found`).
    let metadata = fs.metadata("/").unwrap();
    assert_eq!(metadata.ino(), 2);
    assert_eq!(metadata.nlink(), 5);

    let metadata = fs.metadata("/no_xattrs").unwrap();
    assert_eq!(metadata.nlink(), 1);

    // Hard links share an inode.
    let a = fs.metadata("/hard_link_a").unwrap();
    let b = fs.metadata("/dir/hard_link_b").unwrap();
    assert_eq!(a.ino(), b.ino());
    assert_eq!(a.nlink(), 2);
    assert_eq!(b.nlink(), 2);
    assert_ne!(a.ino(), metadata.ino());

    // A symlink has its own inode.
    let link = fs.symlink_metadata("/symlink").unwrap();
    let target = fs.metadata("/symlink").unwrap();
    assert_eq!(target.ino(), fs.metadata("/inode_xattr").unwrap().ino());
    assert_ne!(link.ino(), target.ino());
}
