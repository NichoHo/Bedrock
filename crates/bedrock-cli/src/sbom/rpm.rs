//! rpm package database parser. The database comes in three on-disk formats,
//! all holding the same thing: one rpm "header blob" per installed package.
//!
//! - SQLite (`rpmdb.sqlite`): Fedora 33+, RHEL 9, Amazon Linux 2023.
//! - Berkeley DB hash (`Packages`): RHEL/CentOS 7 and 8, Amazon Linux 2.
//! - NDB (`Packages.db`): openSUSE and SLES.
//!
//! Every byte here comes from an untrusted image, so all offsets are
//! bounds-checked and a malformed database is an error, never a panic.
use crate::fs::FileInventory;
use crate::sbom::{read_file, OsRelease, Package};
use anyhow::{bail, ensure, Context, Result};
use std::collections::BTreeSet;
use std::path::PathBuf;

/// Where the database lives across distros. `var/lib/rpm` is a symlink to
/// `../../usr/lib/sysimage/rpm` on newer Fedora, so both are listed. The
/// format is detected from the file's magic bytes, not its name.
const DB_PATHS: &[&str] = &[
    "usr/lib/sysimage/rpm/rpmdb.sqlite",
    "var/lib/rpm/rpmdb.sqlite",
    "usr/lib/sysimage/rpm/Packages.db",
    "var/lib/rpm/Packages.db",
    "usr/lib/sysimage/rpm/Packages",
    "var/lib/rpm/Packages",
];

pub fn parse_rpm<F>(inventory: &FileInventory, resolver: F) -> Result<Vec<Package>>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    for path in DB_PATHS {
        let Some(data) = read_file(inventory, &resolver, path)? else { continue };
        let wal = read_file(inventory, &resolver, &format!("{path}-wal"))?;
        let os = OsRelease::read(inventory, &resolver);
        return parse_db(&data, wal.as_deref(), &os)
            .with_context(|| format!("reading rpm database {path}"));
    }
    Ok(Vec::new())
}

/// Parses an rpm database in any of the three formats. `wal` is SQLite's
/// write-ahead log, if the image has one. Public for the fuzz target.
pub fn parse_db(data: &[u8], wal: Option<&[u8]>, os: &OsRelease) -> Result<Vec<Package>> {
    let blobs = if data.starts_with(b"SQLite format 3\0") {
        sqlite_blobs(data, wal)?
    } else if data.starts_with(b"RpmP") {
        ndb_blobs(data)?
    } else {
        bdb_blobs(data)?
    };
    let mut packages = Vec::new();
    for blob in blobs {
        let header = Header::parse(&blob).context("malformed rpm header")?;
        if let Some(pkg) = header.to_package(os)? {
            packages.push(pkg);
        }
    }
    packages.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(packages)
}

// ---------------------------------------------------------------- header blob

const TAG_NAME: i32 = 1000;
const TAG_VERSION: i32 = 1001;
const TAG_RELEASE: i32 = 1002;
const TAG_EPOCH: i32 = 1003;
const TAG_ARCH: i32 = 1022;
const TAG_SOURCERPM: i32 = 1044;
const TAG_OLDFILENAMES: i32 = 1027;
const TAG_DIRINDEXES: i32 = 1116;
const TAG_BASENAMES: i32 = 1117;
const TAG_DIRNAMES: i32 = 1118;

const TYPE_INT32: u32 = 4;
const TYPE_STRING: u32 = 6;
const TYPE_STRING_ARRAY: u32 = 8;
const TYPE_I18NSTRING: u32 = 9;

fn be_u32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// An rpm header as stored in the database: big-endian `il` (entry count) and
/// `dl` (data length), `il` 16-byte index entries, then the data store.
struct Header<'a> {
    /// (tag, type, offset, count)
    entries: Vec<(i32, u32, usize, usize)>,
    data: &'a [u8],
}

impl<'a> Header<'a> {
    fn parse(blob: &'a [u8]) -> Result<Self> {
        let il = be_u32(blob, 0).context("truncated header")? as usize;
        let dl = be_u32(blob, 4).context("truncated header")? as usize;
        // rpm itself caps these (HEADER_TAGS_MAX, HEADER_DATA_MAX).
        ensure!(il <= 0xffff && dl <= 256 << 20, "header sizes out of range");
        let data_start = 8 + il * 16;
        let data = blob.get(data_start..data_start + dl).context("header data out of bounds")?;
        let entries = (0..il)
            .map(|i| {
                let e = 8 + i * 16;
                // Unwraps are safe: data_start bounds check covers every entry.
                let field = |o| be_u32(blob, e + o).unwrap();
                (field(0) as i32, field(4), field(8) as usize, field(12) as usize)
            })
            .collect();
        Ok(Self { entries, data })
    }

    fn entry(&self, tag: i32) -> Option<(u32, usize, usize)> {
        self.entries.iter().find(|e| e.0 == tag).map(|&(_, ty, off, count)| (ty, off, count))
    }

    /// `count` NUL-terminated strings starting at the entry's offset.
    fn strings(&self, tag: i32) -> Result<Vec<String>> {
        let Some((ty, off, count)) = self.entry(tag) else { return Ok(Vec::new()) };
        ensure!(
            matches!(ty, TYPE_STRING | TYPE_STRING_ARRAY | TYPE_I18NSTRING),
            "tag {tag} is not a string"
        );
        let count = if ty == TYPE_STRING { 1 } else { count };
        let mut out = Vec::with_capacity(count.min(self.data.len()));
        let mut pos = off;
        for _ in 0..count {
            let rest = self.data.get(pos..).context("string offset out of bounds")?;
            let len = rest.iter().position(|&b| b == 0).context("unterminated string")?;
            out.push(String::from_utf8_lossy(&rest[..len]).into_owned());
            pos += len + 1;
        }
        Ok(out)
    }

    fn string(&self, tag: i32) -> Result<Option<String>> {
        Ok(self.strings(tag)?.into_iter().next())
    }

    fn int32s(&self, tag: i32) -> Result<Vec<u32>> {
        let Some((ty, off, count)) = self.entry(tag) else { return Ok(Vec::new()) };
        ensure!(ty == TYPE_INT32, "tag {tag} is not int32");
        let bytes = count.checked_mul(4).and_then(|n| self.data.get(off..off.checked_add(n)?));
        let bytes = bytes.context("int32 array out of bounds")?;
        Ok(bytes.as_chunks::<4>().0.iter().map(|c| u32::from_be_bytes(*c)).collect())
    }

    fn files(&self) -> Result<Vec<PathBuf>> {
        let basenames = self.strings(TAG_BASENAMES)?;
        let paths: Vec<String> = if basenames.is_empty() {
            self.strings(TAG_OLDFILENAMES)?
        } else {
            let dirnames = self.strings(TAG_DIRNAMES)?;
            let indexes = self.int32s(TAG_DIRINDEXES)?;
            ensure!(indexes.len() == basenames.len(), "dirindexes/basenames length mismatch");
            basenames
                .iter()
                .zip(indexes)
                .map(|(base, i)| {
                    let dir = dirnames.get(i as usize).context("dirindex out of range")?;
                    Ok(format!("{dir}{base}"))
                })
                .collect::<Result<_>>()?
        };
        Ok(paths.iter().map(|p| PathBuf::from(p.trim_start_matches('/'))).collect())
    }

    fn to_package(&self, os: &OsRelease) -> Result<Option<Package>> {
        let name = self.string(TAG_NAME)?.context("header has no name")?;
        // Imported signing keys show up as pseudo-packages; they aren't software.
        if name == "gpg-pubkey" {
            return Ok(None);
        }
        let version = self.string(TAG_VERSION)?.unwrap_or_default();
        let release = self.string(TAG_RELEASE)?.unwrap_or_default();
        let epoch = self.int32s(TAG_EPOCH)?.first().copied();
        let arch = self.string(TAG_ARCH)?;

        let evr = format!("{version}-{release}");
        let mut purl = format!("pkg:rpm/{}/{name}@{evr}", os.id.as_deref().unwrap_or("unknown"),);
        let mut qualifiers = Vec::new();
        if let Some(a) = &arch {
            qualifiers.push(format!("arch={a}"));
        }
        if let Some(e) = epoch {
            qualifiers.push(format!("epoch={e}"));
        }
        if let (Some(id), Some(v)) = (&os.id, &os.version_id) {
            qualifiers.push(format!("distro={id}-{v}"));
        }
        if !qualifiers.is_empty() {
            purl.push('?');
            purl.push_str(&qualifiers.join("&"));
        }

        Ok(Some(Package {
            name,
            version: match epoch {
                Some(e) => format!("{e}:{evr}"),
                None => evr,
            },
            architecture: arch,
            source: self.string(TAG_SOURCERPM)?.as_deref().and_then(srpm_name),
            purl,
            files: self.files()?,
        }))
    }
}

// --------------------------------------------------------------------- SQLite

/// rusqlite needs a file, so the database (and its write-ahead log, which may
/// hold transactions not yet checkpointed into the main file) is copied to a
/// private temp directory and read from there.
fn sqlite_blobs(db: &[u8], wal: Option<&[u8]>) -> Result<Vec<Vec<u8>>> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("bedrock-rpmdb-{}-{nanos}", std::process::id()));
    std::fs::create_dir(&dir)?;
    let result = (|| {
        let path = dir.join("rpmdb.sqlite");
        std::fs::write(&path, db)?;
        if let Some(wal) = wal {
            std::fs::write(dir.join("rpmdb.sqlite-wal"), wal)?;
        }
        let conn = rusqlite::Connection::open(&path)?;
        let mut stmt = conn.prepare("SELECT blob FROM Packages")?;
        let blobs = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        Ok(blobs.collect::<rusqlite::Result<Vec<_>>>()?)
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

/// Rewrites an SQLite rpm database without the named packages, as
/// `rpm -e --justdb` would: the row in `Packages` and every index row for the
/// same `hnum` go. Any write-ahead log is folded in first, so the result is a
/// single self-contained file and the image's `-wal` can be emptied.
pub fn sqlite_without(db: &[u8], wal: Option<&[u8]>, removed: &BTreeSet<&str>) -> Result<Vec<u8>> {
    ensure!(db.starts_with(b"SQLite format 3\0"), "not an SQLite rpm database");
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("rpmdb.sqlite");
    std::fs::write(&path, db)?;
    if let Some(wal) = wal {
        std::fs::write(dir.path().join("rpmdb.sqlite-wal"), wal)?;
    }
    let conn = rusqlite::Connection::open(&path)?;

    let mut gone = Vec::new();
    {
        let mut stmt = conn.prepare("SELECT hnum, blob FROM Packages")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        for row in rows {
            let (hnum, blob) = row?;
            let header = Header::parse(&blob).context("malformed rpm header")?;
            if header.string(TAG_NAME)?.is_some_and(|n| removed.contains(n.as_str())) {
                gone.push(hnum);
            }
        }
    }
    // Every table keyed by `hnum` (Packages and its index tables). Names come
    // from an untrusted file, so only plain identifiers are used.
    let tables: Vec<String> = {
        let mut stmt = conn.prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        )?;
        let names = stmt.query_map([], |r| r.get::<_, String>(0))?;
        names.collect::<rusqlite::Result<Vec<_>>>()?
    };
    // rpm's index tables carry `FOREIGN KEY (hnum) REFERENCES Packages`, so the
    // `Packages` row has to be deleted after the rows that point at it.
    let mut ordered: Vec<&String> = tables
        .iter()
        .filter(|t| t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
        .collect();
    ordered.sort_by_key(|t| t.as_str() == "Packages");
    for table in ordered {
        let has_hnum = conn
            .prepare(&format!("PRAGMA table_info(\"{table}\")"))?
            .query_map([], |r| r.get::<_, String>(1))?
            .filter_map(Result::ok)
            .any(|c| c == "hnum");
        if has_hnum {
            let mut del = conn.prepare(&format!("DELETE FROM \"{table}\" WHERE hnum = ?1"))?;
            for h in &gone {
                del.execute([h])?;
            }
        }
    }
    // Fold the log into the main file and leave no journal behind.
    conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
    conn.query_row("PRAGMA journal_mode = DELETE", [], |_| Ok(()))?;
    conn.execute_batch("VACUUM")?;
    drop(conn);
    Ok(std::fs::read(&path)?)
}

// ------------------------------------------------------------------------ NDB

const NDB_PAGE_SIZE: usize = 4096;
const NDB_SLOT_SIZE: usize = 16;
const NDB_BLOB_HEAD_SIZE: usize = 16;

fn le_u32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// NDB (rpm's own format, little-endian): a header page holding "RpmP" and the
/// number of slot pages, then 16-byte slots ("Slot", package index, block
/// offset, block count), each pointing at a blob ("BlbS", index, checksum,
/// length) at `block offset * 16`.
fn ndb_blobs(db: &[u8]) -> Result<Vec<Vec<u8>>> {
    ensure!(db.get(0..4) == Some(b"RpmP"), "not an NDB database (bad magic)");
    let slot_pages = le_u32(db, 12).context("truncated NDB header")? as usize;
    let slots_end = slot_pages.checked_mul(NDB_PAGE_SIZE).context("bad slot page count")?;
    ensure!(slots_end <= db.len(), "NDB slot pages run past end of file");

    let mut blobs = Vec::new();
    // The header occupies the first slot(s); anything without the slot magic
    // (header, free slots) is skipped.
    for slot in (NDB_SLOT_SIZE..slots_end).step_by(NDB_SLOT_SIZE) {
        if db.get(slot..slot + 4) != Some(b"Slot") {
            continue;
        }
        let pkg_index = le_u32(db, slot + 4).context("truncated slot")?;
        let blk_offset = le_u32(db, slot + 8).context("truncated slot")? as usize;
        if pkg_index == 0 {
            continue;
        }
        let start = blk_offset.checked_mul(NDB_BLOB_HEAD_SIZE).context("bad block offset")?;
        ensure!(db.get(start..start + 4) == Some(b"BlbS"), "NDB blob {pkg_index}: bad magic");
        let len = le_u32(db, start + 12).context("truncated blob header")? as usize;
        let body = start + NDB_BLOB_HEAD_SIZE;
        let blob = db.get(body..body.checked_add(len).context("bad blob length")?);
        blobs.push(blob.context("NDB blob runs past end of file")?.to_vec());
    }
    Ok(blobs)
}

// ---------------------------------------------------------- Berkeley DB (hash)

const BDB_HASH_MAGIC: u32 = 0x061561;
const BDB_PAGE_HEADER_SIZE: usize = 26;
const BDB_PAGE_HASH_UNSORTED: u8 = 2;
const BDB_PAGE_HASH: u8 = 13;
const BDB_ITEM_OFFPAGE: u8 = 3;

/// Berkeley DB hash database, as written by rpm before 4.16. Every package
/// header is large enough to be stored "off-page": the hash page holds a
/// pointer to a chain of overflow pages, which concatenate to the blob. Byte
/// order is whatever the host that wrote the file used, detected from the
/// magic number.
fn bdb_blobs(db: &[u8]) -> Result<Vec<Vec<u8>>> {
    let raw_magic = db.get(12..16).context("truncated Berkeley DB metadata")?;
    let big_endian = match u32::from_le_bytes(raw_magic.try_into()?) {
        BDB_HASH_MAGIC => false,
        m if m.swap_bytes() == BDB_HASH_MAGIC => true,
        _ => bail!("not a Berkeley DB hash database (bad magic)"),
    };
    let u32_at = |b: &[u8], at: usize| -> Option<u32> {
        let bytes: [u8; 4] = b.get(at..at + 4)?.try_into().ok()?;
        Some(if big_endian { u32::from_be_bytes(bytes) } else { u32::from_le_bytes(bytes) })
    };
    let u16_at = |b: &[u8], at: usize| -> Option<u16> {
        let bytes: [u8; 2] = b.get(at..at + 2)?.try_into().ok()?;
        Some(if big_endian { u16::from_be_bytes(bytes) } else { u16::from_le_bytes(bytes) })
    };

    ensure!(db.get(24) == Some(&0), "encrypted Berkeley DB is not supported");
    let page_size = u32_at(db, 20).context("truncated metadata")? as usize;
    ensure!((512..=65536).contains(&page_size), "invalid page size {page_size}");
    let last_page = u32_at(db, 32).context("truncated metadata")? as usize;
    let page = |n: usize| db.get(n.checked_mul(page_size)?..(n + 1).checked_mul(page_size)?);

    let mut blobs = Vec::new();
    // In a real database every overflow page belongs to exactly one chain,
    // so all chains together can't hold more bytes than the file. Enforcing
    // that bounds both a chain that loops and many items pointing at one long
    // chain, either of which would otherwise let a small hostile file expand
    // without limit. (`last_page` comes from the file, so it bounds nothing.)
    let mut bytes_read = 0usize;
    for page_no in 0..=last_page {
        let Some(p) = page(page_no) else { break };
        if !matches!(p[25], BDB_PAGE_HASH | BDB_PAGE_HASH_UNSORTED) {
            continue;
        }
        let entries = u16_at(p, 20).context("truncated page header")? as usize;
        // Index entries alternate key, value; only values hold package data.
        for i in (1..entries).step_by(2) {
            let item = u16_at(p, BDB_PAGE_HEADER_SIZE + i * 2).context("truncated index")? as usize;
            if p.get(item) != Some(&BDB_ITEM_OFFPAGE) {
                continue;
            }
            let mut next = u32_at(p, item + 4).context("truncated off-page item")? as usize;
            let total = u32_at(p, item + 8).context("truncated off-page item")? as usize;
            let mut blob = Vec::with_capacity(total.min(db.len()));
            while next != 0 {
                let op = page(next).context("overflow page out of range")?;
                let following = u32_at(op, 16).context("truncated overflow page")? as usize;
                // On overflow pages the free-area offset field holds the byte count.
                let len = u16_at(op, 22).context("truncated overflow page")? as usize;
                let end = if following == 0 { BDB_PAGE_HEADER_SIZE + len } else { op.len() };
                let chunk =
                    op.get(BDB_PAGE_HEADER_SIZE..end).context("overflow data out of bounds")?;
                bytes_read += chunk.len();
                ensure!(bytes_read <= db.len(), "overflow pages are reused or loop");
                blob.extend_from_slice(chunk);
                next = following;
            }
            blob.truncate(total);
            blobs.push(blob);
        }
    }
    Ok(blobs)
}

/// `bash-5.2.26-3.fc40.src.rpm` -> `bash`.
fn srpm_name(srpm: &str) -> Option<String> {
    let base =
        srpm.strip_suffix(".rpm")?.strip_suffix(".src").or_else(|| srpm.strip_suffix(".rpm"))?;
    let mut parts = base.rsplitn(3, '-');
    parts.next()?;
    parts.next()?;
    parts.next().map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an rpm header blob from (tag, type, count, data) entries.
    fn header(entries: &[(i32, u32, u32, &[u8])]) -> Vec<u8> {
        let mut index = Vec::new();
        let mut data = Vec::new();
        for &(tag, ty, count, bytes) in entries {
            if ty == TYPE_INT32 {
                while data.len() % 4 != 0 {
                    data.push(0);
                }
            }
            index.extend_from_slice(&tag.to_be_bytes());
            index.extend_from_slice(&ty.to_be_bytes());
            index.extend_from_slice(&(data.len() as u32).to_be_bytes());
            index.extend_from_slice(&count.to_be_bytes());
            data.extend_from_slice(bytes);
        }
        let mut blob = (entries.len() as u32).to_be_bytes().to_vec();
        blob.extend_from_slice(&(data.len() as u32).to_be_bytes());
        blob.extend(index);
        blob.extend(data);
        blob
    }

    fn bash_header() -> Vec<u8> {
        header(&[
            (TAG_NAME, TYPE_STRING, 1, b"bash\0"),
            (TAG_VERSION, TYPE_STRING, 1, b"5.2.26\0"),
            (TAG_RELEASE, TYPE_STRING, 1, b"3.fc40\0"),
            (TAG_EPOCH, TYPE_INT32, 1, &1u32.to_be_bytes()),
            (TAG_ARCH, TYPE_STRING, 1, b"x86_64\0"),
            (TAG_DIRNAMES, TYPE_STRING_ARRAY, 2, b"/usr/bin/\0/etc/\0"),
            (TAG_BASENAMES, TYPE_STRING_ARRAY, 2, b"bash\0bashrc\0"),
            (TAG_DIRINDEXES, TYPE_INT32, 2, &[0, 0, 0, 0, 0, 0, 0, 1]),
        ])
    }

    #[test]
    fn srpm_names() {
        assert_eq!(srpm_name("bash-5.2.26-3.fc40.src.rpm").as_deref(), Some("bash"));
        assert_eq!(
            srpm_name("python-dateutil-2.8.2-1.el9.src.rpm").as_deref(),
            Some("python-dateutil")
        );
        assert_eq!(srpm_name("(none)"), None);
    }

    #[test]
    fn header_becomes_package_with_files_and_purl() {
        let blob = bash_header();
        let os = OsRelease { id: Some("fedora".into()), version_id: Some("40".into()) };
        let pkg = Header::parse(&blob).unwrap().to_package(&os).unwrap().unwrap();
        assert_eq!(pkg.name, "bash");
        assert_eq!(pkg.version, "1:5.2.26-3.fc40");
        assert_eq!(
            pkg.purl,
            "pkg:rpm/fedora/bash@5.2.26-3.fc40?arch=x86_64&epoch=1&distro=fedora-40"
        );
        assert_eq!(pkg.files, vec![PathBuf::from("usr/bin/bash"), PathBuf::from("etc/bashrc")]);
    }

    #[test]
    fn gpg_pubkey_pseudo_package_is_skipped() {
        let blob = header(&[(TAG_NAME, TYPE_STRING, 1, b"gpg-pubkey\0")]);
        let pkg = Header::parse(&blob).unwrap().to_package(&OsRelease::default()).unwrap();
        assert!(pkg.is_none());
    }

    #[test]
    fn malformed_headers_error_instead_of_panicking() {
        assert!(Header::parse(&[0, 0]).is_err());
        assert!(Header::parse(&[0, 0, 0, 5, 0, 0, 0, 0]).is_err());
        let bad_offset = header(&[(TAG_NAME, TYPE_STRING, 1, b"x")]); // no NUL
        assert!(Header::parse(&bad_offset).unwrap().string(TAG_NAME).is_err());
        let bad_index = header(&[
            (TAG_DIRNAMES, TYPE_STRING_ARRAY, 1, b"/\0"),
            (TAG_BASENAMES, TYPE_STRING_ARRAY, 1, b"x\0"),
            (TAG_DIRINDEXES, TYPE_INT32, 1, &9u32.to_be_bytes()),
        ]);
        assert!(Header::parse(&bad_index).unwrap().files().is_err());
    }

    #[test]
    fn ndb_slots_point_at_blobs() {
        let blob = bash_header();
        let mut db = vec![0u8; NDB_PAGE_SIZE + NDB_BLOB_HEAD_SIZE + blob.len()];
        db[0..4].copy_from_slice(b"RpmP");
        db[12..16].copy_from_slice(&1u32.to_le_bytes()); // one slot page
        let slot = 32;
        db[slot..slot + 4].copy_from_slice(b"Slot");
        db[slot + 4..slot + 8].copy_from_slice(&1u32.to_le_bytes());
        let blk = (NDB_PAGE_SIZE / NDB_BLOB_HEAD_SIZE) as u32;
        db[slot + 8..slot + 12].copy_from_slice(&blk.to_le_bytes());
        let at = NDB_PAGE_SIZE;
        db[at..at + 4].copy_from_slice(b"BlbS");
        db[at + 12..at + 16].copy_from_slice(&(blob.len() as u32).to_le_bytes());
        db[at + 16..].copy_from_slice(&blob);

        assert_eq!(ndb_blobs(&db).unwrap(), vec![blob]);
        assert!(ndb_blobs(b"nope").is_err());
    }

    #[test]
    fn bdb_follows_overflow_chain() {
        // Opaque bytes, long enough to span two 512-byte overflow pages.
        let blob: Vec<u8> = (0..700u32).map(|i| i as u8).collect();
        let ps = 512;
        let first_len = ps - BDB_PAGE_HEADER_SIZE;
        let mut db = vec![0u8; ps * 4];
        // Page 0: metadata.
        db[12..16].copy_from_slice(&BDB_HASH_MAGIC.to_le_bytes());
        db[20..24].copy_from_slice(&(ps as u32).to_le_bytes());
        db[32..36].copy_from_slice(&3u32.to_le_bytes());
        // Page 1: hash page with one key/value pair; the value is off-page.
        let p = ps;
        db[p + 25] = BDB_PAGE_HASH;
        db[p + 20..p + 22].copy_from_slice(&2u16.to_le_bytes());
        let item = 100u16;
        db[p + 28..p + 30].copy_from_slice(&item.to_le_bytes());
        let it = p + item as usize;
        db[it] = BDB_ITEM_OFFPAGE;
        db[it + 4..it + 8].copy_from_slice(&2u32.to_le_bytes());
        db[it + 8..it + 12].copy_from_slice(&(blob.len() as u32).to_le_bytes());
        // Pages 2 and 3: overflow chain.
        let p2 = 2 * ps;
        db[p2 + 16..p2 + 20].copy_from_slice(&3u32.to_le_bytes());
        db[p2 + 26..p2 + ps].copy_from_slice(&blob[..first_len]);
        let p3 = 3 * ps;
        let rest = &blob[first_len..];
        db[p3 + 22..p3 + 24].copy_from_slice(&(rest.len() as u16).to_le_bytes());
        db[p3 + 26..p3 + 26 + rest.len()].copy_from_slice(rest);

        assert_eq!(bdb_blobs(&db).unwrap(), vec![blob]);

        // Many items sharing one chain must error, not multiply memory use:
        // 18 values pointing at the same chain (the index ends before the item).
        let mut shared = db.clone();
        shared[p + 20..p + 22].copy_from_slice(&36u16.to_le_bytes());
        for i in (1..36).step_by(2) {
            let at = p + BDB_PAGE_HEADER_SIZE + i * 2;
            shared[at..at + 2].copy_from_slice(&item.to_le_bytes());
        }
        assert!(bdb_blobs(&shared).is_err());

        // A chain pointing back at itself must error, not spin.
        db[p2 + 16..p2 + 20].copy_from_slice(&2u32.to_le_bytes());
        assert!(bdb_blobs(&db).is_err());
    }

    #[test]
    fn sqlite_packages_table_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rpmdb.sqlite");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB NOT NULL)", [])
            .unwrap();
        conn.execute("INSERT INTO Packages (blob) VALUES (?1)", [bash_header()]).unwrap();
        drop(conn);
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(sqlite_blobs(&bytes, None).unwrap(), vec![bash_header()]);
    }

    fn curl_header() -> Vec<u8> {
        header(&[
            (TAG_NAME, TYPE_STRING, 1, b"curl\0"),
            (TAG_VERSION, TYPE_STRING, 1, b"8.6.0\0"),
            (TAG_RELEASE, TYPE_STRING, 1, b"1.fc40\0"),
            (TAG_ARCH, TYPE_STRING, 1, b"x86_64\0"),
        ])
    }

    /// A database shaped like rpm's: `Packages` plus index tables keyed by `hnum`.
    fn rpmdb() -> Vec<u8> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rpmdb.sqlite");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)",
            [],
        )
        .unwrap();
        for t in ["Name", "Basenames", "Installtid"] {
            conn.execute(
                // Like the real index tables: deleting a Packages row first would violate this.
                &format!(
                    "CREATE TABLE {t} (key BLOB, hnum INTEGER NOT NULL, idx INTEGER, \
                     FOREIGN KEY (hnum) REFERENCES Packages(hnum))"
                ),
                [],
            )
            .unwrap();
        }
        conn.execute("CREATE TABLE Meta (k TEXT, v TEXT)", []).unwrap();
        conn.execute("INSERT INTO Meta VALUES ('keep', 'me')", []).unwrap();
        for (h, name) in [(bash_header(), "bash"), (curl_header(), "curl")] {
            conn.execute("INSERT INTO Packages (blob) VALUES (?1)", [h]).unwrap();
            let hnum = conn.last_insert_rowid();
            for t in ["Name", "Basenames", "Installtid"] {
                conn.execute(
                    &format!("INSERT INTO {t} VALUES (?1, ?2, 0)"),
                    rusqlite::params![name, hnum],
                )
                .unwrap();
            }
        }
        drop(conn);
        std::fs::read(&path).unwrap()
    }

    fn names_in(db: &[u8], wal: Option<&[u8]>) -> Vec<String> {
        let os = OsRelease::default();
        parse_db(db, wal, &os).unwrap().into_iter().map(|p| p.name).collect()
    }

    #[test]
    fn removed_packages_leave_no_row_in_any_hnum_table() {
        let db = rpmdb();
        let out = sqlite_without(&db, None, &BTreeSet::from(["bash"])).unwrap();
        assert_eq!(names_in(&out, None), ["curl"]);

        // Inspect the result directly: no index row for the removed package either.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rpmdb.sqlite");
        std::fs::write(&path, &out).unwrap();
        let conn = rusqlite::Connection::open(&path).unwrap();
        for t in ["Packages", "Name", "Basenames", "Installtid"] {
            let n: i64 =
                conn.query_row(&format!("SELECT COUNT(*) FROM {t}"), [], |r| r.get(0)).unwrap();
            assert_eq!(n, 1, "{t}");
        }
        let meta: String = conn.query_row("SELECT v FROM Meta", [], |r| r.get(0)).unwrap();
        assert_eq!(meta, "me", "tables without hnum are untouched");
    }

    #[test]
    fn nothing_removed_keeps_every_package_and_other_input_is_rejected() {
        let db = rpmdb();
        let out = sqlite_without(&db, None, &BTreeSet::new()).unwrap();
        assert_eq!(names_in(&out, None), ["bash", "curl"]);
        assert!(sqlite_without(b"RpmP not sqlite", None, &BTreeSet::new()).is_err());
    }
}
