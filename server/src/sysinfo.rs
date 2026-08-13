//! What the host has left: system memory and the free space under a path.
//!
//! Read for reporting only — the startup notice in [`crate::startup`] is the
//! one caller, and nothing here feeds a decision the server makes. Every
//! probe is therefore fallible in the quietest possible way: an unreadable
//! `/proc/meminfo` or a failed `statvfs` yields `None`, and the report simply
//! says so.
//!
//! **In a container these are the host's figures**, not the container's,
//! unless a cgroup limit happens to be reflected in `/proc/meminfo` (it is
//! not) or the data directory is a bind mount (it is — so the disk figures
//! *are* the host filesystem's, which is what an operator wants to see).

use std::path::Path;

pub use crate::types::{DiskUsage, MemoryUsage};

/// Where Linux publishes the memory figures.
const MEMINFO: &str = "/proc/meminfo";

impl MemoryUsage {
    /// Total minus available — what is actually spoken for, in the sense
    /// `free -h` prints under "used".
    pub fn used(&self) -> u64 {
        self.total.saturating_sub(self.available)
    }
}

/// System memory, or `None` where `/proc/meminfo` is not a thing (macOS,
/// Windows) or cannot be read.
pub fn memory() -> Option<MemoryUsage> {
    parse_meminfo(&std::fs::read_to_string(MEMINFO).ok()?)
}

/// Occupancy of the filesystem holding `path`.
///
/// The path need not exist: `statvfs` answers about a *file*, and the data
/// directory may not have been created yet on the memory backend, so this
/// walks up to the nearest existing ancestor. A relative path with no
/// existing ancestor falls back to the working directory, which is the
/// filesystem the caller meant anyway.
pub fn disk(path: &Path) -> Option<DiskUsage> {
    let mut candidate = Some(path);
    while let Some(dir) = candidate {
        if dir.exists() {
            return statvfs(dir);
        }
        candidate = dir.parent();
    }
    statvfs(Path::new("."))
}

/// Formats a byte count the way an operator reads one: binary units, one
/// decimal, exact below a kibibyte.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Pulled out of [`memory`] so the parsing is testable without a filesystem.
///
/// `MemAvailable` is the field that answers "how much can still be
/// allocated"; it has been there since Linux 3.14, and the `MemFree`
/// fallback is for anything older, where it under-reports by the size of the
/// page cache.
fn parse_meminfo(text: &str) -> Option<MemoryUsage> {
    let mut total = None;
    let mut available = None;
    let mut free = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        // "MemTotal:       16316160 kB" — always kibibytes on every kernel
        // that has ever written this file.
        let Some(kib) = value
            .split_whitespace()
            .next()
            .and_then(|n| n.parse::<u64>().ok())
        else {
            continue;
        };
        match key {
            "MemTotal" => total = Some(kib * 1024),
            "MemAvailable" => available = Some(kib * 1024),
            "MemFree" => free = Some(kib * 1024),
            _ => {}
        }
    }
    Some(MemoryUsage {
        total: total?,
        available: available.or(free)?,
    })
}

#[cfg(unix)]
fn statvfs(path: &Path) -> Option<DiskUsage> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `c_path` is a NUL-terminated path that outlives the call, and
    // `stat` is a writable, correctly sized and aligned `statvfs`. The kernel
    // fills it whenever it returns 0, which is the only branch that reads it.
    let filled = unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) } == 0;
    if !filled {
        return None;
    }
    let stat = unsafe { stat.assume_init() };

    // `f_frsize` is the size a block count is expressed in; `f_bsize` is the
    // preferred I/O size and only coincidentally equal. Fall back to it
    // rather than reporting zeroes if a filesystem leaves f_frsize unset.
    let frsize = wide(stat.f_frsize);
    let unit = if frsize > 0 {
        frsize
    } else {
        wide(stat.f_bsize)
    };
    let blocks = wide(stat.f_blocks);
    Some(DiskUsage {
        total: blocks.saturating_mul(unit),
        // `f_bavail`, not `f_bfree`: the reserved blocks are not ours.
        available: wide(stat.f_bavail).saturating_mul(unit),
        used: blocks
            .saturating_sub(wide(stat.f_bfree))
            .saturating_mul(unit),
    })
}

/// Widens whatever integer width this platform's `statvfs` uses — the block
/// counts are 64-bit on Linux and 32-bit on some others, and a cast per field
/// would be either lossy or redundant depending on the target.
#[cfg(unix)]
fn wide(value: impl Into<u64>) -> u64 {
    value.into()
}

#[cfg(not(unix))]
fn statvfs(_path: &Path) -> Option<DiskUsage> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meminfo_is_read_in_bytes_from_the_available_field() {
        let info = parse_meminfo(
            "MemTotal:       16316160 kB\n\
             MemFree:          524288 kB\n\
             MemAvailable:    8388608 kB\n\
             Buffers:          131072 kB\n",
        )
        .expect("both fields present");
        assert_eq!(info.total, 16_316_160 * 1024);
        // MemAvailable wins over MemFree: the page cache is reclaimable, and
        // reporting MemFree here would tell an operator a healthy server is
        // nearly out of memory.
        assert_eq!(info.available, 8_388_608 * 1024);
        assert_eq!(info.used(), 16_316_160 * 1024 - 8_388_608 * 1024);
    }

    #[test]
    fn a_kernel_without_memavailable_falls_back_to_memfree() {
        let info = parse_meminfo("MemTotal: 1024 kB\nMemFree: 256 kB\n").expect("fallback");
        assert_eq!(info.available, 256 * 1024);
    }

    #[test]
    fn unparsable_meminfo_reports_nothing_rather_than_zero() {
        assert!(parse_meminfo("").is_none());
        // A total with no free figure at all: "0 available" would read as an
        // emergency, so the report must say "unavailable" instead.
        assert!(parse_meminfo("MemTotal: 1024 kB\n").is_none());
        assert!(parse_meminfo("MemTotal: not-a-number kB\nMemFree: 1 kB\n").is_none());
    }

    #[test]
    fn bytes_are_formatted_in_binary_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(999), "999 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(16 * 1024 * 1024 * 1024), "16.0 GiB");
        // Nothing bigger than TiB, so a large enough number keeps growing in
        // that unit instead of running off the end of the table.
        assert_eq!(format_bytes(4096 * 1024_u64.pow(4)), "4096.0 TiB");
    }

    #[test]
    fn disk_answers_for_a_path_that_does_not_exist_yet() {
        let tmp = tempfile::tempdir().unwrap();
        // The data directory before the first run creates it: the answer must
        // come from the nearest existing ancestor rather than being `None`.
        let usage = disk(&tmp.path().join("data").join("vaults")).expect("a mounted filesystem");
        assert!(usage.total > 0, "{usage:?}");
        assert!(usage.available <= usage.total, "{usage:?}");
    }
}
