//! The memory-access abstraction.
//!
//! Every decode function is generic over `M: Memory` so the read layer can vary: [`Buffer`]
//! addresses a decrypted byte slice by offset. All table addressing is `(base + offset)` where
//! `base` is an offset into the decrypted body or the GenshinImpact image.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MemError {
    #[error("offset {off:#x} + len {len:#x} out of bounds (size {size:#x})")]
    OutOfBounds { off: usize, len: usize, size: usize },
}

/// Read little-endian scalars / C strings / raw slices from some backing store, addressed by
/// offset.
///
/// All methods are infallible-by-convention: reads past the end return a zero of the right type and
/// `readable` returns false; callers that care check `readable` first.
pub trait Memory {
    /// True if `[off, off+len)` is readable.
    fn readable(&self, off: usize, len: usize) -> bool;

    fn read_u8(&self, off: usize) -> u8;
    fn read_u16(&self, off: usize) -> u16;
    fn read_u32(&self, off: usize) -> u32;
    fn read_i32(&self, off: usize) -> i32;
    fn read_u64(&self, off: usize) -> u64;
    fn read_i64(&self, off: usize) -> i64;

    /// Read a NUL-terminated C string bounded to `max` bytes, re-validating on page crossings.
    /// Returns `None` if the start isn't readable or empty.
    fn read_cstr(&self, off: usize, max: usize) -> Option<String>;

    /// Borrow a raw byte slice, if the whole range is readable. Useful for bulk string reads.
    fn read_slice(&self, off: usize, len: usize) -> Option<&[u8]>;

    /// Total size of the backing store (for diagnostics / bounds reports).
    fn size(&self) -> usize;
}

/// A byte-buffer-backed [`Memory`]: the decrypted metadata body (or header) addressed by offset.
/// `readable` is a plain bounds check.
#[derive(Clone, Copy)]
pub struct Buffer<'a> {
    data: &'a [u8],
}

impl<'a> Buffer<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
    #[inline]
    fn get(&self, off: usize, len: usize) -> Option<&'a [u8]> {
        self.data.get(off..off.checked_add(len)?)
    }

    /// Bounds-checked reads returning `None` past the end — for callers that want explicit
    /// out-of-range handling rather than the trait's read-zero behaviour.
    #[inline]
    pub fn read_u8_opt(&self, off: usize) -> Option<u8> {
        self.get(off, 1).map(|s| s[0])
    }
    #[inline]
    pub fn read_u32_opt(&self, off: usize) -> Option<u32> {
        self.get(off, 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    #[inline]
    pub fn read_u64_opt(&self, off: usize) -> Option<u64> {
        self.get(off, 8)
            .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
    }
}

impl<'a> Memory for Buffer<'a> {
    #[inline]
    fn readable(&self, off: usize, len: usize) -> bool {
        off.checked_add(len).map_or(false, |end| end <= self.data.len())
    }

    #[inline]
    fn read_u8(&self, off: usize) -> u8 {
        self.get(off, 1).map_or(0, |s| s[0])
    }
    #[inline]
    fn read_u16(&self, off: usize) -> u16 {
        self.get(off, 2).map_or(0, |s| u16::from_le_bytes([s[0], s[1]]))
    }
    #[inline]
    fn read_u32(&self, off: usize) -> u32 {
        self.get(off, 4).map_or(0, |s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    #[inline]
    fn read_i32(&self, off: usize) -> i32 {
        self.read_u32(off) as i32
    }
    #[inline]
    fn read_u64(&self, off: usize) -> u64 {
        self.get(off, 8).map_or(0, |s| {
            u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
        })
    }
    #[inline]
    fn read_i64(&self, off: usize) -> i64 {
        self.read_u64(off) as i64
    }

    /// NUL-terminated, page-bounded reader. Re-validate when
    /// crossing a 0x1000 page boundary (the metadata string section spans many pages; without the
    /// page-cap, names straddling a boundary get truncated).
    fn read_cstr(&self, off: usize, max: usize) -> Option<String> {
        if !self.readable(off, 1) {
            return None;
        }
        let cap = max.min(512);
        let mut bytes = Vec::new();
        for i in 0..cap {
            let addr = off + i;
            if addr & 0xFFF == 0 && !self.readable(addr, 1) {
                break;
            }
            let b = self.data.get(addr).copied().unwrap_or(0);
            if b == 0 {
                break;
            }
            bytes.push(b);
        }
        if bytes.is_empty() {
            return None;
        }
        Some(String::from_utf8_lossy(&bytes).into_owned())
    }

    #[inline]
    fn read_slice(&self, off: usize, len: usize) -> Option<&[u8]> {
        self.get(off, len)
    }

    fn size(&self) -> usize {
        self.data.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_reads_le() {
        let d = [0x78u8, 0x56, 0x34, 0x12, 0xEF, 0xCD, 0xAB, 0x90];
        let b = Buffer::new(&d);
        assert_eq!(b.read_u8(0), 0x78);
        assert_eq!(b.read_u16(0), 0x5678);
        assert_eq!(b.read_u32(0), 0x12345678);
        assert_eq!(b.read_u64(0), 0x90ABCDEF12345678);
        assert!(b.readable(0, 8));
        assert!(!b.readable(0, 9));
        assert!(!b.readable(7, 2));
        // OOB reads are zero, never panic (read-then-check style).
        assert_eq!(b.read_u32(6), 0);
    }

    #[test]
    fn buffer_cstr_bounded() {
        let d = b"hello\0world\0 padding";
        let b = Buffer::new(d);
        assert_eq!(b.read_cstr(0, 64).as_deref(), Some("hello"));
        assert_eq!(b.read_cstr(6, 64).as_deref(), Some("world"));
        assert!(b.read_cstr(0, 3).as_deref().is_some()); // bounded by max
    }
}
