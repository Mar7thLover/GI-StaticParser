//! PE32+ parsing: section table, VA/RVA/file-offset mapping, and IAT resolution.
//!
//! Milestone (a). Used for two things: (1) the Phase-1 loader RE (locate functions, resolve IAT
//! call sites like CreateFileW/ReadFile), and (2) RVA emission in the dump (`method RVA = code
//! pointer − ImageBase`).
//!
//! Implemented with [`pelite`] (cached, pure-Rust). The key subtlety this module handles: an RVA
//! may fall in a section whose `VirtualSize > RawSize` (BSS) — i.e. it is mapped at runtime but has
//! no file bytes. [`rva_to_file`] returns `None` for such RVAs. This is exactly how the metadata
//! globals `f418`/`f420` (RVA `0x521F418`/`0x521F420`) appear: in-`.data`-range but beyond
//! `RawSize`, so genuinely BSS — zero on disk, produced by the loader at runtime.

use anyhow::{anyhow, Result};
use pelite::pe64::{Pe, PeFile};

/// A loaded PE image with its section table and import directory cached.
pub struct Image<'a> {
    bytes: &'a [u8],
    file: PeFile<'a>,
    image_base: u64,
    sections: Vec<Section>,
}

#[derive(Clone, Debug)]
pub struct Section {
    pub name: String,
    pub virtual_address: u32, // RVA
    pub virtual_size: u32,
    pub raw_pointer: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

impl Section {
    pub fn is_executable(&self) -> bool {
        self.characteristics & 0x2000_0000 != 0 // IMAGE_SCN_MEM_EXECUTE
    }
    pub fn is_writable(&self) -> bool {
        self.characteristics & 0x8000_0000 != 0
    }
}

impl<'a> Image<'a> {
    /// Parse a PE32+ image from raw bytes.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let file = PeFile::from_bytes(bytes).map_err(|e| anyhow!("pelite parse: {e:?}"))?;
        let optional = file.optional_header();
        let image_base = optional.ImageBase;
        let sections: Vec<Section> = file
            .section_headers()
            .iter()
            .map(|s| Section {
                name: s.name().unwrap_or("<bad>").to_string(),
                virtual_address: s.VirtualAddress,
                virtual_size: s.VirtualSize,
                raw_pointer: s.PointerToRawData,
                raw_size: s.SizeOfRawData,
                characteristics: s.Characteristics,
            })
            .collect();
        Ok(Self { bytes, file, image_base, sections })
    }

    pub fn image_base(&self) -> u64 {
        self.image_base
    }
    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    /// Find a section by name (case-insensitive).
    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name.eq_ignore_ascii_case(name))
    }

    /// Convert a VA (ImageBase + RVA) to an RVA.
    pub fn va_to_rva(&self, va: u64) -> Option<u32> {
        va.checked_sub(self.image_base).map(|r| r as u32)
    }

    /// Convert an RVA to a file offset. Returns `None` if the RVA is unmapped (BSS gap where
    /// `VirtualSize > RawSize`) or outside any section.
    pub fn rva_to_file(&self, rva: u32) -> Option<u64> {
        for s in &self.sections {
            // Match the loader's mapping: cover the full VirtualSize (filled with zeroes for the
            // BSS tail), but only the RawSize portion has real file bytes.
            let va_start = s.virtual_address;
            let va_end = s.virtual_address.wrapping_add(s.virtual_size);
            if rva >= va_start && rva < va_end {
                let off_in_sec = rva - va_start;
                if off_in_sec < s.raw_size {
                    return Some(s.raw_pointer as u64 + off_in_sec as u64);
                }
                return None; // in section's BSS tail: mapped but no file bytes
            }
        }
        None
    }

    /// VA → file offset convenience.
    pub fn va_to_file(&self, va: u64) -> Option<u64> {
        self.rva_to_file(self.va_to_rva(va)?)
    }

    /// Is this VA/RVA within a section whose RawSize < VirtualSize for the relevant offset? Used to
    /// flag BSS globals like f418/f420.
    pub fn is_bss(&self, rva: u32) -> bool {
        for s in &self.sections {
            let va_end = s.virtual_address.wrapping_add(s.virtual_size);
            if rva >= s.virtual_address && rva < va_end {
                let off = rva - s.virtual_address;
                return off >= s.raw_size; // beyond raw data => BSS
            }
        }
        false
    }

    /// Borrow a raw byte slice for a file offset range, if in bounds.
    pub fn file_slice(&self, file_off: u64, len: usize) -> Option<&'a [u8]> {
        let end = file_off.checked_add(len as u64)?;
        self.bytes.get(file_off as usize..end as usize)
    }

    /// Iterator over imports: `(dll_name, import_name_or_ordinal, iat_slot_va)`. The `iat_slot_va`
    /// is the address of the IAT entry (`ImageBase + FirstThunk + i*8`) — this is what `call
    /// [rip+disp]` targets in code, so the loader-RE scans for calls to this VA.
    ///
    /// Hand-rolled from the import directory rather than via pelite's `imports()`, which rejects
    /// this particular binary's import directory with a `Misaligned` error. We only need name→IAT-VA
    /// mapping, which the raw directory walk gives directly.
    pub fn imports(&self) -> Vec<(String, Option<String>, u64)> {
        self.parse_imports().unwrap_or_default()
    }

    fn parse_imports(&self) -> Option<Vec<(String, Option<String>, u64)>> {
        // DataDirectory[1] = Import Table (RVA, size). pelite stores DataDirectory as a flexible
        // (zero-length) array on the optional header, so index it via `data_directory()` instead.
        let import_dir = self.file.data_directory().get(1)?;
        let dir_rva = import_dir.VirtualAddress;
        if dir_rva == 0 {
            return None;
        }
        let read_u32 = |rva: u32| -> Option<u32> {
            let off = self.rva_to_file(rva)? as usize;
            let s = self.bytes.get(off..off + 4)?;
            Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        };
        let read_u64 = |rva: u32| -> Option<u64> {
            let off = self.rva_to_file(rva)? as usize;
            let s = self.bytes.get(off..off + 8)?;
            Some(u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
        };
        let read_cstr = |rva: u32| -> String {
            let Some(off) = self.rva_to_file(rva) else { return String::new() };
            let mut v = Vec::new();
            let mut p = off as usize;
            while let Some(&b) = self.bytes.get(p) {
                if b == 0 || v.len() > 256 {
                    break;
                }
                v.push(b);
                p += 1;
            }
            String::from_utf8_lossy(&v).into_owned()
        };

        const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;
        let mut out = Vec::new();
        // Each IMAGE_IMPORT_DESCRIPTOR is 20 bytes: {OriginalFirstThunk(INT) u32, TimeDateStamp,
        // ForwarderChain, Name u32, FirstThunk(IAT) u32}. Terminated by an all-zero descriptor.
        let mut desc_rva = dir_rva;
        for _ in 0..1024 {
            let original_first_thunk = read_u32(desc_rva)?;
            let name_rva = read_u32(desc_rva + 12)?;
            let first_thunk = read_u32(desc_rva + 16)?;
            if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
                break; // null terminator
            }
            let dll = read_cstr(name_rva);
            // Prefer the INT (OriginalFirstThunk) for names; fall back to IAT if INT is absent.
            let int_rva = if original_first_thunk != 0 { original_first_thunk } else { first_thunk };
            let mut i = 0u32;
            loop {
                let entry = read_u64(int_rva + i * 8)?;
                if entry == 0 {
                    break;
                }
                let name = if entry & IMAGE_ORDINAL_FLAG64 != 0 {
                    Some(format!("#{}", entry & 0xFFFF))
                } else {
                    // entry is an RVA to IMAGE_IMPORT_BY_NAME { hint u16, name[] }
                    let hint_name_rva = (entry & 0x7FFF_FFFF) as u32;
                    Some(read_cstr(hint_name_rva + 2))
                };
                let iat_va = self.image_base + first_thunk as u64 + (i as u64) * 8;
                out.push((dll.clone(), name, iat_va));
                i += 1;
                if i > 100_000 {
                    break;
                }
            }
            desc_rva += 20;
        }
        Some(out)
    }

    /// Look up the IAT slot VA for a function name (case-insensitive, any dll). The returned VA is
    /// the IAT entry's address; code calls it via `call [rip+disp]` whose target == this VA.
    pub fn iat_slot(&self, func: &str) -> Option<u64> {
        self.imports()
            .into_iter()
            .find(|(_, n, _)| n.as_deref().map_or(false, |x| x.eq_ignore_ascii_case(func)))
            .map(|(_, _, va)| va)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Path to the real GameAssembly.exe. Skipped if absent (e.g. CI without the binaries).
    fn ga() -> Option<Image<'static>> {
        let path = "Original/GameAssembly.exe";
        let bytes = std::fs::read(path).ok()?;
        // Leak to get 'static — these tests are one-shot CLI runs.
        let b: &'static [u8] = Box::leak(bytes.into_boxed_slice());
        Image::parse(b).ok()
    }

    #[test]
    fn parse_sections_and_bounds() {
        let img = match ga() {
            Some(i) => i,
            None => {
                eprintln!("[skip] GameAssembly.exe not present");
                return;
            }
        };
        assert_eq!(img.image_base(), 0x140000000);
        let text = img.section(".text").expect(".text");
        assert_eq!(text.virtual_address, 0x1000);
        assert!(text.is_executable());
        // RVA → file offset works inside .text.
        assert!(img.rva_to_file(0x1000).is_some());
        // f418/f420 are BSS (in .data but beyond RawSize) — the load-bearing correctness check.
        assert!(img.is_bss(0x521F418), "f418 must be BSS");
        assert!(img.is_bss(0x521F420), "f420 must be BSS");
        assert!(img.rva_to_file(0x521F418).is_none(), "f418 has no file bytes");
    }

    #[test]
    fn iat_resolves_kernel32_io() {
        let img = match ga() {
            Some(i) => i,
            None => {
                eprintln!("[skip] GameAssembly.exe not present");
                return;
            }
        };
        // At least one file/read API should be imported somewhere in the import set.
        let has_io = img
            .imports()
            .iter()
            .any(|(_, n, _)| n.as_deref().map_or(false, |x| x.contains("ReadFile") || x.contains("CreateFile")));
        assert!(has_io, "expected a ReadFile/CreateFile import");
    }
}
