//! `DecodedMetadata` — the resolved view over the decrypted buffers, with every table base
//! computed in one place so the dump walk reads named fields
//! `f420.wrapping_add((i32)(f418+K) - C)` expressions).
//!
//! Data flow: [`crate::decrypt::file::load`] → [`crate::decrypt::Metadata`] (owned buffers) → this
//! view (borrows them) → the ported dump walk. The header-driven table offsets all live in the body
//! buffer; the three runtime tables (typearr/methodptrs/genericClasses) live in the GameAssembly
//! `.rdata` buffer.

use crate::decrypt::{Metadata, Tables};
use crate::mem::Buffer;

/// Header field offsets and their de-obfuscation constants Each resolves to
/// an offset *within the body buffer*: `body + (i32(header+OFF) - SUB)` or `body + (u32(header+OFF)
/// ^ XOR)`.
mod hdr {
    pub const STRINGS: (usize, i64) = (272, 1426623823);
    pub const PARAMS: (usize, i64) = (420, 178973881);
    pub const FIELD_DEFS: (usize, i64) = (468, 48572191);
    pub const FIELD_OFFS: (usize, i64) = (20, 1964484308);
    pub const GENERIC_PARAMS: (usize, i64) = (188, 1405585855);
    pub const FIELD_OFF_TBL_B: (usize, u32) = (436, 0x6AE9_4CF7);
    pub const FOFF_V43BASE: (usize, u32) = (396, 0x4B8F_DA1A);
    pub const DEFAULT_VAL_BLOB: (usize, u32) = (328, 0x424C_D0BF);
    pub const FIELD_DEF_VALS: (usize, u32) = (524, 0x2429_7E49);
    /// methodDef array base: `body + (i32(header+336) - 201414367)` is the
    /// methods section (header+336, bias 201414367).
    pub const METHOD_DEFS: (usize, i64) = (336, 201414367);
}

/// All metadata table bases resolved as offsets into the body buffer (or GA image for the three
/// runtime tables). Computed once from the header.
pub struct DecodedMetadata<'a> {
    pub header: Buffer<'a>,
    pub body: Buffer<'a>,
    /// GameAssembly.exe image (for typearr/methodptrs/genericClasses + RVA math).
    pub image: Buffer<'a>,
    pub tables: Tables,

    // Resolved body-relative table offsets.
    pub strings: usize,
    pub method_defs: usize,
    pub params: usize,
    pub field_defs: usize,
    pub field_offsets: usize,
    pub generic_params: usize,
    pub field_off_table_b: usize,
    pub foff_v43base: usize,
    pub default_value_blob: usize,
    pub field_default_values: usize,
}

impl<'a> DecodedMetadata<'a> {
    /// Build the resolved view from owned [`Metadata`].
    pub fn new(md: &'a Metadata) -> Self {
        let header = Buffer::new(&md.header);
        let body = Buffer::new(&md.body);
        let image = Buffer::new(&md.game_assembly);

        let h = &md.header;
        let sub = |(off, bias): (usize, i64)| -> usize {
            (i32_le(h, off) as i64 - bias) as usize
        };
        let xor = |(off, key): (usize, u32)| -> usize {
            (u32_le(h, off) ^ key) as usize
        };

        DecodedMetadata {
            header,
            body,
            image,
            tables: md.tables,
            strings: sub(hdr::STRINGS),
            method_defs: sub(hdr::METHOD_DEFS),
            params: sub(hdr::PARAMS),
            field_defs: sub(hdr::FIELD_DEFS),
            field_offsets: sub(hdr::FIELD_OFFS),
            generic_params: sub(hdr::GENERIC_PARAMS),
            field_off_table_b: xor(hdr::FIELD_OFF_TBL_B),
            foff_v43base: xor(hdr::FOFF_V43BASE),
            default_value_blob: xor(hdr::DEFAULT_VAL_BLOB),
            field_default_values: xor(hdr::FIELD_DEF_VALS),
        }
    }

    /// Decode a string by packed index, against the resolved string section. Convenience wrapper
    /// over [`crate::decode_str::decode_str`].
    pub fn string(&self, idx: u32) -> String {
        crate::decode_str::decode_str(&self.body, self.strings, idx)
    }

    /// Read an `Il2CppType` field `(kind, data)` for a global type index, from typearr in the GA
    /// image. `kind` @ +0xA (u8), `data` @ +0 (u32). Returns `None` if out of range.
    pub fn il2cpp_type(&self, type_index: usize) -> Option<(u8, u32)> {
        let base = self.tables.typearr + 16 * type_index;
        let kind = self.image.read_u8_opt(base + 0xA)?;
        let data = self.image.read_u32_opt(base)?;
        Some((kind, data))
    }

    /// File offset (into the GA image) for the typearr entry of a type index.
    pub fn il2cpp_type_offset(&self, type_index: usize) -> usize {
        self.tables.typearr + 16 * type_index
    }

    /// Map a VA into the GA image's `.rdata` to a file offset, for Il2CppType `data` pointers (e.g.
    /// the element type of a pointer/array, which is a VA into `.rdata`). Returns `None` if the VA is
    /// outside `.rdata`.
    pub fn va_to_image_off(&self, va: u64) -> Option<usize> {
        let t = &self.tables;
        if va < t.rdata_va_start {
            return None;
        }
        let off = (va - t.rdata_va_start) as usize;
        if off < t.rdata_size {
            Some(t.rdata_file_start + off)
        } else {
            None
        }
    }

    /// Method code RVA for a global method index, via methodptrs in the GA image. Returns 0 if the
    /// entry is null or out of the code range (in-code-range filter).
    pub fn method_rva(&self, gmi: u32) -> u32 {
        let base = self.tables.methodptrs + 8 * gmi as usize;
        let Some(va) = self.image.read_u64_opt(base) else { return 0 };
        let ib = self.tables.image_base;
        if va > ib && va < ib + 0x4000_0000 {
            (va - ib) as u32
        } else {
            0
        }
    }
}

#[inline]
fn i32_le(b: &[u8], o: usize) -> i32 {
    i32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
#[inline]
fn u32_le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_all_table_bases_in_range() {
        let (Ok(ga), Ok(gm)) = (
            std::fs::read("Original/GameAssembly.exe"),
            std::fs::read("Original/global-metadata.dat"),
        ) else {
            eprintln!("[skip] inputs not present");
            return;
        };
        let md = crate::decrypt::file::load(&ga, &gm).expect("load");
        let dm = DecodedMetadata::new(&md);
        let blen = md.body.len();
        for (name, off) in [
            ("strings", dm.strings),
            ("method_defs", dm.method_defs),
            ("params", dm.params),
            ("field_defs", dm.field_defs),
            ("field_offsets", dm.field_offsets),
            ("generic_params", dm.generic_params),
            ("field_off_table_b", dm.field_off_table_b),
            ("foff_v43base", dm.foff_v43base),
            ("default_value_blob", dm.default_value_blob),
            ("field_default_values", dm.field_default_values),
        ] {
            assert!(off < blen, "{name} offset 0x{off:X} out of body (len 0x{blen:X})");
        }
        // Oracle still holds through the resolved view.
        assert_eq!(dm.string((8 << 24) | 0), "mscorlib");
    }
}
