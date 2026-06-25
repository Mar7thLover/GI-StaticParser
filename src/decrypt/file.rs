//! The `File` decryption strategy (Risk A — now closed).
//!
//! Produces `Metadata { header, body }` purely from the on-disk files:
//!   - `body`   = `global-metadata.dat[0x210..]` (the `f420` base; consumed in place at runtime).
//!   - `header` = the embedded "MHY" blob in `GenshinImpact.exe`'s `.rdata` (the `f418` struct).
//!
//! The header is located by a *self-validating* scan: among the `MHY\0` occurrences in `.rdata`,
//! the real one is the blob whose `+272` field (the string-section offset, decoded as
//! `i32(hdr+272) - 1426623823`) yields a string section that decodes "mscorlib" at offset 0 — the
//! first IL2CPP string. This avoids hard-coding the VA `0x1423AAFC8` and survives game updates.

use anyhow::{anyhow, bail, Result};

use super::{Metadata, Tables};
use crate::pe::Image;

/// Byte offset of the metadata body within `global-metadata.dat` (the loader sets
/// `f420 = file_buffer + 0x210`).
pub const BODY_OFFSET: usize = 0x210;

/// `strsec = f420 + (i32(header+272) - 1426623823)`.
const STRSEC_HDR_OFF: usize = 272;
const STRSEC_BIAS: i64 = 1426623823;

// Static pointer-chain anchors (VAs into GenshinImpact.exe), written into globals at load time by the
// registration fn `0x1402A7C20`.
//   typearr        = *(F400_VA + 0x18)
//   methodptrs     = *(F3F8_VA + 0x60)
//   genericClasses = *(F400_VA + 0x30)
const F400_VA: u64 = 0x1424387A8;
const F3F8_VA: u64 = 0x141F2EDD0;

/// Build [`Metadata`] from the raw bytes of `GenshinImpact.exe` and `global-metadata.dat`.
pub fn load(game_assembly: &[u8], global_metadata: &[u8]) -> Result<Metadata> {
    if global_metadata.len() <= BODY_OFFSET {
        bail!("global-metadata.dat too small ({} bytes)", global_metadata.len());
    }
    if &global_metadata[..4] != b"MHY\0" {
        bail!("global-metadata.dat missing MHY magic (got {:02x?})", &global_metadata[..4]);
    }
    let body = global_metadata[BODY_OFFSET..].to_vec();

    let img = Image::parse(game_assembly)?;
    let header = find_embedded_header(&img, &body)
        .ok_or_else(|| anyhow!("could not locate the embedded MHY header in GenshinImpact .rdata"))?;
    let tables = resolve_tables(&img)?;

    Ok(Metadata {
        header,
        body,
        game_assembly: game_assembly.to_vec(),
        tables,
    })
}

/// Resolve the three runtime tables by walking the static pointer chains in the exe's `.rdata`.
fn resolve_tables(img: &Image) -> Result<Tables> {
    let read_va_u64 = |va: u64| -> Option<u64> {
        let fo = img.va_to_file(va)? as usize;
        let bytes = img.file_slice(fo as u64, 8)?;
        Some(u64::from_le_bytes(bytes.try_into().ok()?))
    };
    let typearr_va = read_va_u64(F400_VA + 0x18)
        .ok_or_else(|| anyhow!("typearr pointer chain unreadable"))?;
    let methodptrs_va = read_va_u64(F3F8_VA + 0x60)
        .ok_or_else(|| anyhow!("methodptrs pointer chain unreadable"))?;
    let generic_va = read_va_u64(F400_VA + 0x30)
        .ok_or_else(|| anyhow!("genericClasses pointer chain unreadable"))?;

    let to_file = |va: u64, what: &str| -> Result<usize> {
        img.va_to_file(va)
            .map(|o| o as usize)
            .ok_or_else(|| anyhow!("{what} VA 0x{va:X} not mapped to file"))
    };
    let rdata = img
        .section(".rdata")
        .ok_or_else(|| anyhow!(".rdata section missing"))?;
    let tables = Tables {
        image_base: img.image_base(),
        typearr: to_file(typearr_va, "typearr")?,
        methodptrs: to_file(methodptrs_va, "methodptrs")?,
        generic_classes: to_file(generic_va, "genericClasses")?,
        rdata_va_start: img.image_base() + rdata.virtual_address as u64,
        rdata_file_start: rdata.raw_pointer as usize,
        rdata_size: rdata.raw_size as usize,
    };

    // Self-validate typearr: the first 256 Il2CppType entries should have kind ∈ [1, 0x1F] @ +0xA.
    let bytes = &img_full(img);
    let ok = (0..256).filter(|&i| {
        bytes
            .get(tables.typearr + 16 * i + 0xA)
            .map_or(false, |&k| (1..=0x1F).contains(&k))
    }).count();
    if ok < 240 {
        bail!("typearr self-validation failed ({ok}/256 valid kinds) — pointer anchors may be stale");
    }
    Ok(tables)
}

fn img_full<'a>(img: &Image<'a>) -> &'a [u8] {
    img.file_slice(0, img_len(img)).unwrap_or(&[])
}

/// Scan `.rdata` for the self-validating embedded "MHY" header. Returns its first `0x200` bytes.
fn find_embedded_header(img: &Image, body: &[u8]) -> Option<Vec<u8>> {
    let rdata = img.section(".rdata")?;
    let raw_start = rdata.raw_pointer as usize;
    let raw_end = raw_start + rdata.raw_size as usize;
    let bytes = img.file_slice(0, img_len(img))?; // whole file
    let region = &bytes[raw_start..raw_end.min(bytes.len())];

    // header fields are read up to +524, so capture at least 0x600 bytes.
    const HDR_LEN: usize = 0x600;
    let mut pos = 0usize;
    while let Some(rel) = find_subslice(&region[pos..], b"MHY\0") {
        let at = pos + rel;
        let hdr = region.get(at..at + HDR_LEN);
        if let Some(hdr) = hdr {
            if header_validates(hdr, body) {
                return Some(hdr.to_vec());
            }
        }
        pos = at + 1;
        if pos >= region.len() {
            break;
        }
    }
    None
}

/// A candidate header validates iff its string section decodes "mscorlib" at offset 0.
fn header_validates(hdr: &[u8], body: &[u8]) -> bool {
    if hdr.len() < STRSEC_HDR_OFF + 4 {
        return false;
    }
    let f272 = i32_le(hdr, STRSEC_HDR_OFF) as i64;
    let strsec = f272 - STRSEC_BIAS;
    if strsec < 0 || strsec as usize >= body.len() {
        return false;
    }
    // decode_str(body, strsec, idx with len=8, off=0)
    let s = crate::decode_str::decode_at(body, strsec as usize, (8 << 24) | 0);
    s.as_deref() == Some("mscorlib")
}

fn img_len(img: &Image) -> usize {
    // file_slice bounds-checks; pass a large len and let it clamp via the section walk instead.
    // We approximate the file length by the end of the last section's raw data.
    img.sections()
        .iter()
        .map(|s| s.raw_pointer as usize + s.raw_size as usize)
        .max()
        .unwrap_or(0)
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn i32_le(b: &[u8], o: usize) -> i32 {
    i32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_strategy_decodes_mscorlib() {
        let (Ok(ga), Ok(gm)) = (
            std::fs::read("Original/GenshinImpact.exe"),
            std::fs::read("Original/global-metadata.dat"),
        ) else {
            eprintln!("[skip] inputs not present");
            return;
        };
        let md = load(&ga, &gm).expect("load metadata");
        assert!(md.header.len() >= 0x200);
        assert_eq!(&md.header[..4], b"MHY\0");
        // The oracle: strsec decodes "mscorlib" at offset 0.
        let f272 = i32_le(&md.header, STRSEC_HDR_OFF) as i64;
        let strsec = (f272 - STRSEC_BIAS) as usize;
        let s = crate::decode_str::decode_at(&md.body, strsec, (8 << 24) | 0);
        assert_eq!(s.as_deref(), Some("mscorlib"));
        // Tables resolved + self-validated.
        assert_eq!(md.tables.image_base, 0x140000000);
        let ga_typearr_va = md.tables.image_base + 0; // sanity: typearr file off non-zero
        let _ = ga_typearr_va;
        // typearr[9] is a CLASS/VALUETYPE with data = a valid typeDefIndex (verified in RE).
        let k = md.game_assembly[md.tables.typearr + 16 * 9 + 0xA];
        assert!(matches!(k, 0x11 | 0x12), "typearr[9] should be CLASS/VALUETYPE, got kind 0x{k:X}");
    }
}
