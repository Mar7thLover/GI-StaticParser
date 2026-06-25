//! String decryption (see `RECIPE.md` §2).
//!
//! `idx` packs offset (low 24 bits) + length (next 8 bits). The keystream is 8-byte blocks XOR'd
//! with an evolving key seeded from the string's offset.

use crate::mem::Memory;

/// Decode a string at `strsec` (offset of the string section within the body buffer) for packed
/// index `idx`. Generic over the backing store.
pub fn decode_str<M: Memory>(mem: &M, strsec: usize, idx: u32) -> String {
    if idx == 0xFFFF_FFFF {
        return String::new();
    }
    let off = (idx & 0xFF_FFFF) as usize;
    let len = ((idx >> 24) & 0xFF) as usize;
    let nq = (len + 7) >> 3;
    let src = strsec.wrapping_add(off);
    if !mem.readable(src, nq * 8 + 8) {
        return String::new();
    }
    let a = 0x7EC9_2DE8_77F1_13F2u64.wrapping_mul(off as u64) ^ 0x17AE_9BC6_7ADF_D24D;
    let c = 0x2534_E544_4975_26A1u64
        .wrapping_mul(a)
        .wrapping_add(0x54EB_1A52_1F01_14C9)
        ^ 0x68A6_9E94_2939_701D;
    let mut key = 0x5CDE_4E05_62F8_84EAu64.wrapping_mul(c);
    let mut buf = Vec::with_capacity(nq * 8);
    for k in 0..nq {
        let enc = mem.read_u64(src + 8 * k);
        buf.extend_from_slice(&(enc ^ key).to_le_bytes());
        key = key.wrapping_add(0x6C80_2BDA_2DB0_1DBB);
    }
    buf.truncate(len);
    if let Some(z) = buf.iter().position(|&b| b == 0) {
        buf.truncate(z);
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Convenience: decode against a raw byte slice (the common case — the body buffer). Returns `None`
/// for an empty result so callers can distinguish "no string" from `""`.
pub fn decode_at(body: &[u8], strsec: usize, idx: u32) -> Option<String> {
    let mem = crate::mem::Buffer::new(body);
    let s = decode_str(&mem, strsec, idx);
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_known_anchor_strings() {
        let Ok(gm) = std::fs::read("Original/global-metadata.dat") else {
            eprintln!("[skip] global-metadata.dat not present");
            return;
        };
        let Ok(ga) = std::fs::read("Original/GameAssembly.exe") else {
            eprintln!("[skip] GameAssembly.exe not present");
            return;
        };
        let md = crate::decrypt::file::load(&ga, &gm).expect("load");
        let f272 = i32::from_le_bytes([md.header[272], md.header[273], md.header[274], md.header[275]]);
        let strsec = (f272 as i64 - 1426623823) as usize;
        // Exact-offset anchors confirmed during RE.
        assert_eq!(decode_at(&md.body, strsec, (8 << 24) | 0).as_deref(), Some("mscorlib"));
        assert_eq!(decode_at(&md.body, strsec, (8 << 24) | 0x3D4).as_deref(), Some("hidden_3"));
        assert_eq!(decode_at(&md.body, strsec, (9 << 24) | 0x40D).as_deref(), Some("hidden_12"));
        assert_eq!(decode_at(&md.body, strsec, (8 << 24) | 0x487).as_deref(), Some("hash_alg"));
    }
}
