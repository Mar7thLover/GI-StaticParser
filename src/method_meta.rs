//! Method metadata decoding (`mkey` + the method loop in `dump_full`).
//!
//! methodDef array (stride 26) holds the obfuscated name/flags/param/return indices. A per-method
//! key `mkey(gmi)` drives the de-obfuscation; `v30` is derived from it. Parameters come from the
//! param table (stride 8) with their own per-index key. RVA via methodptrs (GA image).

use crate::mem::Memory;
use crate::metadata::DecodedMetadata;
use crate::typenames::{method_modifiers, type_name, ClassNames};

const METHOD_STRIDE: usize = 26;
const PARAM_STRIDE: usize = 8;

/// Per-method key, 
pub fn mkey(idx: u32) -> u32 {
    let t = (50506u32.wrapping_mul(idx).wrapping_add(1_474_059_192)) ^ 0x1ABE_5654;
    833_330_077u32.wrapping_mul(t) ^ 0xCD8D_ECC5
}

/// One decoded method (rendered signature pieces).
pub struct Method {
    pub modifiers: String,
    pub return_type: String,
    pub name: String,
    pub params: Vec<String>,
    pub rva: u32,
    pub flags: u32,
}

/// Decode the methods of a type given `method_start` / `method_count` (from `class_model`).
pub fn methods<N: ClassNames>(
    dm: &DecodedMetadata,
    names: &N,
    method_start: u32,
    method_count: u32,
) -> Vec<Method> {
    let mut out = Vec::new();
    if method_start == u32::MAX || method_count == 0 || method_count >= 0x4000 {
        return out;
    }
    let mda = dm.method_defs;
    let parr = dm.params;
    for slot in 0..method_count {
        let gmi = method_start.wrapping_add(slot);
        let mdp = mda + METHOD_STRIDE * gmi as usize;
        if !dm.body.readable(mdp, 0x1A) {
            continue;
        }
        let nk = mkey(gmi); // = bkraw ^ 0xCD8DECC5
        let bkraw = nk ^ 0xCD8D_ECC5;
        let v30 = (bkraw ^ 0x3272_133A).wrapping_add(1_649_375_352);

        // name = methodDef[8] + nk - 2038689201
        let raw = dm.body.read_u32(mdp + 8);
        let name = dm.string(raw.wrapping_add(nk).wrapping_sub(2_038_689_201));

        // flags = (methodDef[0xC] ^ 0x9F21) - v30
        let mdc = dm.body.read_u16(mdp + 0xC) as u32;
        let flags = (mdc ^ 0x9F21).wrapping_sub(v30) & 0xFFFF;
        let modifiers = method_modifiers(flags);

        // RVA via methodptrs (GA image).
        let rva = dm.method_rva(gmi);

        // Parameters: paramStart = (md[0] ^ 0x4B00A30E) - v30 ; count = (md[0x18] ^ 0xB5) - v30.
        let pstart = (dm.body.read_u32(mdp) ^ 0x4B00_A30E).wrapping_sub(v30);
        let pcnt = ((dm.body.read_u8(mdp + 0x18) as u32 ^ 0xB5).wrapping_sub(v30)) & 0xFF;
        let mut params = Vec::new();
        for p in 0..pcnt.min(64) {
            let gpi = pstart.wrapping_add(p);
            let pe = parr + PARAM_STRIDE * gpi as usize;
            if !dm.body.readable(pe, 8) {
                break;
            }
            let vp = (676_740_890u32.wrapping_mul(gpi) ^ 0x62C4_F529)
                .wrapping_add(1_878_447_171);
            let pname = dm.string(vp ^ dm.body.read_u32(pe + 4).wrapping_sub(1_551_419_869));
            let pti = vp ^ dm.body.read_u32(pe).wrapping_sub(46_302_897);
            let ptn = if pti == 0xFFFF_FFFF {
                "void".to_string()
            } else {
                type_name(dm, names, dm.il2cpp_type_offset(pti as usize), 0)
            };
            params.push(format!("{ptn} {pname}"));
        }

        // return type: returnTypeIdx = (methodDef[4] ^ 0x7A3D7454) - v30 ; typearr[idx]
        let md4 = dm.body.read_u32(mdp + 4);
        let rtidx = (md4 ^ 0x7A3D_7454).wrapping_sub(v30);
        let return_type = if (rtidx as usize) < 4_000_000
            && dm.image.readable(dm.il2cpp_type_offset(rtidx as usize), 0x10)
        {
            type_name(dm, names, dm.il2cpp_type_offset(rtidx as usize), 0)
        } else {
            "void".to_string()
        };

        out.push(Method {
            modifiers,
            return_type,
            name,
            params,
            rva,
            flags,
        });
    }
    out
}
