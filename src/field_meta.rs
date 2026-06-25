//! Field metadata decoding (`field_key` + the field loop in `dump_full`).
//!
//! Per-field, the fieldDef array (stride 8) holds `{ typeIndex @ +0, nameIndex @ +4 }`, both
//! obfuscated with a per-field key `field_key(gfi)`. The field offset comes from the foff section.

use crate::mem::Memory;
use crate::metadata::DecodedMetadata;
use crate::typenames::{field_modifiers, type_name, ClassNames};

/// Sentinel typeIndex meaning "void" / no type.
const VOID_TI: u32 = 585684949;
const TI_BIAS: u32 = 585684950;
/// Field name de-obfuscation: `decode_str(strsec, (nameEnc ^ 0xA7202EF) - key)`.
const FNAME_XOR: u32 = 0xA7202EF;

/// Per-field key, 
pub fn field_key(gfi: u32) -> u32 {
    let t0 = 0x3122_A154_F98u64
        .wrapping_mul(gfi as u64)
        .wrapping_add(0x8D5_71A5_EC88_21EC);
    let t2 = 1_675_458_389u64.wrapping_mul(t0 >> 19);
    let t4 = 1_795_536_755u64.wrapping_mul(t2 >> 8);
    (t4 >> 18) as u32
}

/// One decoded field.
pub struct Field {
    pub modifiers: String,
    pub type_name: String,
    pub name: String,
    pub offset: u32,
    /// Global field index (for default-value lookup).
    pub gfi: u32,
    /// True if `const ` (LITERAL) — eligible for a `= value` default.
    pub is_const: bool,
}

/// Decode the fields of a type given its `field_start` / `field_count` (from `class_model`).
/// `names` resolves CLASS/VALUETYPE type names for the field types.
pub fn fields<N: ClassNames>(
    dm: &DecodedMetadata,
    names: &N,
    field_start: i32,
    field_count: u32,
    foff_start: usize,
) -> Vec<Field> {
    let mut out = Vec::new();
    if field_start < 0 || field_count == 0 {
        return out;
    }
    let fda = dm.field_defs;
    for j in 0..field_count {
        let gfi = (field_start as u32).wrapping_add(j);
        let key = field_key(gfi);
        let ep = fda + 8 * gfi as usize;
        if !dm.body.readable(ep, 8) {
            continue;
        }
        let ti = dm.body.read_u32(ep).wrapping_sub(key);
        let (type_name_s, modifiers) = if ti == VOID_TI {
            ("void".to_string(), String::new())
        } else {
            let tp = dm.il2cpp_type_offset(ti.wrapping_sub(TI_BIAS) as usize);
            let attrs = if dm.image.readable(tp + 0xB, 1) {
                dm.image.read_u16(tp + 8)
            } else {
                0
            };
            (type_name(dm, names, tp, 0), field_modifiers(attrs))
        };
        let nenc = dm.body.read_u32(ep + 4);
        let name = dm.string((nenc ^ FNAME_XOR).wrapping_sub(key));

        // Field offset from the foff section: foff_arr + 4*(j + foff_start). Thread-static => high byte.
        let op = dm.field_offsets + 4 * (j as usize + foff_start);
        let offset = if dm.body.readable(op, 4) {
            let r = dm.body.read_u32(op);
            if r & 0x0100_0000 != 0 {
                r & 0xFF00_0000
            } else {
                r
            }
        } else {
            0
        };

        let is_const = modifiers.contains("const ");
        out.push(Field {
            modifiers,
            type_name: type_name_s,
            name,
            offset,
            gfi,
            is_const,
        });
    }
    out
}

/// Resolve the per-class field-offset start (`foff_start`) for a type index, via the
/// foff_table_b → v43 chain.
pub fn foff_start(dm: &DecodedMetadata, type_index: usize) -> usize {
    let ib_off = dm.field_off_table_b + 4 * type_index;
    if !dm.body.readable(ib_off, 4) {
        return 0;
    }
    let ib = dm.body.read_i32(ib_off);
    let v43 = dm.foff_v43base + 12 * ib as usize;
    if dm.body.readable(v43 + 0xC, 4) {
        dm.body.read_u32(v43 + 8) as usize
    } else {
        0
    }
}
