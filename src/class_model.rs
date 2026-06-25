//! Per-type metadata from the typeDefinitions table: name / namespace / parent / flags / fieldStart
//! / methodStart / counts.
//!
//! The typeDef table is one contiguous buffer of stride 0x46 covering all `tdi` 0..82221, with
//! constant-keyed fields (see `RECIPE.md` §5):
//!
//! ```text
//!   TD_BASE  = body + i32((0x89E5238C + u32(header+0x90)) & 0xFFFFFFFF)   ( = body + 0x355B450 )
//!   stride   = 0x46
//!   record(tdi) = body + TD_BASE + 0x46*tdi
//!   name        = decode_str((0xDD6271FD + u32(rec+0x24)) & 0xFFFFFFFF)
//!   namespace   = decode_str(u32(rec+0x28) ^ 0x558608EC)
//!   parent      = typearr[(0xCEC48090 + u32(rec+0x08)) & 0xFFFFFFFF].data   (0xFFFFFFFF => null)
//!   flags       = (u16(rec+0x18) - 0x9C9A) & 0xFFFF        [TYPE_ATTRIBUTE]
//!   fieldStart  = u32(rec+0x14) - 0xD513F0
//!   methodStart = u32(rec+0x0C) - 290622229
//!   fieldCount  = (u16(rec+0x3A) + 5528) & 0xFFFF
//! ```

use crate::mem::Memory;
use crate::metadata::DecodedMetadata;
use crate::typenames::ClassNames;

/// Total type count (TypeDefinitionIndex range).
pub const TYPE_COUNT: usize = 82222;

const TD_STRIDE: usize = 0x46;
const TD_BASE_HDR_OFF: usize = 0x90;
const TD_BASE_BIAS: u32 = 0x89E5_238C;

const NAME_BIAS: u32 = 0xDD62_71FD;
const NS_XOR: u32 = 0x5586_08EC;
const PARENT_BIAS: u32 = 0xCEC4_8090;
const FLAGS_BIAS: u16 = 0x9C9A;
const FIELDSTART_BIAS: u32 = 0x00D5_13F0;
const METHODSTART_BIAS: u32 = 290_622_229;
const FIELDCOUNT_BIAS: u16 = 5528;

/// Decoded view of one typeDef record. `ClassModel::type_def` builds these on demand.
#[derive(Debug, Clone)]
pub struct TypeDef {
    pub name: String,
    pub namespace: String,
    /// Parent's Il2CppType index (into typearr), or `None` for a null parent (interfaces and the
    /// roots). Resolve to a name via `type_name` — this correctly handles generic-instance parents
    /// (kind 0x15), not just plain CLASS/VALUETYPE.
    pub parent_type: Option<u32>,
    pub flags: u32,
    pub field_start: i32,
    pub method_start: u32,
    pub field_count: u32,
}

/// Reconstructs per-type metadata from the decrypted body + GA image (typearr). Wraps a
/// [`DecodedMetadata`] and the resolved typeDef table base.
pub struct ClassModel<'a, 'm> {
    dm: &'a DecodedMetadata<'m>,
    td_base: usize,
}

impl<'a, 'm> ClassModel<'a, 'm> {
    pub fn new(dm: &'a DecodedMetadata<'m>) -> Self {
        // TD_BASE = body + i32((0x89E5238C + u32(header+0x90)) & 0xFFFFFFFF)
        let raw = TD_BASE_BIAS.wrapping_add(dm.header.read_u32(TD_BASE_HDR_OFF));
        let td_base = raw as i32 as usize; // sign-extend then index (positive in practice)
        Self { dm, td_base }
    }

    /// File offset of the resolved typeDef-table base within the body buffer.
    pub fn td_base(&self) -> usize {
        self.td_base
    }

    #[inline]
    fn record(&self, tdi: usize) -> usize {
        self.td_base + TD_STRIDE * tdi
    }

    /// Decode the full typeDef record for a type index. Returns `None` if the record is unreadable.
    pub fn type_def(&self, tdi: usize) -> Option<TypeDef> {
        if tdi >= TYPE_COUNT {
            return None;
        }
        let r = self.record(tdi);
        if !self.dm.body.readable(r, TD_STRIDE) {
            return None;
        }
        let name = self.name(tdi);
        let namespace = self.namespace(tdi);
        let parent_type = self.parent_type(tdi);
        let flags = (self.dm.body.read_u16(r + 0x18).wrapping_sub(FLAGS_BIAS)) as u32;
        let field_start = self.dm.body.read_u32(r + 0x14).wrapping_sub(FIELDSTART_BIAS) as i32;
        let method_start = self.dm.body.read_u32(r + 0x0C).wrapping_sub(METHODSTART_BIAS);
        let field_count =
            (self.dm.body.read_u16(r + 0x3A).wrapping_add(FIELDCOUNT_BIAS)) as u32 & 0xFFFF;
        Some(TypeDef {
            name,
            namespace,
            parent_type,
            flags,
            field_start,
            method_start,
            field_count,
        })
    }

    /// Type name: `decode_str((0xDD6271FD + u32(rec+0x24)) & 0xFFFFFFFF)`.
    pub fn name(&self, tdi: usize) -> String {
        let r = self.record(tdi);
        let idx = NAME_BIAS.wrapping_add(self.dm.body.read_u32(r + 0x24));
        self.dm.string(idx)
    }

    /// Namespace: `decode_str(u32(rec+0x28) ^ 0x558608EC)`.
    pub fn namespace(&self, tdi: usize) -> String {
        let r = self.record(tdi);
        let idx = self.dm.body.read_u32(r + 0x28) ^ NS_XOR;
        self.dm.string(idx)
    }

    /// Parent's Il2CppType index: `(0xCEC48090 + u32(rec+0x08)) & 0xFFFFFFFF`. `0xFFFFFFFF` means no
    /// parent. The index points into typearr; resolve to a name via `type_name` (handles plain
    /// CLASS/VALUETYPE *and* generic-instance parents, kind 0x15).
    pub fn parent_type(&self, tdi: usize) -> Option<u32> {
        let r = self.record(tdi);
        let ptype = PARENT_BIAS.wrapping_add(self.dm.body.read_u32(r + 0x08));
        if ptype == 0xFFFF_FFFF {
            None
        } else {
            Some(ptype)
        }
    }

    /// Convenience: the parent's typeDefIndex when the parent resolves to a concrete type definition.
    /// Handles CLASS/VALUETYPE (kind 0x11/0x12) and the OBJECT primitive (kind 0x1C, used for the
    /// `System.Object` root) — all three carry the parent typeDefIndex in `data`. Returns `None` for
    /// null parents and generic-instance parents (kind 0x15), whose name comes via `type_name`.
    pub fn parent_type_def(&self, tdi: usize) -> Option<u32> {
        let ptype = self.parent_type(tdi)?;
        let (kind, data) = self.dm.il2cpp_type(ptype as usize)?;
        if matches!(kind, 0x11 | 0x12 | 0x1C) {
            Some(data)
        } else {
            None
        }
    }
}

/// `ClassModel` resolves CLASS/VALUETYPE typeDefIndex → short name for `type_name`.
impl<'a, 'm> ClassNames for ClassModel<'a, 'm> {
    fn short_name(&self, type_def_index: usize) -> Option<String> {
        if type_def_index >= TYPE_COUNT {
            return None;
        }
        let n = self.name(type_def_index);
        if n.is_empty() {
            None
        } else {
            Some(n)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load() -> Option<crate::decrypt::Metadata> {
        let ga = std::fs::read("Original/GenshinImpact.exe").ok()?;
        let gm = std::fs::read("Original/global-metadata.dat").ok()?;
        crate::decrypt::file::load(&ga, &gm).ok()
    }

    #[test]
    fn name_anchors() {
        let Some(md) = load() else {
            eprintln!("[skip] inputs not present");
            return;
        };
        let dm = DecodedMetadata::new(&md);
        let cm = ClassModel::new(&dm);
        // TD_BASE resolves to body+0x355B450.
        assert_eq!(cm.td_base(), 0x355B450);
        for (tdi, exp) in [
            (28usize, "CodePointIndexer"),
            (42, "ExtenderType"),
            (204, "Enum"),
            (314, "Type"),
            (371, "Object"),
            (405, "ValueType"),
            (545, "FieldInfo"),
        ] {
            assert_eq!(cm.name(tdi), exp, "name(tdi={tdi})");
        }
        assert_eq!(cm.namespace(371), "System");
    }

    #[test]
    fn parent_chain() {
        let Some(md) = load() else {
            eprintln!("[skip] inputs not present");
            return;
        };
        let dm = DecodedMetadata::new(&md);
        let cm = ClassModel::new(&dm);
        // Enum -> ValueType -> Object -> null (all plain CLASS parents).
        assert_eq!(cm.parent_type_def(204), Some(405)); // Enum -> ValueType
        assert_eq!(cm.parent_type_def(405), Some(371)); // ValueType -> Object
        assert_eq!(cm.parent_type_def(371), None); // Object -> null
        assert_eq!(cm.parent_type_def(42), Some(204)); // ExtenderType -> Enum
    }

    #[test]
    fn full_range_parent_sanity() {
        let Some(md) = load() else {
            eprintln!("[skip] inputs not present");
            return;
        };
        let dm = DecodedMetadata::new(&md);
        let cm = ClassModel::new(&dm);
        // Every parent_type must be either null or a readable Il2CppType (kind ∈ [1,0x1F]); the
        // generic-instance parents (kind 0x15) are valid and resolve via type_name, not a plain tdi.
        let (mut null, mut valid, mut bad) = (0u32, 0u32, 0u32);
        for tdi in 0..TYPE_COUNT {
            match cm.parent_type(tdi) {
                None => null += 1,
                Some(pt) => match dm.il2cpp_type(pt as usize) {
                    Some((k, _)) if (1..=0x1F).contains(&k) => valid += 1,
                    _ => bad += 1,
                },
            }
        }
        assert_eq!(bad, 0, "every non-null parent must be a valid Il2CppType");
        assert!(valid > 80000, "got {valid} valid parents");
        assert!(null > 1000 && null < 3000, "got {null} null parents");
    }
}
