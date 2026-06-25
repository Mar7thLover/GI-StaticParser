//! Type-name resolution and C# modifier formatting.
//!
//! `type_name` resolves an `Il2CppType` to a C# type name: primitive kinds map directly;
//! CLASS/VALUETYPE resolve their typeDefIndex → short name via a [`ClassNames`] resolver (implemented
//! by `class_model`); ptr/array/generic kinds recurse.

use crate::mem::Memory;
use crate::metadata::DecodedMetadata;

/// Resolves a type-definition index to its short C# name (e.g. "List`1" → caller strips the arity).
/// Implemented by `class_model` over the metadata typeDef table. Kept as a trait so `type_name` does
/// not depend on the full class model and can be tested with a stub.
pub trait ClassNames {
    /// Short name of the type at `type_def_index`, or `None` if out of range / unreadable.
    fn short_name(&self, type_def_index: usize) -> Option<String>;
}

/// IL2CPP `METHOD_ATTRIBUTE_*` flags → C# modifiers. 
pub fn method_modifiers(f: u32) -> String {
    let mut s = String::new();
    match f & 0x7 {
        1 => s.push_str("private "),
        2 => s.push_str("private protected "),
        3 => s.push_str("internal "),
        4 => s.push_str("protected "),
        5 => s.push_str("protected internal "),
        6 => s.push_str("public "),
        _ => {}
    }
    if f & 0x10 != 0 {
        s.push_str("static ");
    }
    if f & 0x400 != 0 {
        s.push_str("abstract ");
    } else if f & 0x40 != 0 {
        if f & 0x100 != 0 {
            s.push_str("virtual ");
        } else if f & 0x20 != 0 {
            s.push_str("sealed override ");
        } else {
            s.push_str("override ");
        }
    }
    if f & 0x2000 != 0 {
        s.push_str("extern ");
    }
    s
}

/// FIELD_ATTRIBUTE flags → C# field modifiers. 
pub fn field_modifiers(attrs: u16) -> String {
    let mut s = String::new();
    match attrs & 0x7 {
        1 => s.push_str("private "),
        2 => s.push_str("private protected "),
        3 => s.push_str("internal "),
        4 => s.push_str("protected "),
        5 => s.push_str("protected internal "),
        6 => s.push_str("public "),
        _ => {}
    }
    if attrs & 0x40 != 0 {
        s.push_str("const ");
    } else if attrs & 0x10 != 0 {
        s.push_str("static ");
        if attrs & 0x20 != 0 {
            s.push_str("readonly ");
        }
    } else if attrs & 0x20 != 0 {
        s.push_str("readonly ");
    }
    s
}

/// Resolve an `Il2CppType` (at `tp`, a file offset into the GA image / typearr space) to a C# type
/// name. Decodes The primitive kinds and ptr/array/generic structure are
/// identical; CLASS/VALUETYPE names come from `names` (typeDefIndex → short name).
///
/// `tp` is an offset into `dm.image` (the GA image, where typearr lives). Recurses for ptr/array/
/// generic argument element types, which are also typearr offsets.
pub fn type_name<N: ClassNames>(dm: &DecodedMetadata, names: &N, tp: usize, depth: u32) -> String {
    let img = &dm.image;
    if depth > 8 || !img.readable(tp, 0x10) {
        return "object".into();
    }
    let kind = img.read_u8(tp + 0xA);
    let prim = match kind {
        1 => "void", 2 => "bool", 3 => "char", 4 => "sbyte", 5 => "byte",
        6 => "short", 7 => "ushort", 8 => "int", 9 => "uint", 0xA => "long",
        0xB => "ulong", 0xC => "float", 0xD => "double", 0xE => "string",
        0x16 => "TypedReference", 0x18 => "IntPtr", 0x19 => "UIntPtr", 0x1C => "object",
        _ => "",
    };
    if !prim.is_empty() {
        return prim.into();
    }
    match kind {
        0x11 | 0x12 => {
            // CLASS / VALUETYPE: data = typeDefIndex. Resolve short name via the class model.
            let tdi = img.read_u32(tp) as usize;
            match names.short_name(tdi) {
                Some(nm) => match nm.as_str() {
                    // Il2CppDumper keyword-maps by SHORT name regardless of namespace.
                    "Object" => "object".into(),
                    "String" => "string".into(),
                    _ => nm,
                },
                None => "object".into(),
            }
        }
        0xF => match type_data_ptr(dm, tp) {
            Some(et) => format!("{}*", type_name(dm, names, et, depth + 1)),
            None => "object*".into(),
        },
        0x1D => match type_data_ptr(dm, tp) {
            Some(et) => format!("{}[]", type_name(dm, names, et, depth + 1)),
            None => "object[]".into(),
        },
        0x14 => {
            // SZARRAY/ARRAY: data -> Il2CppArrayType { etype@0, rank@8 }. The element type and the
            // array-type struct are pointers (VAs into .rdata); map each VA → file offset.
            match type_data_ptr(dm, tp) {
                Some(at) if img.readable(at, 9) => {
                    let etype_off = va_ptr_at(dm, at).unwrap_or(at);
                    let et = type_name(dm, names, etype_off, depth + 1);
                    let rank = img.read_u8(at + 8).max(1) as usize;
                    format!("{et}[{}]", ",".repeat(rank - 1))
                }
                _ => "Array".into(),
            }
        }
        0x13 | 0x1E => {
            // Generic parameter (VAR/MVAR). Name from the genericParameters table (stride 14), keyed
            // per global generic-parameter index.
            let data = img.read_u32(tp);
            if data == 0xFFFF_FFFF {
                return "T".into();
            }
            let entry = dm.generic_params + 14 * data as usize;
            if !dm.body.readable(entry, 4) {
                return "T".into();
            }
            let raw = dm.body.read_u32(entry);
            let inner = (49448u64.wrapping_mul(data as u64).wrapping_add(1_205_237_949)) ^ 0x49F3_BD14;
            let key = ((1_534_055_843u64.wrapping_mul(inner) >> 21).wrapping_add(325_917_417)
                ^ 0x69F9_2E4F) as u32;
            let nm = dm.string(key ^ raw ^ 0x7803_C4DF);
            if nm.is_empty() {
                "T".into()
            } else {
                nm
            }
        }
        0x15 => {
            // GENERICINST: data = generic-class index into genericClasses (GA image). Resolve the
            // def name; arguments need the inst table (deferred — see class_model).
            generic_inst_name(dm, names, tp, depth)
        }
        _ => format!("object/*k{kind:X}*/"),
    }
}

/// Read the `data` pointer of an Il2CppType at GA-image offset `tp` (offset +0, an 8-byte VA into
/// `.rdata`) and map it to a GA-image file offset. Used for ptr/array element types.
fn type_data_ptr(dm: &DecodedMetadata, tp: usize) -> Option<usize> {
    let va = dm.image.read_u64_opt(tp)?;
    dm.va_to_image_off(va)
}

/// Read an 8-byte VA at GA-image offset `at` and map it to a file offset (for the array element-type
/// pointer inside an Il2CppArrayType).
fn va_ptr_at(dm: &DecodedMetadata, at: usize) -> Option<usize> {
    let va = dm.image.read_u64_opt(at)?;
    dm.va_to_image_off(va)
}

/// GENERICINST name: `Def<...>` — def name from genericClasses[data].typeDefIndex; args deferred.
fn generic_inst_name<N: ClassNames>(
    dm: &DecodedMetadata,
    names: &N,
    tp: usize,
    _depth: u32,
) -> String {
    let data = dm.image.read_u32(tp) as usize;
    let entry = dm.tables.generic_classes + 32 * data;
    let mut name = match dm.image.read_u32_opt(entry) {
        Some(def_idx) => names.short_name(def_idx as usize).unwrap_or_else(|| "object".into()),
        None => "object".into(),
    };
    if let Some(b) = name.find('`') {
        name.truncate(b);
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::class_model::ClassModel;

    #[test]
    fn type_name_resolves_class_via_typearr() {
        let (Ok(ga), Ok(gm)) = (
            std::fs::read("Original/GameAssembly.exe"),
            std::fs::read("Original/global-metadata.dat"),
        ) else {
            eprintln!("[skip] inputs not present");
            return;
        };
        let md = crate::decrypt::file::load(&ga, &gm).expect("load");
        let dm = DecodedMetadata::new(&md);
        let cm = ClassModel::new(&dm);
        // Find a CLASS/VALUETYPE Il2CppType whose data is a known tdi, and confirm type_name returns
        // the class_model name (modulo Object/String keyword mapping).
        let mut checked = 0;
        for ti in 0..5000usize {
            let off = dm.il2cpp_type_offset(ti);
            let (kind, data) = match dm.il2cpp_type(ti) {
                Some(v) => v,
                None => break,
            };
            if matches!(kind, 0x11 | 0x12) && (data as usize) < crate::class_model::TYPE_COUNT {
                let via_type = type_name(&dm, &cm, off, 0);
                let direct = cm.name(data as usize);
                let expected = match direct.as_str() {
                    "Object" => "object".to_string(),
                    "String" => "string".to_string(),
                    other => other.to_string(),
                };
                if !direct.is_empty() {
                    assert_eq!(via_type, expected, "type_name mismatch at typearr[{ti}] tdi={data}");
                    checked += 1;
                }
            }
            if checked >= 50 {
                break;
            }
        }
        assert!(checked >= 20, "expected to check >=20 class types, got {checked}");
    }
}
