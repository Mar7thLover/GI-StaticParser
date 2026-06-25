//! The full dump walk — emitting Il2CppDumper-style `dump.cs` from the
//! decrypted metadata. Type headers (namespace, visibility/modifier/keyword, base clause), fields,
//! and methods follow Il2CppDumper formatting.

use std::io::Write;

use crate::class_model::{ClassModel, TYPE_COUNT};
use crate::default_values::dv_literal;
use crate::field_meta::{self, foff_start};
use crate::mem::Memory;
use crate::method_meta;
use crate::metadata::DecodedMetadata;

/// Precomputed method_count for every type, via the sentinel-aware sequential rule:
/// `methodStart` is monotonic over non-sentinel (`0xFFFFFFFF`) entries; a type's method_count is the
/// next larger methodStart minus its own (0 for sentinel types).
fn method_counts(cm: &ClassModel) -> Vec<u32> {
    // Collect (tdi, methodStart) for non-sentinel types, sorted by methodStart.
    let starts: Vec<u32> = (0..TYPE_COUNT)
        .map(|tdi| cm.type_def(tdi).map(|t| t.method_start).unwrap_or(u32::MAX))
        .collect();
    let mut sorted: Vec<u32> = starts.iter().copied().filter(|&m| m != u32::MAX).collect();
    sorted.sort_unstable();
    sorted.dedup();
    let mut counts = vec![0u32; TYPE_COUNT];
    for (tdi, &m) in starts.iter().enumerate() {
        if m == u32::MAX {
            continue;
        }
        // next strictly-greater methodStart in the sorted unique list.
        let next = match sorted.binary_search(&m) {
            Ok(i) => sorted.get(i + 1).copied(),
            Err(i) => sorted.get(i).copied(),
        };
        counts[tdi] = next.map(|n| n.saturating_sub(m)).unwrap_or(0);
    }
    counts
}

/// Field default values: build `gfi -> (typeIndex, dataIndex)` from the fieldDefaultValues table
/// (stride 12, sorted ascending by fieldIndex). 
fn field_default_values(dm: &DecodedMetadata) -> std::collections::HashMap<u32, (i32, i32)> {
    let mut dv = std::collections::HashMap::new();
    let base = dm.field_default_values;
    let mut prev: i64 = -1;
    for i in 0..400_000usize {
        let e = base + 12 * i;
        if !dm.body.readable(e, 12) {
            break;
        }
        let type_index = dm.body.read_i32(e);
        let field_index = dm.body.read_i32(e + 4);
        let data_index = dm.body.read_i32(e + 8);
        if (field_index as i64) <= prev
            || field_index < 0
            || field_index > 2_000_000
            || type_index < -1
            || type_index > 2_000_000
            || data_index < -1
        {
            break;
        }
        prev = field_index as i64;
        dv.insert(field_index as u32, (type_index, data_index));
    }
    dv
}

/// Walk all type definitions and write `dump.cs` to `w`. Optionally restrict to a set of type
/// indices (for the anchor milestone). Returns `(ntypes, nfields, nmethods)`.
pub fn dump_all<W: Write>(
    dm: &DecodedMetadata,
    w: &mut W,
    only: Option<&[usize]>,
) -> std::io::Result<(u64, u64, u64)> {
    let cm = ClassModel::new(dm);
    let mcounts = method_counts(&cm);
    let dv = field_default_values(dm);

    let indices: Vec<usize> = match only {
        Some(list) => list.to_vec(),
        None => (0..TYPE_COUNT).collect(),
    };

    let (mut ntypes, mut nfields, mut nmethods) = (0u64, 0u64, 0u64);
    for &i in &indices {
        let Some(td) = cm.type_def(i) else { continue };
        if td.name.is_empty() {
            continue;
        }
        ntypes += 1;

        // Parent name (for base clause + kind discrimination). Resolve via the parent's typeDef when
        // it's a plain CLASS/VALUETYPE/OBJECT; generic-instance parents go through type_name.
        let pname = match cm.parent_type_def(i) {
            Some(ptdi) => cm.name(ptdi as usize),
            None => String::new(),
        };

        let flags = td.flags;
        // kind: 0 class, 1 struct, 2 enum, 3 interface .
        let kind: u8 = if flags & 0x20 != 0 {
            3
        } else if pname == "Enum" {
            2
        } else if pname == "ValueType" && td.name != "Enum" {
            1
        } else {
            0
        };
        let vis_word = match flags & 0x7 {
            1 => "public ",
            2 => "", // NestedPublic -> bare
            3 => "private ",
            4 => "protected ",
            7 => "protected internal ",
            _ => "internal ",
        };
        let is_abstract = flags & 0x80 != 0;
        let is_sealed = flags & 0x100 != 0;
        let (modifier, keyword) = match kind {
            1 => (if is_sealed { "sealed " } else { "" }, "struct"),
            2 => ("", "enum"),
            3 => (if is_abstract { "abstract " } else { "" }, "interface"),
            _ => (
                if is_abstract && is_sealed {
                    "static "
                } else if is_sealed {
                    "sealed "
                } else {
                    ""
                },
                "class",
            ),
        };
        let base_clause = if kind == 0
            && !pname.is_empty()
            && pname != "Object"
            && pname != "ValueType"
            && pname.len() < 200
        {
            format!(" : {pname}")
        } else {
            String::new()
        };

        writeln!(w, "\n// Namespace: {}", td.namespace)?;
        writeln!(
            w,
            "{vis_word}{modifier}{keyword} {}{base_clause} // TypeDefIndex: {i}\n{{",
            td.name
        )?;

        // Fields.
        if td.field_start >= 0 && td.field_count > 0 {
            let foff = foff_start(dm, i);
            let fields = field_meta::fields(dm, &cm, td.field_start, td.field_count, foff);
            if !fields.is_empty() {
                writeln!(w, "\t// Fields")?;
            }
            for f in fields {
                let eq = if f.is_const {
                    match dv.get(&f.gfi) {
                        Some(&(ti, di)) => dv_literal(&dm.image, dm.tables.typearr, &dm.body, dm.default_value_blob, ti, di)
                            .map(|v| format!(" = {v}"))
                            .unwrap_or_default(),
                        None => String::new(),
                    }
                } else {
                    String::new()
                };
                writeln!(
                    w,
                    "\t{}{} {}{eq}; // Offset: 0x{:X}",
                    f.modifiers, f.type_name, f.name, f.offset
                )?;
                nfields += 1;
            }
        }

        // Methods.
        let mc = mcounts[i];
        if mc > 0 {
            let methods = method_meta::methods(dm, &cm, td.method_start, mc);
            if !methods.is_empty() {
                writeln!(w, "\t// Methods")?;
            }
            for m in methods {
                writeln!(
                    w,
                    "\t// RVA: 0x{:X} Flags: 0x{:X}\n\t{}{} {}({});",
                    m.rva,
                    m.flags,
                    m.modifiers,
                    m.return_type,
                    m.name,
                    m.params.join(", ")
                )?;
                nmethods += 1;
            }
        }

        writeln!(w, "}}")?;
    }
    Ok((ntypes, nfields, nmethods))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dumps_anchor_types() {
        let (Ok(ga), Ok(gm)) = (
            std::fs::read("Original/GameAssembly.exe"),
            std::fs::read("Original/global-metadata.dat"),
        ) else {
            eprintln!("[skip] inputs not present");
            return;
        };
        let md = crate::decrypt::file::load(&ga, &gm).expect("load");
        let dm = DecodedMetadata::new(&md);
        let mut buf = Vec::new();
        let (nt, nf, nm) = dump_all(&dm, &mut buf, Some(&[28, 42, 204, 371])).expect("dump");
        let out = String::from_utf8_lossy(&buf);
        eprintln!("{out}");
        assert_eq!(nt, 4);
        // CodePointIndexer: internal class with 4 fields incl ranges/TotalCount.
        assert!(out.contains("class CodePointIndexer"));
        assert!(out.contains("int TotalCount"));
        assert!(out.contains("int defaultCP"));
        // ExtenderType is a nested enum.
        assert!(out.contains("enum ExtenderType"));
        // Object is the root class.
        assert!(out.contains("class Object"));
        let _ = (nf, nm);
    }

    /// Known type-header anchors — type-header rendering (visibility/modifier/keyword/base
    /// (visibility/modifier/keyword/base clause).
    #[test]
    fn probe_tflags_anchors() {
        let (Ok(ga), Ok(gm)) = (
            std::fs::read("Original/GameAssembly.exe"),
            std::fs::read("Original/global-metadata.dat"),
        ) else {
            eprintln!("[skip] inputs not present");
            return;
        };
        let md = crate::decrypt::file::load(&ga, &gm).expect("load");
        let dm = DecodedMetadata::new(&md);
        let mut buf = Vec::new();
        dump_all(&dm, &mut buf, Some(&[1, 2, 4, 22, 88, 105, 245])).expect("dump");
        let out = String::from_utf8_lossy(&buf);
        for expect in [
            "internal sealed class Locale // TypeDefIndex: 1",
            "internal static class SR // TypeDefIndex: 2",
            "internal sealed struct RuntimeClassHandle // TypeDefIndex: 4",
            "internal class SecurityParser : SmallXmlParser // TypeDefIndex: 22",
            "internal abstract interface IRegistryApi // TypeDefIndex: 88",
            "public class SafeHandleZeroOrMinusOneIsInvalid : SafeHandle // TypeDefIndex: 105",
            "public abstract interface IDisposable // TypeDefIndex: 245",
        ] {
            assert!(out.contains(expect), "missing anchor: {expect}");
        }
    }

    /// Full dump — writes dump.cs and checks gross counts. Ignored by default (slow / writes a
    /// file); run with `cargo test --lib full_dump -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn full_dump() {
        let (Ok(ga), Ok(gm)) = (
            std::fs::read("Original/GameAssembly.exe"),
            std::fs::read("Original/global-metadata.dat"),
        ) else {
            eprintln!("[skip] inputs not present");
            return;
        };
        let md = crate::decrypt::file::load(&ga, &gm).expect("load");
        let dm = DecodedMetadata::new(&md);
        let f = std::fs::File::create("dump.cs").expect("create");
        let mut w = std::io::BufWriter::new(f);
        let (nt, nf, nm) = dump_all(&dm, &mut w, None).expect("dump");
        w.flush().unwrap();
        eprintln!("dump.cs: {nt} types, {nf} fields, {nm} methods");
        assert!(nt > 80000, "expected >80000 types, got {nt}");
        assert!(nf > 100000, "expected many fields, got {nf}");
        assert!(nm > 300000, "expected many methods, got {nm}");
    }
}
