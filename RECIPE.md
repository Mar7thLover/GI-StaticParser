# Decryption recipe

Offsets and constants are specific to one game build; a different version needs them re-derived.
`ImageBase = 0x140000000`; `va2off` maps a VA to a file offset via the section table.

## Buffers

- **body** = `global-metadata.dat[0x210:]` — the metadata body; raw disk bytes, no bulk decrypt.
- **header** = an embedded `MHY\0` blob in the main module's `.rdata` (`0x600` bytes), located by a
  self-validating scan: the one whose `+272` field yields a string section decoding `"mscorlib"` at
  offset 0. Drives every table offset below.

## Strings — `decode_str(idx)`

`strsec = body + (i32(header+272) - 1426623823)`. `idx` packs offset (low 24b) + length (next 8b).
Each 8-byte block is XOR'd with an evolving key:

```
a   = 0x7EC92DE877F113F2 * off ^ 0x17AE9BC67ADFD24D
c   = 0x2534E544497526A1 * a + 0x54EB1A521F0114C9 ^ 0x68A69E942939701D
key = 0x5CDE4E0562F884EA * c
per qword: out = read_u64(body, strsec+off+8k) ^ key ; key += 0x6C802BDA2DB01DBB
```

`idx == 0xFFFFFFFF` → no string.

## Header-driven table offsets (relative to body)

`strings +272 −1426623823`, `methodDefs +336 −201414367`, `params +420 −178973881`,
`fieldDefs +468 −48572191`, `fieldOffsets +20 −1964484308`, `genericParams +188 −1405585855`,
`fieldOffTableB +436 ^0x6AE94CF7`, `foff_v43base +396 ^0x4B8FDA1A`, `defaultValueBlob +328 ^0x424CD0BF`,
`fieldDefaultValues +524 ^0x24297E49`.

## `.rdata` tables in the main module

Resolved via static pointer chains (file offsets): `typearr = u64[va2off(0x1424387A8+0x18)]` (VA
`0x14296B150`, stride 16, `kind@+0xA`, `data@+0`); `methodptrs = u64[va2off(0x141F2EDD0+0x60)]`
(VA `0x1424388B0`, stride 8, code VAs; RVA = entry − ImageBase); `genericClasses =
u64[va2off(0x1424387A8+0x30)]` (VA `0x141F8B6E0`, stride 32).

## typeDefinitions

One contiguous buffer, stride `0x46`, covering all `tdi` 0..82221.
`TD_BASE = body + i32((0x89E5238C + u32(header+0x90)) & 0xFFFFFFFF)` (= `body+0x355B450`);
`record(tdi) = body + TD_BASE + 0x46*tdi`.

| field | offset | decode |
|---|---|---|
| parentType | `+0x08` | `(0xCEC48090 + u32) & 0xFFFFFFFF` (`0xFFFFFFFF` = none); a typearr index |
| methodStart | `+0x0C` | `u32 − 290622229` (`0xFFFFFFFF` = no methods) |
| fieldStart | `+0x14` | `u32 − 0xD513F0` |
| flags | `+0x18` | `(u16 − 0x9C9A) & 0xFFFF` (TYPE_ATTRIBUTE) |
| nameIndex | `+0x24` | `decode_str((0xDD6271FD + u32) & 0xFFFFFFFF)` |
| namespaceIndex | `+0x28` | `decode_str(u32 ^ 0x558608EC)` |
| fieldCount | `+0x3A` | `(u16 + 5528) & 0xFFFF` |

`method_count`: no direct field — non-sentinel `methodStart` is globally monotonic, so a type's count
is the next-larger `methodStart` minus its own (0 for sentinels).

## Fields / methods / defaults

- **fieldDef** (stride 8): `type@+0`, `name@+4`, both keyed by `field_key(gfi)`. `type = u32 − key`
  (`585684949` = void, else typearr index `value − 585684950`); `name = decode_str((u32 ^ 0xA7202EF) − key)`.
- **methodDef** (stride 26): `mkey(gmi)` derives `v30`, which de-obfuscates name/flags/param/return indices.
- Field offset: `fieldOffsets + 4*(j + foff_start)`; high byte = thread-static.
- `const` defaults: `fieldDefaultValues` table (stride 12) + `defaultValueBlob`.

Exact `field_key` / `mkey` / param-key implementations are in `src/field_meta.rs` and `src/method_meta.rs`.

## Notes

`get_class` (`0x1404B4750` → `.upx0 0x15766AA1D`) is plain x86-64 under heavy junk-instruction
obfuscation (dead-register writes, flag noise, `e9 00000000` nop-jmps), not a bytecode VM — the
typeDef field recipes above were recovered by de-noising it. Verified across all 82222 types
(name anchors, parent chain Enum→ValueType→Object→null, no out-of-range parents).
