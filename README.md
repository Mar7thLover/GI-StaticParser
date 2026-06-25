# static-dumper

A static IL2CPP metadata dumper. It reads the custom-encrypted `global-metadata.dat` and the
main program module (the one holding the IL2CPP/GameAssembly code and metadata tables) directly —
with **no live process** — and emits an [Il2CppDumper](https://github.com/Perfare/Il2CppDumper)-style
`dump.cs`.

## How it works

`global-metadata.dat` is encrypted on disk. Instead of running the target, this tool reproduces the
decryption statically: the metadata body is the raw `.dat` from offset `0x210`, the header is an
embedded blob in the main module's `.rdata` (located by a self-validating scan), and all tables are
decoded with constant-keyed recipes recovered by reverse-engineering. Full details in
[`RECIPE.md`](RECIPE.md).

## Build

```sh
cargo build --release
```

Rust (edition 2021); dependencies are pinned in `Cargo.lock`.

## Usage

```sh
mhydump dump --exe <main-module> --metadata <global-metadata.dat> --out dump.cs
```

| Command | Purpose |
|---|---|
| `pe-validate --exe <m>` | Parse the PE, print sections, flag BSS globals |
| `decode-one --exe <m> --metadata <d> --idx <packed>` | Decode a single string by packed index |
| `header-dump --exe <m> --metadata <d>` | Load metadata, print resolved table offsets |
| `dump --exe <m> --metadata <d> [--only 28,42,...] [--out dump.cs]` | Emit `dump.cs` |

A full dump produces ~82k types / ~405k fields / ~672k methods (80 MB+) in ~1 s.

## Layout

```
src/
  pe.rs            PE32+ parsing
  mem.rs           the Memory trait + byte-buffer backing
  decrypt/         header location + table resolution
  decode_str.rs    string decryption
  metadata.rs      resolved table-base view
  class_model.rs   typeDef reconstruction
  typenames.rs     Il2CppType -> C# name + modifiers
  field_meta.rs    field decoding
  method_meta.rs   method decoding
  default_values.rs  default-value literals
  dump.rs          the full dump walk
RECIPE.md          the decryption recipe
```

## Disclaimer

For educational and interoperability research on software you own or are authorized to analyze. The
constants are specific to one build; a different version needs the recipe re-derived.

## License

[GPL-3.0](LICENSE).
