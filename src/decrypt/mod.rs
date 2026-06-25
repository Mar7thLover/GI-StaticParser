//! Decryption strategy: how the decrypted `(header, body)` buffers are produced.
//!
//! The breakthrough (oracle-verified, see memory `static-decrypt-solved`): there is NO bulk body
//! decrypt. The metadata body is simply the on-disk `global-metadata.dat` from offset `0x210`, and
//! the metadata *header* (`f418`) is an embedded `.rdata` blob inside `GameAssembly.exe` (a second
//! "MHY" header). Per-string/per-field decryption is then applied lazily by the ported per-string/per-field
//! logic, exactly as at runtime. So the `File` strategy needs no key schedule — only to slice the
//! buffers out of the two input files.
//!
//! Three runtime tables (`typearr`, `methodptrs`, `genericClasses`) live in `GameAssembly.exe`'s
//! `.rdata` (written into the `base+0x521Fxxx` globals by the static registration fn `0x1402A7C20`),
//! so we keep the whole exe image around and expose those table VAs.

pub mod file;

/// Owned decrypted metadata plus the GameAssembly image needed for the .rdata tables.
pub struct Metadata {
    /// The `f418` header struct (the embedded `.rdata` "MHY" blob, ≥0x1A0 bytes).
    pub header: Vec<u8>,
    /// The `f420` body base = `global-metadata.dat[0x210..]`.
    pub body: Vec<u8>,
    /// The full `GameAssembly.exe` bytes (for `.rdata`-resident tables: typearr/methodptrs/etc.).
    pub game_assembly: Vec<u8>,
    /// Resolved table locations (file offsets into `game_assembly`) + ImageBase.
    pub tables: Tables,
}

/// Locations of the three runtime tables, as file offsets into [`Metadata::game_assembly`], plus the
/// image base for RVA math. Resolved by [`file::load`] from the static pointer chains.
#[derive(Clone, Copy, Debug)]
pub struct Tables {
    pub image_base: u64,
    /// Il2CppType array (stride 16; kind@+0xA, data@+0). File offset into game_assembly.
    pub typearr: usize,
    /// Method code-pointer array (stride 8; each entry a code VA). File offset.
    pub methodptrs: usize,
    /// Il2CppGenericClass array (stride 32; entry+0 = typeDefIndex). File offset.
    pub generic_classes: usize,
    /// `.rdata` section: VA start and file-offset start, for VA→file mapping of Il2CppType `data`
    /// pointers (which are VAs into `.rdata`). `rdata_va_start` is `ImageBase + section RVA`.
    pub rdata_va_start: u64,
    pub rdata_file_start: usize,
    pub rdata_size: usize,
}
