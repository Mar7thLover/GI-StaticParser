//! Static, assembly-scan-based IL2CPP "MHY" metadata dumper.
//!
//! Reads the on-disk files (`GenshinImpact.exe`, `global-metadata.dat`) and emits an
//! Il2CppDumper-style `dump.cs` purely statically — no live process. The decryption recipe (all
//! offsets/constants/algorithms) is documented in `RECIPE.md`.
//!
//! Copyright (C) 2026. Licensed under the GNU General Public License v3.0 (see LICENSE).

pub mod class_model;
pub mod decode_str;
pub mod decrypt;
pub mod default_values;
pub mod dump;
pub mod field_meta;
pub mod mem;
pub mod metadata;
pub mod method_meta;
pub mod pe;
pub mod typenames;
