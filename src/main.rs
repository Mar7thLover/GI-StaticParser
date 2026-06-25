//! CLI entry point. One subcommand per milestone (see the plan).
//!
//! Milestone (a): `mhydump pe-validate <exe>` — parse and print the PE section table + flag BSS.

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "mhydump", about = "Static IL2CPP 'MHY' metadata dumper")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Milestone (a): parse a PE image, print its section table, ImageBase, and flag BSS globals.
    PeValidate {
        /// Path to GameAssembly.exe (or any PE32+ image).
        #[arg(short, long)]
        exe: String,
    },
    /// Milestone (c): decode a single string by packed index from the metadata.
    DecodeOne {
        #[arg(long)]
        exe: String,
        #[arg(long)]
        metadata: String,
        /// Packed string index (offset in low 24 bits, length in next 8). Hex (0x..) or decimal.
        #[arg(long, value_parser = parse_u32)]
        idx: u32,
    },
    /// Milestone (d): load metadata and print every resolved table base.
    HeaderDump {
        #[arg(long)]
        exe: String,
        #[arg(long)]
        metadata: String,
    },
    /// Milestones (e)/(f): emit dump.cs. With --only, restrict to given TypeDefIndices.
    Dump {
        #[arg(long)]
        exe: String,
        #[arg(long)]
        metadata: String,
        /// Output path for dump.cs.
        #[arg(short, long, default_value = "dump.cs")]
        out: String,
        /// Comma-separated TypeDefIndices to emit (milestone e). Omit for the full dump (f).
        #[arg(long, value_delimiter = ',')]
        only: Option<Vec<usize>>,
    },
}

fn parse_u32(s: &str) -> Result<u32, std::num::ParseIntError> {
    if let Some(h) = s.strip_prefix("0x") {
        u32::from_str_radix(h, 16)
    } else {
        s.parse()
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive("mhydump=info".parse()?))
        .with_target(false)
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::PeValidate { exe } => pe_validate(&exe),
        Cmd::DecodeOne { exe, metadata, idx } => decode_one(&exe, &metadata, idx),
        Cmd::HeaderDump { exe, metadata } => header_dump(&exe, &metadata),
        Cmd::Dump { exe, metadata, out, only } => dump_cmd(&exe, &metadata, &out, only.as_deref()),
    }
}

/// Milestones (e)/(f): emit dump.cs.
fn dump_cmd(exe: &str, metadata: &str, out: &str, only: Option<&[usize]>) -> Result<()> {
    let ga = std::fs::read(exe)?;
    let gm = std::fs::read(metadata)?;
    let md = static_mhy_dumper::decrypt::file::load(&ga, &gm)?;
    let dm = static_mhy_dumper::metadata::DecodedMetadata::new(&md);
    let f = std::fs::File::create(out)?;
    let mut w = std::io::BufWriter::new(f);
    let (nt, nf, nm) = static_mhy_dumper::dump::dump_all(&dm, &mut w, only)?;
    use std::io::Write;
    w.flush()?;
    println!("wrote {out}: {nt} types, {nf} fields, {nm} methods");
    Ok(())
}

/// Milestone (c): decode one string by packed index.
fn decode_one(exe: &str, metadata: &str, idx: u32) -> Result<()> {
    let ga = std::fs::read(exe)?;
    let gm = std::fs::read(metadata)?;
    let md = static_mhy_dumper::decrypt::file::load(&ga, &gm)?;
    let dm = static_mhy_dumper::metadata::DecodedMetadata::new(&md);
    let off = idx & 0xFF_FFFF;
    let len = (idx >> 24) & 0xFF;
    println!("idx=0x{idx:08X} (offset=0x{off:X}, len={len}) -> {:?}", dm.string(idx));
    Ok(())
}

/// Milestone (d): print every resolved table base.
fn header_dump(exe: &str, metadata: &str) -> Result<()> {
    let ga = std::fs::read(exe)?;
    let gm = std::fs::read(metadata)?;
    let md = static_mhy_dumper::decrypt::file::load(&ga, &gm)?;
    let dm = static_mhy_dumper::metadata::DecodedMetadata::new(&md);
    println!("Metadata loaded:");
    println!("  header (f418): {} bytes (embedded .rdata MHY blob)", md.header.len());
    println!("  body   (f420): {} bytes (global-metadata.dat[0x210..])", md.body.len());
    println!("\nBody-relative table offsets:");
    for (name, off) in [
        ("strings", dm.strings),
        ("method_defs", dm.method_defs),
        ("params", dm.params),
        ("field_defs", dm.field_defs),
        ("field_offsets", dm.field_offsets),
        ("generic_params", dm.generic_params),
        ("field_off_table_b", dm.field_off_table_b),
        ("foff_v43base", dm.foff_v43base),
        ("default_value_blob", dm.default_value_blob),
        ("field_default_values", dm.field_default_values),
    ] {
        let ok = if off < md.body.len() { "OK" } else { "OOB" };
        println!("  {name:22} body+0x{off:08X}  [{ok}]");
    }
    println!("\nGameAssembly .rdata table file-offsets:");
    println!("  {:22} 0x{:08X}", "typearr", md.tables.typearr);
    println!("  {:22} 0x{:08X}", "methodptrs", md.tables.methodptrs);
    println!("  {:22} 0x{:08X}", "generic_classes", md.tables.generic_classes);
    println!("\nOracle: string idx (len=8, off=0) = {:?}", dm.string((8 << 24) | 0));
    Ok(())
}

/// Milestone (a). Parses the PE, prints sections + ImageBase, and confirms the metadata globals
/// `f418`/`f420` resolve as BSS (in-`.data`-range but beyond RawSize).
fn pe_validate(path: &str) -> Result<()> {
    let bytes = std::fs::read(path)?;
    let img = static_mhy_dumper::pe::Image::parse(&bytes)?;

    println!("ImageBase: 0x{:016X}", img.image_base());
    println!("Sections ({}):", img.sections().len());
    println!(
        "  {:<10} {:<12} {:<12} {:<12} {:<12} flags",
        "name", "VA", "VSize", "raw@file", "rawSize"
    );
    for s in img.sections() {
        println!(
            "  {:<10} VA=0x{:08X} VS=0x{:08X} raw@0x{:08X} rs=0x{:08X} 0x{:08X}{}{}",
            s.name,
            s.virtual_address,
            s.virtual_size,
            s.raw_pointer,
            s.raw_size,
            s.characteristics,
            if s.is_executable() { " X" } else { "" },
            if s.is_writable() { " W" } else { "" },
        );
    }

    // The load-bearing correctness check: f418/f420 are BSS.
    for (name, rva) in [("f418 (header)", 0x521F418u32), ("f420 (body)", 0x521F420u32)] {
        let bss = img.is_bss(rva);
        let file = img.rva_to_file(rva);
        println!(
            "\n{name}: RVA=0x{rva:08X}  BSS={bss}  file_offset={}",
            match file {
                Some(o) => format!("0x{o:X}"),
                None => "<none — BSS/unmapped>".to_string(),
            }
        );
    }

    // IAT: report any file/read APIs (used by the Phase-1 loader RE).
    let io: Vec<_> = img
        .imports()
        .into_iter()
        .filter(|(_, n, _)| {
            n.as_deref().map_or(false, |x| {
                x.eq_ignore_ascii_case("ReadFile")
                    || x.eq_ignore_ascii_case("CreateFileA")
                    || x.eq_ignore_ascii_case("CreateFileW")
            })
        })
        .collect();
    println!("\nFile-IO imports ({}):", io.len());
    for (dll, name, va) in &io {
        println!("  {dll}!{:<14} IAT slot VA=0x{va:016X}", name.as_deref().unwrap_or("?"));
    }
    Ok(())
}
