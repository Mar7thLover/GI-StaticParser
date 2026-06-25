//! Field/enum default-value decoding (`fmt_net` + `dv_literal`),
//! read layer swapped to [`Memory`]. `fmt_net` is pure (no memory); `dv_literal` reads the value
//! type's kind from typearr (GA image) and the value bytes from the default-value blob (body).

use crate::mem::Memory;

/// Format a float/double like .NET's `ToString()` (G15 for double, G7 for float). Pure port.
pub fn fmt_net(v: f64, sig: usize) -> String {
    if v.is_nan() {
        return "NaN".into();
    }
    if v.is_infinite() {
        return if v < 0.0 { "-Infinity".into() } else { "Infinity".into() };
    }
    if v == 0.0 {
        return "0".into();
    }
    let neg = v < 0.0;
    let s = format!("{:.*e}", sig - 1, v.abs());
    let (mant, exp_s) = s.split_once('e').unwrap();
    let exp: i32 = exp_s.parse().unwrap();
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let trimmed = digits.trim_end_matches('0');
    let digits = if trimmed.is_empty() { "0" } else { trimmed };
    let nd = digits.len();
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    if exp < -4 || exp >= sig as i32 {
        out.push_str(&digits[..1]);
        if nd > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('E');
        out.push(if exp < 0 { '-' } else { '+' });
        out.push_str(&format!("{:02}", exp.abs()));
    } else if exp >= 0 {
        let ip = exp as usize + 1;
        if nd <= ip {
            out.push_str(digits);
            out.push_str(&"0".repeat(ip - nd));
        } else {
            out.push_str(&digits[..ip]);
            out.push('.');
            out.push_str(&digits[ip..]);
        }
    } else {
        out.push_str("0.");
        out.push_str(&"0".repeat((-exp - 1) as usize));
        out.push_str(digits);
    }
    out
}

/// Decode a field/enum default value to its C# literal.
/// `type_mem` addresses the typearr (GA image); `blob_mem` addresses the body (default-value blob).
/// `ti` = value typeIndex (kind @ typearr+16*ti+0xA), `di` = dataIndex into the blob.
pub fn dv_literal<T: Memory, B: Memory>(
    type_mem: &T,
    typearr: usize,
    blob_mem: &B,
    blob_base: usize,
    ti: i32,
    di: i32,
) -> Option<String> {
    if ti < 0 || di < 0 {
        return None;
    }
    let tp = typearr + 16 * ti as usize;
    if !type_mem.readable(tp, 16) {
        return None;
    }
    let kind = type_mem.read_u8(tp + 0xA);
    let b = blob_base + di as usize;
    macro_rules! rd {
        ($read:ident, $n:expr) => {{
            if !blob_mem.readable(b, $n) {
                return None;
            }
            blob_mem.$read(b)
        }};
    }
    Some(match kind {
        0x02 => if rd!(read_u8, 1) != 0 { "true".into() } else { "false".into() },
        0x03 => format!("'\\x{:X}'", rd!(read_u16, 2)),
        0x04 => format!("{}", rd!(read_u8, 1) as i8),
        0x05 => format!("{}", rd!(read_u8, 1)),
        0x06 => format!("{}", rd!(read_u16, 2) as i16),
        0x07 => format!("{}", rd!(read_u16, 2)),
        0x08 => format!("{}", rd!(read_u32, 4) as i32),
        0x09 => format!("{}", rd!(read_u32, 4)),
        0x0A => format!("{}", rd!(read_u64, 8) as i64),
        0x0B => format!("{}", rd!(read_u64, 8)),
        0x0C => fmt_net(f32::from_bits(rd!(read_u32, 4)) as f64, 7),
        0x0D => fmt_net(f64::from_bits(rd!(read_u64, 8)), 15),
        0x0E => {
            // string: len (u32) @ blob+0, then `len` UTF-8 bytes @ blob+4.
            let len = rd!(read_u32, 4) as usize;
            if len > 0x10_0000 || !blob_mem.readable(b + 4, len) {
                return None;
            }
            let mut bytes = Vec::with_capacity(len);
            for i in 0..len {
                bytes.push(blob_mem.read_u8(b + 4 + i));
            }
            // Il2CppDumper emits the RAW string value (no escaping).
            format!("\"{}\"", String::from_utf8_lossy(&bytes))
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_net_matches_dotnet() {
        // Spot-checks of the .NET G7/G15 rendering.
        assert_eq!(fmt_net(0.0, 7), "0");
        assert_eq!(fmt_net(1.0, 7), "1");
        assert_eq!(fmt_net(1.5, 7), "1.5");
        assert_eq!(fmt_net(-2.25, 15), "-2.25");
        assert_eq!(fmt_net(f64::INFINITY, 15), "Infinity");
        assert_eq!(fmt_net(100000.0, 7), "100000");
    }
}
