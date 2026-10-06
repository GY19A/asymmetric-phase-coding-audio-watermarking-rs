// SPDX-License-Identifier: BSD-2-Clause
//! Terminal output: the [`Ui`] (quiet / verbose / colour / where text goes)
//! and the Python-compatible renderers: [`to_py_json`] prints JSON the way
//! Python's `json.dumps` does (ASCII-only strings, `repr` floats, its
//! separators), [`py_repr`] quotes a string like Python's `repr`.

use std::cell::Cell;
use std::io::{self, IsTerminal, Write};

use serde::Serialize;
use serde_json::ser::Formatter;

/// ANSI colours used on a terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Paint {
    Green,
    Red,
}

/// Output settings shared by every subcommand.
#[derive(Debug)]
pub struct Ui {
    /// `-v` count.
    pub verbose: u8,
    /// `-q`: only the result line, no notes or details.
    pub quiet: bool,
    /// `--json`: machine-readable reports instead of text.
    pub json: bool,
    no_color: bool,
    to_stderr: Cell<bool>,
}

impl Ui {
    pub fn new(verbose: u8, quiet: bool, json: bool, no_color: bool) -> Self {
        let no_color = no_color
            || std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
            || std::env::var_os("TERM").is_some_and(|v| v == "dumb");
        Ui { verbose, quiet, json, no_color, to_stderr: Cell::new(false) }
    }

    /// Standard output carries audio (`-o -`): send all text to stderr.
    pub fn text_to_stderr(&self) {
        self.to_stderr.set(true);
    }

    fn color(&self) -> bool {
        !self.no_color && if self.to_stderr.get() { io::stderr().is_terminal() } else { io::stdout().is_terminal() }
    }

    /// `s` in colour `p` when the text goes to a terminal.
    pub fn paint(&self, s: &str, p: Paint) -> String {
        if !self.color() {
            return s.to_string();
        }
        let code = match p {
            Paint::Green => "32",
            Paint::Red => "31",
        };
        format!("\x1b[{code}m{s}\x1b[0m")
    }

    /// A result line (printed with `-q` too).
    pub fn line(&self, s: &str) {
        if self.to_stderr.get() {
            let _ = writeln!(io::stderr().lock(), "{s}");
        } else {
            let _ = writeln!(io::stdout().lock(), "{s}");
        }
    }

    /// An indented detail line under the result line (not with `-q`).
    pub fn detail(&self, s: &str) {
        if !self.quiet {
            self.line(&format!("  {s}"));
        }
    }

    /// `apcaw: note: {n}` on stderr (not with `-q`).
    pub fn note(&self, n: &str) {
        if !self.quiet {
            eprintln!("apcaw: note: {n}");
        }
    }

    /// `apcaw: debug: {..}` on stderr at `-v`.
    pub fn debug(&self, f: impl FnOnce() -> String) {
        if self.verbose > 0 {
            eprintln!("apcaw: debug: {}", f());
        }
    }

    /// Print `v` like Python's `json.dumps(v, indent=2)`.
    pub fn json<T: Serialize + ?Sized>(&self, v: &T) {
        self.line(&to_py_json(v, Some(2)));
    }
}

/// `json.dumps(v)` (`indent = None`: separators `", "` and `": "`) or
/// `json.dumps(v, indent=n)`, with `ensure_ascii` and Python float `repr`.
pub fn to_py_json<T: Serialize + ?Sized>(v: &T, indent: Option<usize>) -> String {
    let mut out = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut out, PyFormatter::new(indent));
    v.serialize(&mut ser).expect("JSON report serializes");
    String::from_utf8(out).expect("ASCII output")
}

/// A `serde_json` formatter producing the bytes of Python's `json.dumps`.
#[derive(Debug, Clone)]
pub struct PyFormatter {
    indent: Option<usize>,
    level: usize,
    has_value: bool,
}

impl PyFormatter {
    pub fn new(indent: Option<usize>) -> Self {
        PyFormatter { indent, level: 0, has_value: false }
    }

    fn open<W: ?Sized + Write>(&mut self, w: &mut W, c: &[u8]) -> io::Result<()> {
        self.level += 1;
        self.has_value = false;
        w.write_all(c)
    }

    fn close<W: ?Sized + Write>(&mut self, w: &mut W, c: &[u8]) -> io::Result<()> {
        self.level -= 1;
        if let (Some(n), true) = (self.indent, self.has_value) {
            w.write_all(b"\n")?;
            w.write_all(" ".repeat(n * self.level).as_bytes())?;
        }
        w.write_all(c)
    }

    fn item<W: ?Sized + Write>(&mut self, w: &mut W, first: bool) -> io::Result<()> {
        match self.indent {
            Some(n) => {
                w.write_all(if first { b"\n" } else { b",\n" })?;
                w.write_all(" ".repeat(n * self.level).as_bytes())
            }
            None if first => Ok(()),
            None => w.write_all(b", "),
        }
    }
}

impl Formatter for PyFormatter {
    fn write_f64<W: ?Sized + Write>(&mut self, w: &mut W, v: f64) -> io::Result<()> {
        w.write_all(py_float(v).as_bytes())
    }

    fn write_f32<W: ?Sized + Write>(&mut self, w: &mut W, v: f32) -> io::Result<()> {
        w.write_all(py_float(v as f64).as_bytes())
    }

    /// `ensure_ascii`: everything outside `' '..='~'` as lower-case `\uXXXX`
    /// (UTF-16 surrogate pairs above the BMP). Control characters, `"` and
    /// `\` reach [`Formatter::write_char_escape`], whose escapes match Python's.
    fn write_string_fragment<W: ?Sized + Write>(&mut self, w: &mut W, fragment: &str) -> io::Result<()> {
        let mut start = 0;
        for (i, c) in fragment.char_indices() {
            if c.is_ascii() && c != '\x7f' {
                continue;
            }
            w.write_all(&fragment.as_bytes()[start..i])?;
            let mut buf = [0u16; 2];
            for u in c.encode_utf16(&mut buf) {
                write!(w, "\\u{u:04x}")?;
            }
            start = i + c.len_utf8();
        }
        w.write_all(&fragment.as_bytes()[start..])
    }

    fn begin_array<W: ?Sized + Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.open(w, b"[")
    }

    fn end_array<W: ?Sized + Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.close(w, b"]")
    }

    fn begin_array_value<W: ?Sized + Write>(&mut self, w: &mut W, first: bool) -> io::Result<()> {
        self.item(w, first)
    }

    fn end_array_value<W: ?Sized + Write>(&mut self, _w: &mut W) -> io::Result<()> {
        self.has_value = true;
        Ok(())
    }

    fn begin_object<W: ?Sized + Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.open(w, b"{")
    }

    fn end_object<W: ?Sized + Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.close(w, b"}")
    }

    fn begin_object_key<W: ?Sized + Write>(&mut self, w: &mut W, first: bool) -> io::Result<()> {
        self.item(w, first)
    }

    fn begin_object_value<W: ?Sized + Write>(&mut self, w: &mut W) -> io::Result<()> {
        w.write_all(b": ")
    }

    fn end_object_value<W: ?Sized + Write>(&mut self, _w: &mut W) -> io::Result<()> {
        self.has_value = true;
        Ok(())
    }
}

/// Python's `repr(float)`: the shortest round-trip digits, positional for
/// decimal exponents in `[-4, 16)`, otherwise `d.ddde±XX`.
pub fn py_float(v: f64) -> String {
    if v.is_nan() {
        return "NaN".into();
    }
    if v.is_infinite() {
        return if v > 0.0 { "Infinity" } else { "-Infinity" }.into();
    }
    let sign = if v.is_sign_negative() { "-" } else { "" };
    let a = v.abs();
    if a == 0.0 {
        return format!("{sign}0.0");
    }
    let sci = format!("{a:e}");
    let (mant, exp) = sci.split_once('e').expect("{:e} has an exponent");
    let exp: i32 = exp.parse().expect("integer exponent");
    let digits: String = mant.chars().filter(|&c| c != '.').collect();
    let n = digits.len() as i32;
    let body = if (-4..16).contains(&exp) {
        if exp < 0 {
            format!("0.{}{digits}", "0".repeat((-exp - 1) as usize))
        } else if n <= exp + 1 {
            format!("{digits}{}.0", "0".repeat((exp + 1 - n) as usize))
        } else {
            let (i, f) = digits.split_at((exp + 1) as usize);
            format!("{i}.{f}")
        }
    } else {
        let m = if n == 1 { digits } else { format!("{}.{}", &digits[..1], &digits[1..]) };
        format!("{m}e{}{:02}", if exp < 0 { '-' } else { '+' }, exp.abs())
    };
    format!("{sign}{body}")
}

/// Python's `repr(str)`. Printability outside ASCII follows Python's
/// `str.isprintable` for the separator, format, private-use and
/// non-character code points listed below; other unassigned code points
/// (which Python also escapes) print as-is.
pub fn py_repr(s: &str) -> String {
    let q = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(q);
    for c in s.chars() {
        let n = c as u32;
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ if c == q => {
                out.push('\\');
                out.push(c);
            }
            _ if n < 0x20 || n == 0x7f => out.push_str(&format!("\\x{n:02x}")),
            _ if c.is_ascii() || py_printable(n) => out.push(c),
            _ if n <= 0xff => out.push_str(&format!("\\x{n:02x}")),
            _ if n <= 0xffff => out.push_str(&format!("\\u{n:04x}")),
            _ => out.push_str(&format!("\\U{n:08x}")),
        }
    }
    out.push(q);
    out
}

/// Non-ASCII code points Python's `repr` prints unescaped (approximation:
/// C1 controls, Zs/Zl/Zp separators, Cf format characters, private use and
/// non-characters are escaped).
fn py_printable(n: u32) -> bool {
    let escaped = matches!(
        n,
        0x80..=0xa0
            | 0xad
            | 0x0600..=0x0605
            | 0x061c
            | 0x06dd
            | 0x070f
            | 0x0890..=0x0891
            | 0x08e2
            | 0x1680
            | 0x180e
            | 0x2000..=0x200f
            | 0x2028..=0x202f
            | 0x205f..=0x206f
            | 0x3000
            | 0xe000..=0xf8ff
            | 0xfdd0..=0xfdef
            | 0xfeff
            | 0xfff9..=0xfffb
            | 0x110bd
            | 0x110cd
            | 0x13430..=0x1343f
            | 0x1bca0..=0x1bca3
            | 0x1d173..=0x1d17a
            | 0xe0001
            | 0xe0020..=0xe007f
            | 0xf0000..=0x10ffff
    );
    !escaped && n & 0xfffe != 0xfffe
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn floats_like_python_repr() {
        for (v, want) in [
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (1.0, "1.0"),
            (0.1, "0.1"),
            (1e-5, "1e-05"),
            (0.0001, "0.0001"),
            (1.5e16, "1.5e+16"),
            (1e16, "1e+16"),
            (1234567890123456.0, "1234567890123456.0"),
            (123.456, "123.456"),
            (1e100, "1e+100"),
            (2.5e-300, "2.5e-300"),
            (0.30000000000000004, "0.30000000000000004"),
            (-7.25e-7, "-7.25e-07"),
            (f64::NAN, "NaN"),
            (f64::NEG_INFINITY, "-Infinity"),
        ] {
            assert_eq!(py_float(v), want, "{v:e}");
        }
    }

    #[test]
    fn json_like_python_dumps() {
        let v = json!({"b": [1, 2.5, [], {}], "a": {"x": null, "y": "é\u{7f}\u{1F600}\n\""}, "z": true});
        assert_eq!(
            to_py_json(&v, None),
            r#"{"b": [1, 2.5, [], {}], "a": {"x": null, "y": "\u00e9\u007f\ud83d\ude00\n\""}, "z": true}"#
        );
        assert_eq!(
            to_py_json(&v, Some(2)),
            "{\n  \"b\": [\n    1,\n    2.5,\n    [],\n    {}\n  ],\n  \"a\": {\n    \"x\": null,\n    \
             \"y\": \"\\u00e9\\u007f\\ud83d\\ude00\\n\\\"\"\n  },\n  \"z\": true\n}"
        );
        assert_eq!(to_py_json(&json!([]), Some(2)), "[]");
        assert_eq!(to_py_json(&json!({"k": "\u{1}"}), None), r#"{"k": "\u0001"}"#);
    }

    #[test]
    fn repr_like_python() {
        assert_eq!(py_repr("NIPS2026: A"), "'NIPS2026: A'");
        assert_eq!(py_repr("it's"), "\"it's\"");
        assert_eq!(py_repr("it's \"x\""), "'it\\'s \"x\"'");
        assert_eq!(py_repr("a\\b\tc\n\u{0}\u{7f}"), "'a\\\\b\\tc\\n\\x00\\x7f'");
        assert_eq!(py_repr("é\u{fffd}\u{a0}\u{200b}\u{e000}\u{10ffff}"), "'é\u{fffd}\\xa0\\u200b\\ue000\\U0010ffff'");
    }
}
