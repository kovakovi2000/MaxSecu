//! Primitive encodings (encoding-spec §2): fixed-width big-endian integers,
//! canonical bool, fixed/var byte strings, and NFC-checked text.
//!
//! `Writer` is infallible (it emits the one canonical form). `Reader` is strict
//! and fail-closed: every deviation is a hard reject.

use crate::error::DecodeError;
use crate::MAX_TEXT;
use unicode_normalization::{is_nfc, UnicodeNormalization};

/// Append-only canonical byte sink.
#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn bool(&mut self, v: bool) {
        self.buf.push(if v { 0x01 } else { 0x00 });
    }

    /// Raw fixed-width field — the length is known from the field type, so no
    /// prefix is emitted (encoding-spec §2 `bytes_fixed`).
    pub fn fixed(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    /// `bytes_var` = `u32 len` ‖ `len` raw bytes (encoding-spec §2).
    pub fn var(&mut self, b: &[u8]) {
        // Length is bounded structurally elsewhere; a >4 GiB field cannot arise
        // from any structure in this spec.
        self.u32(b.len() as u32);
        self.buf.extend_from_slice(b);
    }

    /// `text` = a `bytes_var` over NFC UTF-8 (encoding-spec §2). The caller
    /// guarantees `s` is already NFC-normalized (the `Text` type enforces it).
    pub fn text(&mut self, s: &str) {
        self.var(s.as_bytes());
    }
}

/// Strict, fail-closed cursor over a byte string.
#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.remaining() < n {
            return Err(DecodeError::ShortInput {
                needed: n,
                remaining: self.remaining(),
            });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, DecodeError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn bool(&mut self) -> Result<bool, DecodeError> {
        match self.u8()? {
            0x00 => Ok(false),
            0x01 => Ok(true),
            other => Err(DecodeError::InvalidBool(other)),
        }
    }

    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let s = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Ok(out)
    }

    /// `bytes_var`: read a `u32` length then that many bytes; reject overrun.
    pub fn var(&mut self) -> Result<Vec<u8>, DecodeError> {
        let len = self.u32()? as usize;
        if len > self.remaining() {
            return Err(DecodeError::LengthOverrun {
                len: len as u64,
                remaining: self.remaining(),
            });
        }
        Ok(self.take(len)?.to_vec())
    }

    /// `text`: a `bytes_var` that must be valid UTF-8, NFC-normalized, and
    /// within `MAX_TEXT` bytes (encoding-spec §2). All three are hard rejects.
    pub fn text(&mut self) -> Result<String, DecodeError> {
        let bytes = self.var()?;
        if bytes.len() > MAX_TEXT {
            return Err(DecodeError::TextTooLong {
                len: bytes.len(),
                max: MAX_TEXT,
            });
        }
        let s = core::str::from_utf8(&bytes).map_err(|_| DecodeError::InvalidUtf8)?;
        if !is_nfc(s) {
            return Err(DecodeError::NonNfcText);
        }
        Ok(s.to_owned())
    }

    /// After the top-level struct, the input MUST be fully consumed
    /// (encoding-spec §7 rule 2).
    pub fn finish(self) -> Result<(), DecodeError> {
        if self.remaining() != 0 {
            return Err(DecodeError::TrailingBytes {
                remaining: self.remaining(),
            });
        }
        Ok(())
    }
}

/// Normalize an arbitrary string to NFC (used by `Text` constructors so that
/// `encode` always emits the canonical form).
pub(crate) fn to_nfc(s: &str) -> String {
    s.nfc().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u32_is_fixed_width_big_endian() {
        let mut w = Writer::new();
        w.u32(0x0102_0304);
        assert_eq!(w.into_bytes(), [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn integers_round_trip() {
        let mut w = Writer::new();
        w.u8(0xAB);
        w.u16(0xBEEF);
        w.u32(0xDEAD_BEEF);
        w.u64(0x0102_0304_0506_0708);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.u8().unwrap(), 0xAB);
        assert_eq!(r.u16().unwrap(), 0xBEEF);
        assert_eq!(r.u32().unwrap(), 0xDEAD_BEEF);
        assert_eq!(r.u64().unwrap(), 0x0102_0304_0506_0708);
        assert!(r.finish().is_ok());
    }

    #[test]
    fn u32_truncated_rejects() {
        // V-6: a u32 with 3 bytes left → reject.
        let bytes = [0x00, 0x00, 0x00];
        let mut r = Reader::new(&bytes);
        assert!(matches!(
            r.u32(),
            Err(DecodeError::ShortInput {
                needed: 4,
                remaining: 3
            })
        ));
    }

    #[test]
    fn bool_canonical_only() {
        // V-3 class: only 0x00/0x01 are valid bools.
        assert!(!Reader::new(&[0x00]).bool().unwrap());
        assert!(Reader::new(&[0x01]).bool().unwrap());
        assert!(matches!(
            Reader::new(&[0x02]).bool(),
            Err(DecodeError::InvalidBool(0x02))
        ));
    }

    #[test]
    fn var_length_prefix_injective() {
        // V-pos-1: text("ab") = 00 00 00 02 61 62 ; text("a") = 00 00 00 01 61.
        let mut w = Writer::new();
        w.text("ab");
        assert_eq!(w.into_bytes(), [0x00, 0x00, 0x00, 0x02, 0x61, 0x62]);
        let mut w = Writer::new();
        w.text("a");
        assert_eq!(w.into_bytes(), [0x00, 0x00, 0x00, 0x01, 0x61]);
    }

    #[test]
    fn var_length_overrun_rejects() {
        // V-6: a bytes_var len of 0xFFFFFFFF with little input → reject.
        let bytes = [0xFF, 0xFF, 0xFF, 0xFF, 0x61];
        let mut r = Reader::new(&bytes);
        assert!(matches!(
            r.var(),
            Err(DecodeError::LengthOverrun {
                len: 0xFFFF_FFFF,
                remaining: 1
            })
        ));
    }

    #[test]
    fn text_rejects_non_utf8() {
        // V-8: non-UTF-8 username → reject. 0xFF is never valid UTF-8.
        let bytes = [0x00, 0x00, 0x00, 0x01, 0xFF];
        let mut r = Reader::new(&bytes);
        assert!(matches!(r.text(), Err(DecodeError::InvalidUtf8)));
    }

    #[test]
    fn text_rejects_non_nfc() {
        // V-8: a decomposed (non-NFC) form that differs from its NFC bytes → reject.
        // U+0065 U+0301 (e + combining acute) is the NFD form of é (U+00E9).
        let decomposed = "e\u{0301}";
        assert!(!is_nfc(decomposed));
        let mut w = Writer::new();
        w.var(decomposed.as_bytes()); // smuggle non-NFC bytes past the Text guard
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert!(matches!(r.text(), Err(DecodeError::NonNfcText)));
    }

    #[test]
    fn text_rejects_over_max() {
        // §2: len > MAX_TEXT → reject. Build a var with len = MAX_TEXT+1 of 'a'.
        let big = vec![0x61u8; MAX_TEXT + 1];
        let mut w = Writer::new();
        w.var(&big);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert!(matches!(
            r.text(),
            Err(DecodeError::TextTooLong { max: MAX_TEXT, .. })
        ));
    }

    #[test]
    fn finish_rejects_trailing() {
        // §7 rule 2: trailing bytes after the consumed region → reject.
        let bytes = [0x01u8, 0x99];
        let mut r = Reader::new(&bytes);
        assert_eq!(r.u8().unwrap(), 0x01);
        assert!(matches!(
            r.finish(),
            Err(DecodeError::TrailingBytes { remaining: 1 })
        ));
    }
}
