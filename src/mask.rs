// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Output masking: replace injected secret values in a child's captured output
//! with a `***KEY***` placeholder.
//!
//! This is an accident guard, the same idea as GitHub Actions `::add-mask::`.
//! It is **not** a security boundary. It catches a verbatim value that a command
//! echoes to stdout or stderr (an `env` dump, a debug log line). It does not
//! catch a value that is encoded (base64, URL-encoding, hex), transformed,
//! printed in part, split across the two streams, or written to a file or a
//! socket. A child that wants to exfiltrate a value it was handed can do so.
//!
//! Matching is on raw bytes, so binary or non-UTF-8 output is handled. Longer
//! values are tried first, so a value that contains another value masks as the
//! longer key. Values shorter than [`MIN_MASK_LEN`] bytes are not masked: a value
//! like `1` or `true` would otherwise rewrite unrelated output.
//!
//! [`Masker::mask`] scrubs a complete buffer. [`MaskStream`] scrubs a stream
//! that arrives in chunks: it holds back only a chunk tail that could still be
//! the start of a value (at most the longest value minus one byte), and emits
//! everything else at once, so streaming output is not delayed.

use zeroize::Zeroizing;

/// Values shorter than this many bytes are not masked. Masking a 1–3 byte value
/// (`1`, `on`, `dev`) would corrupt ordinary output and still not hide a value
/// that short.
pub const MIN_MASK_LEN: usize = 4;

/// One value to mask and the placeholder that replaces it.
struct Pattern {
    value: Zeroizing<Vec<u8>>,
    placeholder: Vec<u8>,
}

/// A set of secret values to scrub from output. Holds copies of the values in
/// [`Zeroizing`] buffers, so they are wiped when the masker drops.
pub struct Masker {
    /// Longest value first; ties broken by key name for a stable placeholder.
    patterns: Vec<Pattern>,
    /// `first_byte[b]` is true when some value starts with byte `b`. Lets the
    /// scan skip most positions with a single lookup.
    first_byte: [bool; 256],
}

impl Masker {
    /// Build a masker from `(key, value)` pairs. A value shorter than
    /// [`MIN_MASK_LEN`] bytes is skipped. When two keys hold the same value, the
    /// placeholder names the key that sorts first.
    pub fn new<I, K, V>(secrets: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<[u8]>,
    {
        let mut patterns: Vec<Pattern> = secrets
            .into_iter()
            .filter(|(_, v)| v.as_ref().len() >= MIN_MASK_LEN)
            .map(|(k, v)| Pattern {
                value: Zeroizing::new(v.as_ref().to_vec()),
                placeholder: format!("***{}***", k.as_ref()).into_bytes(),
            })
            .collect();
        patterns.sort_by(|a, b| {
            b.value
                .len()
                .cmp(&a.value.len())
                .then_with(|| a.placeholder.cmp(&b.placeholder))
        });
        patterns.dedup_by(|later, earlier| later.value == earlier.value);
        let mut first_byte = [false; 256];
        for p in &patterns {
            first_byte[usize::from(p.value[0])] = true;
        }
        Self {
            patterns,
            first_byte,
        }
    }

    /// True when there is nothing to mask (no values, or all below the floor).
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Mask every occurrence of every value in a complete buffer.
    pub fn mask(&self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        self.scan(input, true, &mut out);
        out
    }

    /// Mask a buffer that was cut off mid-stream (an output cap, a killed
    /// child). A value that started before the cut is only partly present, so
    /// [`mask`](Self::mask) would let its leading bytes through; this drops any
    /// trailing bytes that could still be the start of a value instead.
    pub fn mask_truncated(&self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        self.scan(input, false, &mut out);
        out
    }

    /// Start masking a stream that arrives in chunks.
    pub fn stream(&self) -> MaskStream<'_> {
        MaskStream {
            masker: self,
            pending: Zeroizing::new(Vec::new()),
        }
    }

    /// Scan `buf`, appending masked output to `out`. Returns how many bytes of
    /// `buf` were consumed. With `last` false, the scan stops at the first
    /// position whose remaining bytes are a proper prefix of some value: those
    /// bytes may yet complete a match, so the caller carries them into the next
    /// chunk. With `last` true, everything is consumed.
    fn scan(&self, buf: &[u8], last: bool, out: &mut Vec<u8>) -> usize {
        let mut i = 0;
        let mut emitted = 0;
        'scan: while i < buf.len() {
            if !self.first_byte[usize::from(buf[i])] {
                i += 1;
                continue;
            }
            let rest = &buf[i..];
            // Longest first: an incomplete longer value wins over a complete
            // shorter one, so the stream masks exactly what `mask` would.
            for p in &self.patterns {
                if rest.starts_with(&p.value) {
                    out.extend_from_slice(&buf[emitted..i]);
                    out.extend_from_slice(&p.placeholder);
                    i += p.value.len();
                    emitted = i;
                    continue 'scan;
                }
                if !last && rest.len() < p.value.len() && p.value.starts_with(rest) {
                    out.extend_from_slice(&buf[emitted..i]);
                    return i;
                }
            }
            i += 1;
        }
        out.extend_from_slice(&buf[emitted..]);
        buf.len()
    }
}

/// Incremental masking for one output stream. Feed chunks with [`push`] and
/// write what it returns; call [`finish`] at end of stream for the held tail.
///
/// [`push`]: MaskStream::push
/// [`finish`]: MaskStream::finish
pub struct MaskStream<'a> {
    masker: &'a Masker,
    /// A tail of earlier input that is a proper prefix of some value. Never
    /// longer than the longest value minus one byte.
    pending: Zeroizing<Vec<u8>>,
}

impl MaskStream<'_> {
    /// Mask the next chunk. Returns the bytes that are safe to emit now; a tail
    /// that could be the start of a value split across chunks is held back.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(chunk.len());
        if self.pending.is_empty() {
            let used = self.masker.scan(chunk, false, &mut out);
            self.pending.extend_from_slice(&chunk[used..]);
        } else {
            let mut buf = Zeroizing::new(std::mem::take(&mut *self.pending));
            buf.extend_from_slice(chunk);
            let used = self.masker.scan(&buf, false, &mut out);
            self.pending.extend_from_slice(&buf[used..]);
        }
        out
    }

    /// End of stream: mask and return whatever is still held back.
    pub fn finish(self) -> Vec<u8> {
        self.masker.mask(&self.pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masker(pairs: &[(&str, &str)]) -> Masker {
        Masker::new(pairs.iter().map(|(k, v)| (*k, v.as_bytes())))
    }

    /// Feed `input` through a stream in `size`-byte chunks.
    fn stream_in_chunks(m: &Masker, input: &[u8], size: usize) -> Vec<u8> {
        let mut s = m.stream();
        let mut out = Vec::new();
        for chunk in input.chunks(size) {
            out.extend(s.push(chunk));
        }
        out.extend(s.finish());
        out
    }

    #[test]
    fn masks_every_occurrence() {
        let m = masker(&[("TOKEN", "s3cr3t-value")]);
        let out = m.mask(b"TOKEN=s3cr3t-value\nagain s3cr3t-values3cr3t-value\n");
        assert_eq!(
            out,
            b"TOKEN=***TOKEN***\nagain ***TOKEN******TOKEN***\n".to_vec()
        );
    }

    #[test]
    fn longest_value_wins_when_values_overlap() {
        // A value that contains another value masks as the longer key.
        let m = masker(&[("SHORT", "abcd"), ("LONG", "abcdefgh")]);
        assert_eq!(
            m.mask(b"x abcdefgh y abcd z"),
            b"x ***LONG*** y ***SHORT*** z"
        );
    }

    #[test]
    fn values_below_the_floor_are_not_masked() {
        let m = masker(&[("FLAG", "1"), ("MODE", "dev"), ("PIN", "4242")]);
        assert_eq!(m.mask(b"1 dev 4242"), b"1 dev ***PIN***");
        assert!(masker(&[("FLAG", "on")]).is_empty());
    }

    #[test]
    fn matches_raw_bytes_in_non_utf8_output() {
        let m = Masker::new([("BIN", &[0xff_u8, 0xfe, 0x00, 0x80][..])]);
        assert_eq!(
            m.mask(&[0x01, 0xff, 0xfe, 0x00, 0x80, 0x02]),
            b"\x01***BIN***\x02"
        );
    }

    #[test]
    fn duplicate_values_mask_under_one_key() {
        let m = masker(&[("B_KEY", "same-value"), ("A_KEY", "same-value")]);
        assert_eq!(m.mask(b"same-value"), b"***A_KEY***");
    }

    #[test]
    fn stream_catches_a_value_split_across_every_chunk_boundary() {
        let m = masker(&[("DB_URL", "postgres://u:pw@db/app"), ("API", "sk_live_123")]);
        let input = b"DB_URL=postgres://u:pw@db/app\nAPI=sk_live_123 sk_live_123\nend";
        let expected = m.mask(input);
        assert!(!expected.windows(11).any(|w| w == b"sk_live_123"));
        for size in 1..=input.len() {
            assert_eq!(
                stream_in_chunks(&m, input, size),
                expected,
                "chunk size {size}"
            );
        }
    }

    #[test]
    fn stream_holds_back_only_a_possible_value_prefix() {
        let m = masker(&[("K", "secretvalue")]);
        let mut s = m.stream();
        // No byte of this chunk can start the value: all of it is emitted.
        assert_eq!(s.push(b"progress 50%\n"), b"progress 50%\n");
        // A tail that is the start of the value is held, the rest emitted.
        assert_eq!(s.push(b"line secr"), b"line ");
        assert_eq!(s.push(b"etvalue!"), b"***K***!");
        // A held tail that turns out not to be the value is released.
        assert_eq!(s.push(b"sec"), b"");
        assert_eq!(s.push(b"ond"), b"second");
        assert_eq!(s.push(b" se"), b" ");
        assert_eq!(s.finish(), b"se");
    }

    #[test]
    fn stream_prefers_a_longer_value_still_arriving() {
        let m = masker(&[("SHORT", "abcd"), ("LONG", "abcdefgh")]);
        let mut s = m.stream();
        assert_eq!(s.push(b"abcde"), b"");
        assert_eq!(s.push(b"fgh"), b"***LONG***");
        assert_eq!(s.push(b"abcdX"), b"***SHORT***X");
    }

    #[test]
    fn truncated_buffer_drops_a_cut_off_value_prefix() {
        let m = masker(&[("K", "secretvalue")]);
        // Cut inside the value: its prefix must not survive.
        assert_eq!(m.mask_truncated(b"ok secretvalue x secr"), b"ok ***K*** x ");
        // Cut elsewhere: nothing is dropped.
        assert_eq!(m.mask_truncated(b"ok sex"), b"ok sex");
    }
}
