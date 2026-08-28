use std::fmt;

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use http::HeaderValue;
use zeroize::Zeroize;

/// Precomputed raw and encoded credential patterns used for response redaction.
///
/// This type deliberately exposes no pattern iterator and redacts its `Debug`
/// output. Pattern and pending buffers are zeroized when dropped.
pub struct RedactionSet {
    patterns: Vec<Vec<u8>>,
    maximum_pattern_length: usize,
}

impl fmt::Debug for RedactionSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedactionSet")
            .field("patterns", &"[REDACTED]")
            .field("pattern_count", &self.patterns.len())
            .finish()
    }
}

impl Drop for RedactionSet {
    fn drop(&mut self) {
        for pattern in &mut self.patterns {
            pattern.zeroize();
        }
    }
}

impl RedactionSet {
    /// Precompute redaction patterns for host-resolved credential values.
    pub fn new<I, B>(secrets: I) -> Self
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let mut patterns = secrets
            .into_iter()
            .flat_map(|secret| credential_encodings(secret.as_ref()))
            .filter(|pattern| !pattern.is_empty())
            .collect::<Vec<_>>();
        patterns.sort_by_key(|value| std::cmp::Reverse(value.len()));
        patterns.dedup();
        let maximum_pattern_length = patterns.iter().map(Vec::len).max().unwrap_or(1);
        Self {
            patterns,
            maximum_pattern_length,
        }
    }

    /// Return whether no non-empty credential pattern was supplied.
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Replace every recognized raw or encoded credential occurrence.
    pub fn redact_bytes(&self, body: &[u8]) -> Vec<u8> {
        let mut output = body.to_vec();
        for pattern in &self.patterns {
            output = redact_exact(&output, pattern);
        }
        output
    }

    /// Redact a response header, dropping values that become invalid HTTP text.
    pub fn redact_header(&self, value: &HeaderValue) -> Option<HeaderValue> {
        HeaderValue::from_bytes(&self.redact_bytes(value.as_bytes())).ok()
    }

    /// Consume this set to redact a bounded response stream across chunk boundaries.
    pub fn into_streaming(self) -> StreamingRedactor {
        let mut this = self;
        let patterns = std::mem::take(&mut this.patterns);
        let maximum_pattern_length = this.maximum_pattern_length;
        StreamingRedactor {
            pending: Vec::new(),
            patterns,
            maximum_pattern_length,
        }
    }
}

/// Incremental credential redaction that retains only the largest possible overlap.
pub struct StreamingRedactor {
    pending: Vec<u8>,
    patterns: Vec<Vec<u8>>,
    maximum_pattern_length: usize,
}

impl fmt::Debug for StreamingRedactor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StreamingRedactor")
            .field("pending_bytes", &self.pending.len())
            .field("patterns", &"[REDACTED]")
            .field("pattern_count", &self.patterns.len())
            .finish()
    }
}

impl Drop for StreamingRedactor {
    fn drop(&mut self) {
        self.pending.zeroize();
        for pattern in &mut self.patterns {
            pattern.zeroize();
        }
    }
}

impl StreamingRedactor {
    /// Process the next response chunk and return bytes safe to emit now.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(chunk);
        self.emit(false)
    }

    /// Finish the stream and return the final redacted bytes.
    pub fn finish(&mut self) -> Vec<u8> {
        self.emit(true)
    }

    fn emit(&mut self, finished: bool) -> Vec<u8> {
        let safe_limit = if finished {
            self.pending.len()
        } else {
            self.pending
                .len()
                .saturating_sub(self.maximum_pattern_length.saturating_sub(1))
        };
        let mut consumed = 0;
        let mut output = Vec::with_capacity(safe_limit);
        while consumed < safe_limit {
            if let Some(pattern) = self
                .patterns
                .iter()
                .find(|pattern| self.pending[consumed..].starts_with(pattern.as_slice()))
            {
                output.extend_from_slice(b"[REDACTED]");
                consumed += pattern.len();
            } else {
                output.push(self.pending[consumed]);
                consumed += 1;
            }
        }
        self.pending.drain(..consumed);
        output
    }
}

fn redact_exact(body: &[u8], secret: &[u8]) -> Vec<u8> {
    if secret.is_empty() || body.len() < secret.len() {
        return body.to_vec();
    }
    let mut output = Vec::with_capacity(body.len());
    let mut offset = 0;
    while let Some(position) = body[offset..]
        .windows(secret.len())
        .position(|window| window == secret)
    {
        let absolute = offset + position;
        output.extend_from_slice(&body[offset..absolute]);
        output.extend_from_slice(b"[REDACTED]");
        offset = absolute + secret.len();
    }
    output.extend_from_slice(&body[offset..]);
    output
}

fn credential_encodings(secret: &[u8]) -> Vec<Vec<u8>> {
    let percent_encoded = url::form_urlencoded::byte_serialize(secret).collect::<String>();
    let mut encodings = vec![
        secret.to_vec(),
        STANDARD.encode(secret).into_bytes(),
        STANDARD_NO_PAD.encode(secret).into_bytes(),
        URL_SAFE.encode(secret).into_bytes(),
        URL_SAFE_NO_PAD.encode(secret).into_bytes(),
        percent_encoded.as_bytes().to_vec(),
        lowercase_percent_hex(&percent_encoded).into_bytes(),
    ];
    if let Ok(secret) = std::str::from_utf8(secret)
        && let Ok(json) = serde_json::to_string(secret)
    {
        encodings.push(json.as_bytes()[1..json.len() - 1].to_vec());
    }
    encodings.sort_by_key(|value| std::cmp::Reverse(value.len()));
    encodings.dedup();
    encodings
}

fn lowercase_percent_hex(value: &str) -> String {
    let mut bytes = value.as_bytes().to_vec();
    let mut index = 0;
    while index + 2 < bytes.len() {
        if bytes[index] == b'%' {
            bytes[index + 1].make_ascii_lowercase();
            bytes[index + 2].make_ascii_lowercase();
            index += 3;
        } else {
            index += 1;
        }
    }
    String::from_utf8(bytes).expect("percent encoding is ASCII")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_common_credential_encodings_and_debug_output() {
        let redaction = RedactionSet::new([b"secret+token".as_slice()]);
        assert_eq!(
            redaction.redact_bytes(b"before secret+token after"),
            b"before [REDACTED] after"
        );
        assert_eq!(
            redaction.redact_bytes(STANDARD.encode(b"secret+token").as_bytes()),
            b"[REDACTED]"
        );
        assert_eq!(redaction.redact_bytes(b"secret%2Btoken"), b"[REDACTED]");
        let debug = format!("{redaction:?}");
        assert!(!debug.contains("secret"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn streaming_redaction_catches_every_chunk_boundary() {
        let secret = b"stream+secret";
        let encoded = STANDARD.encode(secret);
        let percent = url::form_urlencoded::byte_serialize(secret).collect::<String>();
        let input = format!("before stream+secret middle {encoded} after {percent}");
        let mut redactor = RedactionSet::new([secret.as_slice()]).into_streaming();
        let mut output = Vec::new();
        for byte in input.as_bytes() {
            output.extend(redactor.push(std::slice::from_ref(byte)));
        }
        output.extend(redactor.finish());

        assert!(!output.windows(secret.len()).any(|window| window == secret));
        assert!(
            !output
                .windows(encoded.len())
                .any(|window| window == encoded.as_bytes())
        );
        assert!(
            !output
                .windows(percent.len())
                .any(|window| window == percent.as_bytes())
        );
        assert_eq!(
            std::str::from_utf8(&output)
                .unwrap()
                .matches("[REDACTED]")
                .count(),
            3
        );
    }

    #[test]
    fn header_redaction_fails_closed_for_invalid_bytes() {
        let redaction = RedactionSet::new([b"secret".as_slice()]);
        assert_eq!(
            redaction
                .redact_header(&HeaderValue::from_static("Bearer secret"))
                .unwrap(),
            HeaderValue::from_static("Bearer [REDACTED]")
        );
    }
}
