//! PEM blocks (`-----BEGIN CERTIFICATE-----`) and the base64 inside them.

/// One `-----BEGIN <label>-----` ... `-----END <label>-----` block.
#[derive(Debug)]
pub(super) struct Block<'a> {
    pub(super) label: &'a str,
    /// Byte range of the `BEGIN` marker.
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) der: Vec<u8>,
}

pub(super) fn blocks(text: &str) -> Vec<Block<'_>> {
    let mut blocks = Vec::new();
    let mut open: Option<(&str, usize, usize, String)> = None;
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let start = offset;
        offset += line.len();
        let trimmed = line.trim();
        if let Some(label) = marker(trimmed, "BEGIN") {
            let begin = start + (line.len() - line.trim_start().len());
            open = Some((label, begin, begin + trimmed.len(), String::new()));
        } else if let Some(label) = marker(trimmed, "END") {
            if let Some((begin, start, end, body)) = open.take()
                && begin == label
                && let Some(der) = base64(&body)
            {
                blocks.push(Block {
                    label,
                    start,
                    end,
                    der,
                });
            }
        } else if let Some((.., body)) = &mut open
            // Encrypted traditional keys carry `Proc-Type:` headers.
            && !trimmed.contains(':')
        {
            body.push_str(trimmed);
        }
    }
    blocks
}

fn marker<'a>(line: &'a str, kind: &str) -> Option<&'a str> {
    line.strip_prefix("-----")?
        .strip_prefix(kind)?
        .strip_prefix(' ')?
        .strip_suffix("-----")
}

/// Standard base64, whitespace ignored, padding optional.
pub(super) fn base64(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}
