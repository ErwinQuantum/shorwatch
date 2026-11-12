//! JSON configuration: `appsettings.json` and its environment variants
//! (`appsettings.Production.json`), `local.settings.json`.
//!
//! Hand-written, like the `.properties` reader: .NET configuration files carry
//! comments and trailing commas, which a strict parser rejects, and every
//! value needs its position. Keys are flattened with a dot (`Jwt.Algorithm`,
//! `Algorithms[0]`), the way the YAML frontend names them; .NET writes the
//! same key `Jwt:Algorithm`, which `link` reads as the same.

use shorwatch_core::Language;
use shorwatch_core::ir::{FactKind, SourceUnit};

use crate::span::Lines;
use crate::{Frontend, LangError};

/// A configuration file nests a handful of levels; more is a file built to be
/// hard to read.
const MAX_DEPTH: usize = 100;

#[derive(Debug, Clone, Copy, Default)]
pub struct JsonFrontend;

impl Frontend for JsonFrontend {
    fn language(&self) -> Language {
        Language::Json
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[]
    }

    fn file_names(&self) -> &'static [&'static str] {
        &["appsettings.json", "local.settings.json"]
    }

    fn accepts(&self, name: &str) -> bool {
        self.file_names().contains(&name)
            || (name.starts_with("appsettings.") && name.ends_with(".json"))
    }

    fn lower(&self, file: &str, source: &str) -> Result<SourceUnit, LangError> {
        let lines = Lines::new(source);
        let mut unit = SourceUnit::new(file, Language::Json);
        let mut reader = Reader {
            path: file,
            src: source,
            at: usize::from(source.starts_with('\u{feff}')) * '\u{feff}'.len_utf8(),
        };
        let mut stack: Vec<Frame> = Vec::new();
        // The key path of the value being read: one segment per level.
        let mut path: Vec<String> = Vec::new();
        while let Some(token) = reader.next()? {
            let (start, end) = (token.start, token.end);
            match token.kind {
                Kind::Colon | Kind::Comma => {}
                Kind::Close => {
                    stack.pop();
                    // The container was the value of its parent's current child.
                    if !stack.is_empty() {
                        path.pop();
                    }
                }
                Kind::Open(object) => {
                    if !begin_child(&mut stack, &mut path) {
                        continue;
                    }
                    if stack.len() >= MAX_DEPTH {
                        return Err(LangError::TooDeep(file.to_owned(), MAX_DEPTH));
                    }
                    stack.push(if object {
                        Frame::Object { key: None }
                    } else {
                        Frame::Array { next: 0 }
                    });
                }
                Kind::String | Kind::Literal => {
                    // A string in the key position of an object is the key.
                    if let (Kind::String, Some(Frame::Object { key: key @ None })) =
                        (&token.kind, stack.last_mut())
                    {
                        *key = Some(decode(&source[start..end]));
                        continue;
                    }
                    let scalar = if token.kind == Kind::String {
                        Some(decode(&source[start..end]))
                    } else {
                        let text = &source[start..end];
                        (text != "null").then(|| text.to_owned())
                    };
                    if !begin_child(&mut stack, &mut path) {
                        continue;
                    }
                    if let Some(value) = scalar {
                        unit.push(
                            FactKind::Property {
                                key: join(&path),
                                value,
                            },
                            SourceUnit::ROOT,
                            lines.range(start, end),
                        );
                    }
                    path.pop();
                }
            }
        }
        Ok(unit)
    }
}

enum Frame {
    /// `key` is the key read and waiting for its value.
    Object {
        key: Option<String>,
    },
    Array {
        next: usize,
    },
}

/// Starts a value: pushes the segment it sits under (its key, or its index in
/// an array). The root value has none. `false` when an object's value has no
/// key (malformed input, skipped).
fn begin_child(stack: &mut [Frame], path: &mut Vec<String>) -> bool {
    match stack.last_mut() {
        None => true,
        Some(Frame::Object { key }) => match key.take() {
            Some(key) => {
                path.push(key);
                true
            }
            None => false,
        },
        Some(Frame::Array { next }) => {
            path.push(format!("[{next}]"));
            *next += 1;
            true
        }
    }
}

fn join(path: &[String]) -> String {
    let mut key = String::new();
    for segment in path {
        if !key.is_empty() && !segment.starts_with('[') {
            key.push('.');
        }
        key.push_str(segment);
    }
    key
}

#[derive(Debug, PartialEq, Eq)]
enum Kind {
    Open(bool),
    Close,
    Colon,
    Comma,
    String,
    /// A number, `true`, `false` or `null`.
    Literal,
}

struct Token {
    kind: Kind,
    start: usize,
    end: usize,
}

struct Reader<'s> {
    path: &'s str,
    src: &'s str,
    at: usize,
}

impl Reader<'_> {
    /// The next token, skipping whitespace and `//` and `/* */` comments.
    fn next(&mut self) -> Result<Option<Token>, LangError> {
        let bytes = self.src.as_bytes();
        loop {
            let Some(&byte) = bytes.get(self.at) else {
                return Ok(None);
            };
            match byte {
                b' ' | b'\t' | b'\r' | b'\n' => self.at += 1,
                b'/' if bytes.get(self.at + 1) == Some(&b'/') => {
                    self.at = self.src[self.at..]
                        .find('\n')
                        .map_or(bytes.len(), |i| self.at + i);
                }
                b'/' if bytes.get(self.at + 1) == Some(&b'*') => {
                    self.at = self.src[self.at + 2..]
                        .find("*/")
                        .map_or(bytes.len(), |i| self.at + 2 + i + 2);
                }
                _ => break,
            }
        }
        let start = self.at;
        let single = |kind| {
            Some(Token {
                kind,
                start,
                end: start + 1,
            })
        };
        let token = match bytes[start] {
            b'{' => single(Kind::Open(true)),
            b'[' => single(Kind::Open(false)),
            b'}' | b']' => single(Kind::Close),
            b':' => single(Kind::Colon),
            b',' => single(Kind::Comma),
            b'"' => {
                let mut i = start + 1;
                loop {
                    match bytes.get(i) {
                        None => return Err(LangError::Parse(self.path.to_owned())),
                        Some(b'\\') => i += 2,
                        Some(b'"') => break,
                        Some(_) => i += 1,
                    }
                }
                Some(Token {
                    kind: Kind::String,
                    start,
                    end: i + 1,
                })
            }
            _ => {
                let end = self.src[start..]
                    .find(|c: char| c.is_whitespace() || ",:]}/\"[{".contains(c))
                    .map_or(bytes.len(), |i| start + i.max(1));
                Some(Token {
                    kind: Kind::Literal,
                    start,
                    end,
                })
            }
        };
        if let Some(token) = &token {
            self.at = token.end;
        }
        Ok(token)
    }
}

/// The text of a string token (quotes included), its escapes decoded.
fn decode(token: &str) -> String {
    let inner = &token[1..token.len().saturating_sub(1).max(1)];
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('b') => out.push('\u{8}'),
            Some('f') => out.push('\u{c}'),
            Some('u') => {
                let hex: String = chars.by_ref().take(4).collect();
                match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    Some(c) => out.push(c),
                    None => out.push('\u{fffd}'),
                }
            }
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}
