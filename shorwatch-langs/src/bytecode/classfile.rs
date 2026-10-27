//! The parts of a JVM class file (JVMS §4) that declare a type: its name,
//! supertypes and methods. Fields, attributes and code are skipped by length.

use std::borrow::Cow;

/// A class, interface, enum or record as declared in a class file. Names
/// are internal (`java/security/KeyPairGenerator`).
#[derive(Debug)]
pub(super) struct ClassFile<'b> {
    pub(super) access: u16,
    pub(super) name: Cow<'b, str>,
    pub(super) super_name: Option<Cow<'b, str>>,
    pub(super) interfaces: Vec<Cow<'b, str>>,
    pub(super) methods: Vec<MethodInfo<'b>>,
}

#[derive(Debug)]
pub(super) struct MethodInfo<'b> {
    pub(super) access: u16,
    pub(super) name: Cow<'b, str>,
    pub(super) descriptor: Cow<'b, str>,
}

pub(super) const ACC_PUBLIC: u16 = 0x0001;
pub(super) const ACC_PROTECTED: u16 = 0x0004;
pub(super) const ACC_BRIDGE: u16 = 0x0040;
pub(super) const ACC_SYNTHETIC: u16 = 0x1000;
pub(super) const ACC_MODULE: u16 = 0x8000;

#[derive(Debug, Clone, Copy)]
enum Constant {
    Utf8(usize, usize),
    Class(u16),
    Other,
}

struct Reader<'b> {
    bytes: &'b [u8],
    at: usize,
}

impl<'b> Reader<'b> {
    fn take(&mut self, n: usize) -> Result<&'b [u8], String> {
        let end = self
            .at
            .checked_add(n)
            .filter(|&end| end <= self.bytes.len());
        let end = end.ok_or_else(|| format!("truncated at byte {}", self.at))?;
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Skips a `fields` or `methods` table entry's attributes.
    fn skip_attributes(&mut self) -> Result<(), String> {
        for _ in 0..self.u16()? {
            self.u16()?;
            let length = self.u32()? as usize;
            self.take(length)?;
        }
        Ok(())
    }
}

pub(super) fn parse(bytes: &[u8]) -> Result<ClassFile<'_>, String> {
    let mut r = Reader { bytes, at: 0 };
    if r.u32()? != 0xCAFE_BABE {
        return Err("not a class file".into());
    }
    r.u16()?; // minor
    r.u16()?; // major
    let count = r.u16()? as usize;
    let mut pool = vec![Constant::Other; count.max(1)];
    let mut index = 1;
    while index < count {
        let tag = r.u8()?;
        pool[index] = match tag {
            1 => {
                let length = r.u16()? as usize;
                let start = r.at;
                r.take(length)?;
                Constant::Utf8(start, length)
            }
            7 => Constant::Class(r.u16()?),
            8 | 16 | 19 | 20 => {
                r.take(2)?;
                Constant::Other
            }
            15 => {
                r.take(3)?;
                Constant::Other
            }
            3 | 4 | 9 | 10 | 11 | 12 | 17 | 18 => {
                r.take(4)?;
                Constant::Other
            }
            // Longs and doubles take two entries.
            5 | 6 => {
                r.take(8)?;
                index += 1;
                Constant::Other
            }
            _ => return Err(format!("unknown constant tag {tag}")),
        };
        index += 1;
    }
    let utf8 = |i: u16| match pool.get(i as usize) {
        // Modified UTF-8 only differs for NUL and supplementary
        // characters, which names of interest never contain.
        Some(Constant::Utf8(start, length)) => {
            Ok(String::from_utf8_lossy(&bytes[*start..start + length]))
        }
        _ => Err(format!("constant {i} is not a string")),
    };
    let class = |i: u16| match pool.get(i as usize) {
        Some(Constant::Class(name)) => utf8(*name),
        _ => Err(format!("constant {i} is not a class")),
    };

    let access = r.u16()?;
    let name = class(r.u16()?)?;
    let super_name = match r.u16()? {
        0 => None,
        i => Some(class(i)?),
    };
    let interfaces = (0..r.u16()?)
        .map(|_| class(r.u16()?))
        .collect::<Result<_, _>>()?;
    for _ in 0..r.u16()? {
        r.take(6)?; // access, name, descriptor
        r.skip_attributes()?;
    }
    let mut methods = Vec::new();
    for _ in 0..r.u16()? {
        let access = r.u16()?;
        let name = utf8(r.u16()?)?;
        let descriptor = utf8(r.u16()?)?;
        r.skip_attributes()?;
        methods.push(MethodInfo {
            access,
            name,
            descriptor,
        });
    }
    Ok(ClassFile {
        access,
        name,
        super_name,
        interfaces,
        methods,
    })
}

/// The arity and return type of a method descriptor
/// (`(Ljava/lang/String;I)Ljava/security/KeyPairGenerator;`). The return type
/// is `None` unless it is a class (not a primitive, `void` or an array).
pub(super) fn signature(descriptor: &str) -> Option<(usize, Option<&str>)> {
    let params = descriptor.strip_prefix('(')?;
    let (params, ret) = params.split_once(')')?;
    let mut arity = 0;
    let mut chars = params.chars();
    while let Some(c) = chars.next() {
        match c {
            '[' => continue,
            'L' => {
                chars.by_ref().find(|&c| c == ';')?;
            }
            'B' | 'C' | 'D' | 'F' | 'I' | 'J' | 'S' | 'Z' => {}
            _ => return None,
        }
        arity += 1;
    }
    let ret = ret.strip_prefix('L').and_then(|r| r.strip_suffix(';'));
    Some((arity, ret))
}
