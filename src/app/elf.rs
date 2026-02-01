use std::borrow::Cow;
use std::fmt;

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const SHT_DYNSYM: u32 = 11;

#[derive(Debug)]
pub(super) struct ElfInfo<'a> {
    pub bits: u8,
    pub endian: &'static str,
    pub abi: Cow<'static, str>,
    pub object_type: Cow<'static, str>,
    pub machine: Cow<'static, str>,
    pub entry: u64,
    pub program_headers: usize,
    pub sections: usize,
    pub exports: Vec<Symbol<'a>>,
    load_image: LoadImage,
}

impl ElfInfo<'_> {
    pub(super) fn runtime_address(
        &self,
        mapping_start: usize,
        mapping_size: usize,
        symbol: &Symbol<'_>,
    ) -> Option<usize> {
        let symbol_end = symbol.value.checked_add(symbol.size.max(1))?;
        let executable = self.load_image.segments.iter().any(|segment| {
            segment.executable
                && symbol.value >= segment.virtual_address
                && symbol_end
                    <= segment
                        .virtual_address
                        .checked_add(segment.memory_size)
                        .unwrap_or(0)
        });
        if !executable {
            return None;
        }

        let base = self.load_image.base?;
        let relative = symbol.value.checked_sub(base)?;
        let relative_end = symbol_end.checked_sub(base)?;
        if relative_end > mapping_size as u64 {
            return None;
        }
        mapping_start.checked_add(usize::try_from(relative).ok()?)
    }
}

#[derive(Debug)]
pub(super) struct Symbol<'a> {
    pub name: &'a str,
    pub value: u64,
    pub size: u64,
}

#[derive(Clone, Copy)]
enum Class {
    Elf32,
    Elf64,
}

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

#[derive(Debug)]
pub(super) struct ParseError(&'static str);

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

#[derive(Clone, Copy)]
struct Section {
    kind: u32,
    offset: u64,
    size: u64,
    link: usize,
    entry_size: u64,
}

#[derive(Debug)]
struct LoadImage {
    base: Option<u64>,
    segments: Vec<LoadSegment>,
}

#[derive(Debug)]
struct LoadSegment {
    virtual_address: u64,
    memory_size: u64,
    executable: bool,
}

pub(super) fn parse(bytes: &[u8]) -> Result<ElfInfo<'_>, ParseError> {
    if bytes.get(..4) != Some(ELF_MAGIC) {
        return Err(ParseError("missing ELF magic"));
    }
    let class = match bytes.get(4) {
        Some(1) => Class::Elf32,
        Some(2) => Class::Elf64,
        _ => return Err(ParseError("unsupported ELF class")),
    };
    let endian = match bytes.get(5) {
        Some(1) => Endian::Little,
        Some(2) => Endian::Big,
        _ => return Err(ParseError("unsupported ELF byte order")),
    };
    let reader = Reader { bytes, endian };
    let abi = describe_abi(*bytes.get(7).ok_or(ParseError("truncated ELF identity"))?);
    let object_type = describe_type(reader.u16(16)?);
    let machine = describe_machine(reader.u16(18)?);

    let (
        bits,
        entry,
        program_offset,
        program_entry_size,
        program_headers,
        section_offset,
        section_entry_size,
        sections,
    ) = match class {
        Class::Elf32 => (
            32,
            u64::from(reader.u32(24)?),
            u64::from(reader.u32(28)?),
            usize::from(reader.u16(42)?),
            usize::from(reader.u16(44)?),
            u64::from(reader.u32(32)?),
            usize::from(reader.u16(46)?),
            usize::from(reader.u16(48)?),
        ),
        Class::Elf64 => (
            64,
            reader.u64(24)?,
            reader.u64(32)?,
            usize::from(reader.u16(54)?),
            usize::from(reader.u16(56)?),
            reader.u64(40)?,
            usize::from(reader.u16(58)?),
            usize::from(reader.u16(60)?),
        ),
    };

    let load_image = parse_load_image(
        &reader,
        class,
        program_offset,
        program_entry_size,
        program_headers,
    )?;
    let exports = parse_exports(&reader, class, section_offset, section_entry_size, sections)?;

    Ok(ElfInfo {
        bits,
        endian: match endian {
            Endian::Little => "little-endian",
            Endian::Big => "big-endian",
        },
        abi,
        object_type,
        machine,
        entry,
        program_headers,
        sections,
        exports,
        load_image,
    })
}

fn parse_load_image(
    reader: &Reader<'_>,
    class: Class,
    table_offset: u64,
    entry_size: usize,
    entry_count: usize,
) -> Result<LoadImage, ParseError> {
    if entry_count == 0 {
        return Ok(LoadImage {
            base: None,
            segments: Vec::new(),
        });
    }
    if table_offset == 0 {
        return Err(ParseError("ELF program header table is missing"));
    }
    let minimum_size = match class {
        Class::Elf32 => 32,
        Class::Elf64 => 56,
    };
    if entry_size < minimum_size {
        return Err(ParseError("invalid ELF program header entry size"));
    }
    let table_size = entry_size
        .checked_mul(entry_count)
        .ok_or(ParseError("ELF program header table is too large"))?;
    reader.range(table_offset, table_size as u64)?;

    let mut base = None;
    let mut segments = Vec::new();
    for index in 0..entry_count {
        let relative_offset = index
            .checked_mul(entry_size)
            .ok_or(ParseError("ELF program header offset overflow"))?;
        let offset = table_offset
            .checked_add(relative_offset as u64)
            .ok_or(ParseError("ELF program header offset overflow"))?;
        if reader.u32(offset)? != PT_LOAD {
            continue;
        }

        let (flags, file_offset, virtual_address, file_size, memory_size, alignment) = match class {
            Class::Elf32 => (
                reader.u32(offset + 24)?,
                u64::from(reader.u32(offset + 4)?),
                u64::from(reader.u32(offset + 8)?),
                u64::from(reader.u32(offset + 16)?),
                u64::from(reader.u32(offset + 20)?),
                u64::from(reader.u32(offset + 28)?),
            ),
            Class::Elf64 => (
                reader.u32(offset + 4)?,
                reader.u64(offset + 8)?,
                reader.u64(offset + 16)?,
                reader.u64(offset + 32)?,
                reader.u64(offset + 40)?,
                reader.u64(offset + 48)?,
            ),
        };
        if file_size > memory_size {
            return Err(ParseError("ELF load segment exceeds its memory size"));
        }
        if alignment > 1
            && (!alignment.is_power_of_two()
                || virtual_address % alignment != file_offset % alignment)
        {
            return Err(ParseError("invalid ELF load segment alignment"));
        }
        reader.range(file_offset, file_size)?;

        let segment_base = if alignment > 1 {
            virtual_address & !(alignment - 1)
        } else {
            virtual_address
        };
        base = Some(base.map_or(segment_base, |existing: u64| existing.min(segment_base)));
        segments.push(LoadSegment {
            virtual_address,
            memory_size,
            executable: flags & PF_X != 0,
        });
    }

    Ok(LoadImage { base, segments })
}

fn section_at(
    reader: &Reader<'_>,
    class: Class,
    table_offset: u64,
    entry_size: usize,
    index: usize,
) -> Result<Section, ParseError> {
    let minimum_size = match class {
        Class::Elf32 => 40,
        Class::Elf64 => 64,
    };
    if entry_size < minimum_size {
        return Err(ParseError("invalid ELF section entry size"));
    }
    let relative_offset = index
        .checked_mul(entry_size)
        .ok_or(ParseError("ELF section offset overflow"))?;
    let offset = table_offset
        .checked_add(relative_offset as u64)
        .ok_or(ParseError("ELF section offset overflow"))?;
    match class {
        Class::Elf32 => Ok(Section {
            kind: reader.u32(offset + 4)?,
            offset: u64::from(reader.u32(offset + 16)?),
            size: u64::from(reader.u32(offset + 20)?),
            link: reader.u32(offset + 24)? as usize,
            entry_size: u64::from(reader.u32(offset + 36)?),
        }),
        Class::Elf64 => Ok(Section {
            kind: reader.u32(offset + 4)?,
            offset: reader.u64(offset + 24)?,
            size: reader.u64(offset + 32)?,
            link: reader.u32(offset + 40)? as usize,
            entry_size: reader.u64(offset + 56)?,
        }),
    }
}

fn parse_exports<'a>(
    reader: &Reader<'a>,
    class: Class,
    table_offset: u64,
    entry_size: usize,
    section_count: usize,
) -> Result<Vec<Symbol<'a>>, ParseError> {
    if section_count == 0 || table_offset == 0 {
        return Ok(Vec::new());
    }
    let table_size = entry_size
        .checked_mul(section_count)
        .ok_or(ParseError("ELF section table is too large"))?;
    reader.range(table_offset, table_size as u64)?;

    let mut symbols = None;
    for index in 0..section_count {
        let section = section_at(reader, class, table_offset, entry_size, index)?;
        if section.kind == SHT_DYNSYM {
            symbols = Some(section);
            break;
        }
    }
    let Some(symbols) = symbols else {
        return Ok(Vec::new());
    };
    if symbols.link >= section_count {
        return Err(ParseError("dynamic symbol string table is missing"));
    }
    let strings = section_at(reader, class, table_offset, entry_size, symbols.link)?;
    let string_bytes = reader.range(strings.offset, strings.size)?;
    let minimum_entry_size = match class {
        Class::Elf32 => 16,
        Class::Elf64 => 24,
    };
    if symbols.entry_size < minimum_entry_size || symbols.size % symbols.entry_size != 0 {
        return Err(ParseError("invalid dynamic symbol entry size"));
    }
    let count = symbols.size / symbols.entry_size;
    reader.range(symbols.offset, symbols.size)?;

    let capacity = usize::try_from(count).map_err(|_| ParseError("too many dynamic symbols"))?;
    let mut exports = Vec::with_capacity(capacity);
    for index in 0..count {
        let offset = symbols
            .offset
            .checked_add(
                index
                    .checked_mul(symbols.entry_size)
                    .ok_or(ParseError("dynamic symbol offset overflow"))?,
            )
            .ok_or(ParseError("dynamic symbol offset overflow"))?;
        let (name_offset, info, section_index, value, size) = match class {
            Class::Elf32 => (
                reader.u32(offset)? as usize,
                reader.u8(offset + 12)?,
                reader.u16(offset + 14)?,
                u64::from(reader.u32(offset + 4)?),
                u64::from(reader.u32(offset + 8)?),
            ),
            Class::Elf64 => (
                reader.u32(offset)? as usize,
                reader.u8(offset + 4)?,
                reader.u16(offset + 6)?,
                reader.u64(offset + 8)?,
                reader.u64(offset + 16)?,
            ),
        };
        let binding = info >> 4;
        let symbol_type = info & 0x0f;
        if section_index == 0 || !matches!(binding, 1 | 2 | 10) || !matches!(symbol_type, 2 | 10) {
            continue;
        }
        let Some(name) = read_string(string_bytes, name_offset) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        exports.push(Symbol { name, value, size });
    }

    exports.sort_unstable_by(|left, right| {
        left.value
            .cmp(&right.value)
            .then_with(|| left.name.cmp(right.name))
    });
    Ok(exports)
}

fn read_string(bytes: &[u8], offset: usize) -> Option<&str> {
    let tail = bytes.get(offset..)?;
    let end = tail.iter().position(|byte| *byte == 0)?;
    std::str::from_utf8(&tail[..end]).ok()
}

struct Reader<'a> {
    bytes: &'a [u8],
    endian: Endian,
}

impl<'a> Reader<'a> {
    fn range(&self, offset: u64, size: u64) -> Result<&'a [u8], ParseError> {
        let start = usize::try_from(offset).map_err(|_| ParseError("ELF offset is too large"))?;
        let size = usize::try_from(size).map_err(|_| ParseError("ELF range is too large"))?;
        let end = start
            .checked_add(size)
            .ok_or(ParseError("ELF range overflow"))?;
        self.bytes
            .get(start..end)
            .ok_or(ParseError("truncated ELF data"))
    }

    fn u8(&self, offset: u64) -> Result<u8, ParseError> {
        self.range(offset, 1).map(|bytes| bytes[0])
    }

    fn u16(&self, offset: u64) -> Result<u16, ParseError> {
        let bytes: [u8; 2] = self
            .range(offset, 2)?
            .try_into()
            .expect("range has exact length");
        Ok(match self.endian {
            Endian::Little => u16::from_le_bytes(bytes),
            Endian::Big => u16::from_be_bytes(bytes),
        })
    }

    fn u32(&self, offset: u64) -> Result<u32, ParseError> {
        let bytes: [u8; 4] = self
            .range(offset, 4)?
            .try_into()
            .expect("range has exact length");
        Ok(match self.endian {
            Endian::Little => u32::from_le_bytes(bytes),
            Endian::Big => u32::from_be_bytes(bytes),
        })
    }

    fn u64(&self, offset: u64) -> Result<u64, ParseError> {
        let bytes: [u8; 8] = self
            .range(offset, 8)?
            .try_into()
            .expect("range has exact length");
        Ok(match self.endian {
            Endian::Little => u64::from_le_bytes(bytes),
            Endian::Big => u64::from_be_bytes(bytes),
        })
    }
}

fn describe_abi(value: u8) -> Cow<'static, str> {
    match value {
        0 => "System V".into(),
        3 => "Linux".into(),
        6 => "Solaris".into(),
        9 => "FreeBSD".into(),
        12 => "OpenBSD".into(),
        _ => Cow::Owned(format!("unknown ({value})")),
    }
}

fn describe_type(value: u16) -> Cow<'static, str> {
    match value {
        0 => "none".into(),
        1 => "relocatable".into(),
        2 => "executable".into(),
        3 => "shared object".into(),
        4 => "core".into(),
        _ => Cow::Owned(format!("processor/OS-specific ({value:#x})")),
    }
}

fn describe_machine(value: u16) -> Cow<'static, str> {
    match value {
        3 => "x86".into(),
        8 => "MIPS".into(),
        20 => "PowerPC".into(),
        21 => "PowerPC64".into(),
        22 => "s390".into(),
        40 => "ARM".into(),
        62 => "x86-64".into(),
        183 => "AArch64".into(),
        243 => "RISC-V".into(),
        258 => "LoongArch".into(),
        _ => Cow::Owned(format!("machine {value}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_elf64_with_load(base: u64, flags: u32) -> Vec<u8> {
        let mut bytes = vec![0; 128];
        let file_size = bytes.len() as u64;
        bytes[..4].copy_from_slice(ELF_MAGIC);
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes[24..32].copy_from_slice(&(base + 0x20).to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
        bytes[58..60].copy_from_slice(&64_u16.to_le_bytes());

        bytes[64..68].copy_from_slice(&PT_LOAD.to_le_bytes());
        bytes[68..72].copy_from_slice(&flags.to_le_bytes());
        bytes[80..88].copy_from_slice(&base.to_le_bytes());
        bytes[96..104].copy_from_slice(&file_size.to_le_bytes());
        bytes[104..112].copy_from_slice(&file_size.to_le_bytes());
        bytes[112..120].copy_from_slice(&0x1000_u64.to_le_bytes());
        bytes
    }

    #[test]
    fn rejects_non_elf_data() {
        assert_eq!(
            parse(b"not ELF").unwrap_err().to_string(),
            "missing ELF magic"
        );
    }

    #[test]
    fn reads_strings_safely() {
        assert_eq!(read_string(b"\0hello\0", 1), Some("hello"));
        assert_eq!(read_string(b"unterminated", 0), None);
        assert_eq!(read_string(b"\0", 2), None);
    }

    #[test]
    fn resolves_runtime_addresses_from_the_load_image_base() {
        let bytes = minimal_elf64_with_load(0x4000, PF_X);
        let info = parse(&bytes).unwrap();
        let symbol = Symbol {
            name: "function",
            value: 0x4020,
            size: 8,
        };

        assert_eq!(info.runtime_address(0x7000, 128, &symbol), Some(0x7020));
        assert_eq!(info.runtime_address(0x7000, 0x20, &symbol), None);
    }

    #[test]
    fn rejects_runtime_addresses_outside_executable_load_segments() {
        let bytes = minimal_elf64_with_load(0x4000, 4);
        let info = parse(&bytes).unwrap();
        let symbol = Symbol {
            name: "data",
            value: 0x4020,
            size: 8,
        };

        assert_eq!(info.runtime_address(0x7000, 128, &symbol), None);
    }

    #[test]
    fn rejects_truncated_program_header_tables() {
        let mut bytes = minimal_elf64_with_load(0x4000, PF_X);
        bytes.truncate(96);

        assert_eq!(parse(&bytes).unwrap_err().to_string(), "truncated ELF data");
    }
}
