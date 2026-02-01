use std::fmt::Write as _;
use std::io::Write;

use super::cli::Segment;
use super::maps::Mapping;
use super::memory::Dump;
use super::{AppError, Result, clocks, elf};

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

pub(super) struct Palette {
    enabled: bool,
}

impl Palette {
    const RESET: &'static str = "\x1b[0m";
    const BOLD_CYAN: &'static str = "\x1b[1;36m";
    const CYAN: &'static str = "\x1b[36m";
    const GREEN: &'static str = "\x1b[32m";
    const YELLOW: &'static str = "\x1b[33m";
    const RED: &'static str = "\x1b[31m";
    const DIM: &'static str = "\x1b[2m";

    pub(super) const fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    const fn code(&self, code: &'static str) -> &'static str {
        if self.enabled { code } else { "" }
    }

    const fn reset(&self) -> &'static str {
        self.code(Self::RESET)
    }
}

pub(super) fn write_mapping_header<W: Write>(
    output: &mut W,
    mapping: &Mapping,
    dump: Option<&Dump>,
    palette: &Palette,
) -> Result<()> {
    write!(
        output,
        "{}{}{}  {}  {}0x{:0width$x}-0x{:0width$x}{}  {}  {}",
        palette.code(Palette::BOLD_CYAN),
        mapping.segment.name(),
        palette.reset(),
        mapping.kernel_name,
        palette.code(Palette::CYAN),
        mapping.start,
        mapping.end,
        palette.reset(),
        mapping.permissions,
        human_size(mapping.len()),
        width = usize::BITS as usize / 4,
    )
    .map_err(|error| AppError::io("cannot write stdout", error))?;

    if let Some(dump) = dump {
        let unreadable = dump.unreadable_count();
        if unreadable != 0 {
            write!(
                output,
                "  {}({} unreadable){}",
                palette.code(Palette::RED),
                human_size(unreadable),
                palette.reset()
            )
            .map_err(|error| AppError::io("cannot write stdout", error))?;
        }
    }
    writeln!(output).map_err(|error| AppError::io("cannot write stdout", error))
}

pub(super) fn write_missing<W: Write>(
    output: &mut W,
    segment: Segment,
    palette: &Palette,
) -> Result<()> {
    writeln!(
        output,
        "{}{}{}  {}  {}not present{}",
        palette.code(Palette::BOLD_CYAN),
        segment.name(),
        palette.reset(),
        segment.expected_kernel_name(),
        palette.code(Palette::DIM),
        palette.reset(),
    )
    .map_err(|error| AppError::io("cannot write stdout", error))
}

pub(super) fn write_decoded<W: Write>(
    output: &mut W,
    mapping: &Mapping,
    dump: &Dump,
    palette: &Palette,
) -> Result<()> {
    match mapping.segment {
        Segment::Vdso => write_decoded_vdso(output, mapping, dump, palette),
        Segment::Vvar => write_decoded_vvar(output, dump, palette),
        Segment::VvarClock => write_decoded_vvar_clock(output, dump, palette),
    }
}

fn write_decoded_vdso<W: Write>(
    output: &mut W,
    mapping: &Mapping,
    dump: &Dump,
    palette: &Palette,
) -> Result<()> {
    write_field(
        output,
        "purpose",
        "kernel-provided userspace system calls",
        palette,
    )?;
    let info = match elf::parse(&dump.bytes) {
        Ok(info) => info,
        Err(error) => {
            return write_field(output, "ELF", &format!("cannot decode: {error}"), palette);
        }
    };
    write_field(
        output,
        "format",
        &format!("ELF{} {}, {}", info.bits, info.endian, info.object_type),
        palette,
    )?;
    write_field(output, "architecture", info.machine.as_ref(), palette)?;
    write_field(output, "ABI", info.abi.as_ref(), palette)?;
    write_field(
        output,
        "tables",
        &format!(
            "{} program headers, {} sections",
            info.program_headers, info.sections
        ),
        palette,
    )?;
    write_field(output, "entry", &format!("{:#x}", info.entry), palette)?;

    writeln!(
        output,
        "  {}exports{}           {}{} functions{}",
        palette.code(Palette::CYAN),
        palette.reset(),
        palette.code(Palette::GREEN),
        info.exports.len(),
        palette.reset(),
    )
    .map_err(|error| AppError::io("cannot write stdout", error))?;
    for symbol in &info.exports {
        if let Some(address) = info.runtime_address(mapping.start, mapping.len(), symbol) {
            writeln!(
                output,
                "    {}0x{:0width$x}{}  {}{}{}  {}({} B){}",
                palette.code(Palette::YELLOW),
                address,
                palette.reset(),
                palette.code(Palette::GREEN),
                symbol.name,
                palette.reset(),
                palette.code(Palette::DIM),
                symbol.size,
                palette.reset(),
                width = usize::BITS as usize / 4,
            )
            .map_err(|error| AppError::io("cannot write stdout", error))?;
        } else {
            writeln!(
                output,
                "    {}unresolved{}          {}{}{}  {}(ELF value {:#x}, {} B){}",
                palette.code(Palette::RED),
                palette.reset(),
                palette.code(Palette::GREEN),
                symbol.name,
                palette.reset(),
                palette.code(Palette::DIM),
                symbol.value,
                symbol.size,
                palette.reset(),
            )
            .map_err(|error| AppError::io("cannot write stdout", error))?;
        }
    }
    Ok(())
}

fn write_decoded_vvar<W: Write>(output: &mut W, dump: &Dump, palette: &Palette) -> Result<()> {
    write_field(
        output,
        "purpose",
        "kernel timekeeping data consumed by vDSO",
        palette,
    )?;
    write_field(output, "readable", &readable_summary(dump), palette)?;
    write_field(
        output,
        "layout",
        "kernel-private; use --hex for exact fields",
        palette,
    )?;
    if let Some(source) = clocks::current_clocksource() {
        write_field(output, "clocksource", source, palette)?;
    }

    writeln!(
        output,
        "  {}clock values{}",
        palette.code(Palette::CYAN),
        palette.reset()
    )
    .map_err(|error| AppError::io("cannot write stdout", error))?;
    for clock in clocks::read_all() {
        let resolution = clock
            .resolution
            .map(|value| format!(", resolution {value}"))
            .unwrap_or_default();
        writeln!(
            output,
            "    {}{:<18}{} {}{}{}  {}({}{}){}",
            palette.code(Palette::CYAN),
            clock.name,
            palette.reset(),
            palette.code(Palette::GREEN),
            clock.value,
            palette.reset(),
            palette.code(Palette::DIM),
            clock.note,
            resolution,
            palette.reset(),
        )
        .map_err(|error| AppError::io("cannot write stdout", error))?;
    }
    Ok(())
}

fn write_decoded_vvar_clock<W: Write>(
    output: &mut W,
    dump: &Dump,
    palette: &Palette,
) -> Result<()> {
    write_field(
        output,
        "purpose",
        "architecture or hypervisor clock acceleration",
        palette,
    )?;
    write_field(output, "readable", &readable_summary(dump), palette)?;
    write_field(
        output,
        "layout",
        "architecture-private; use --hex for exact bytes",
        palette,
    )?;
    if let Some(source) = clocks::current_clocksource() {
        write_field(output, "current source", source, palette)?;
    }
    if let Some(sources) = clocks::available_clocksources() {
        write_field(output, "available", sources, palette)?;
    }
    if dump.unreadable_count() == dump.bytes.len() {
        write_field(
            output,
            "status",
            "mapping present, but no pages are readable here",
            palette,
        )?;
    }
    Ok(())
}

fn write_field<W: Write>(
    output: &mut W,
    label: &str,
    value: &str,
    palette: &Palette,
) -> Result<()> {
    writeln!(
        output,
        "  {}{label:<18}{} {}{value}{}",
        palette.code(Palette::CYAN),
        palette.reset(),
        palette.code(Palette::GREEN),
        palette.reset(),
    )
    .map_err(|error| AppError::io("cannot write stdout", error))
}

fn readable_summary(dump: &Dump) -> String {
    let readable = dump.bytes.len() - dump.unreadable_count();
    if readable == dump.bytes.len() {
        format!("all {}", human_size(readable))
    } else {
        format!(
            "{} of {} ({} unavailable)",
            human_size(readable),
            human_size(dump.bytes.len()),
            human_size(dump.unreadable_count())
        )
    }
}

pub(super) fn write_hexdump<W: Write>(
    output: &mut W,
    mapping: &Mapping,
    dump: &Dump,
    width: usize,
    palette: &Palette,
) -> Result<()> {
    let mut previous: Option<(usize, usize)> = None;
    let mut eliding = false;
    let mut line = String::with_capacity(64 + width * if palette.enabled { 16 } else { 4 });

    for offset in (0..dump.bytes.len()).step_by(width) {
        let end = (offset + width).min(dump.bytes.len());
        let repeated = previous.is_some_and(|(previous_start, previous_end)| {
            previous_end - previous_start == end - offset
                && dump.bytes[previous_start..previous_end] == dump.bytes[offset..end]
                && dump.readable[previous_start..previous_end] == dump.readable[offset..end]
        });
        previous = Some((offset, end));

        if repeated {
            if !eliding {
                writeln!(output, "{}*{}", palette.code(Palette::DIM), palette.reset())
                    .map_err(|error| AppError::io("cannot write stdout", error))?;
            }
            eliding = true;
            continue;
        }
        eliding = false;

        line.clear();
        write!(
            line,
            "{}{:0address_width$x}{}  ",
            palette.code(Palette::CYAN),
            mapping.start + offset,
            palette.reset(),
            address_width = usize::BITS as usize / 4,
        )
        .expect("writing to a String cannot fail");

        let mut active_color = "";
        for index in offset..offset + width {
            if index >= end {
                reset_line_color(&mut line, &mut active_color, palette);
                line.push_str("   ");
            } else if !dump.readable[index] {
                set_line_color(&mut line, &mut active_color, Palette::RED, palette);
                line.push_str("?? ");
            } else {
                let byte = dump.bytes[index];
                let color = if byte == 0 {
                    Palette::DIM
                } else if byte.is_ascii_graphic() || byte == b' ' {
                    Palette::GREEN
                } else {
                    Palette::YELLOW
                };
                set_line_color(&mut line, &mut active_color, color, palette);
                push_hex_byte(&mut line, byte);
                line.push(' ');
            }
        }
        reset_line_color(&mut line, &mut active_color, palette);

        line.push_str(" |");
        for index in offset..end {
            if dump.readable[index] {
                let byte = dump.bytes[index];
                let character = if byte.is_ascii_graphic() || byte == b' ' {
                    char::from(byte)
                } else {
                    '.'
                };
                let color = if character == '.' {
                    Palette::DIM
                } else {
                    Palette::GREEN
                };
                set_line_color(&mut line, &mut active_color, color, palette);
                line.push(character);
            } else {
                set_line_color(&mut line, &mut active_color, Palette::RED, palette);
                line.push('?');
            }
        }
        reset_line_color(&mut line, &mut active_color, palette);
        line.push_str("|\n");
        output
            .write_all(line.as_bytes())
            .map_err(|error| AppError::io("cannot write stdout", error))?;
    }
    Ok(())
}

fn push_hex_byte(output: &mut String, byte: u8) {
    output.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
    output.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
}

fn set_line_color(
    output: &mut String,
    active: &mut &'static str,
    requested: &'static str,
    palette: &Palette,
) {
    let requested = palette.code(requested);
    if *active == requested {
        return;
    }
    if !active.is_empty() {
        output.push_str(Palette::RESET);
    }
    output.push_str(requested);
    *active = requested;
}

fn reset_line_color(output: &mut String, active: &mut &'static str, palette: &Palette) {
    if !active.is_empty() {
        output.push_str(palette.reset());
        *active = "";
    }
}

fn human_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else {
        let mut whole = bytes / 1024;
        let mut hundredths = ((bytes % 1024) * 100 + 512) / 1024;
        if hundredths == 100 {
            whole += 1;
            hundredths = 0;
        }
        format!("{whole}.{hundredths:02} KiB")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_unreadable_bytes() {
        let mapping = Mapping {
            segment: Segment::Vvar,
            kernel_name: "[vvar]".into(),
            permissions: "r--p".into(),
            start: 0x1000,
            end: 0x1002,
        };
        let dump = Dump {
            bytes: vec![b'A', 0],
            readable: vec![true, false],
            readable_count: 1,
        };
        let mut output = Vec::new();

        write_hexdump(&mut output, &mapping, &dump, 2, &Palette::new(false)).unwrap();

        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("41 ??  |A?|"));
    }

    #[test]
    fn collapses_repeated_rows() {
        let mapping = Mapping {
            segment: Segment::VvarClock,
            kernel_name: "[vvar_vclock]".into(),
            permissions: "r--p".into(),
            start: 0x1000,
            end: 0x100c,
        };
        let dump = Dump {
            bytes: vec![0; 12],
            readable: vec![false; 12],
            readable_count: 0,
        };
        let mut output = Vec::new();

        write_hexdump(&mut output, &mapping, &dump, 4, &Palette::new(false)).unwrap();

        let output = String::from_utf8(output).unwrap();
        assert_eq!(output.lines().count(), 2);
        assert!(output.ends_with("*\n"));
    }

    #[test]
    fn reports_human_sizes_without_floating_point() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1024), "1.00 KiB");
        assert_eq!(human_size(1536), "1.50 KiB");
        assert_eq!(human_size(2047), "2.00 KiB");
    }
}
