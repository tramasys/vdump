mod cli;
mod clocks;
mod elf;
mod maps;
mod memory;
mod output;

use std::env;
use std::error::Error;
use std::fmt;
use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;

use cli::{Action, ColorChoice, Config, OutputMode, Segment};
use maps::{Mapping, parse_maps};
use memory::MemoryReader;
use output::{Palette, write_decoded, write_hexdump, write_mapping_header, write_missing};

#[derive(Debug)]
enum AppError {
    Message(String),
    Io {
        context: &'static str,
        source: io::Error,
    },
}

impl AppError {
    const fn io(context: &'static str, source: io::Error) -> Self {
        Self::Io { context, source }
    }

    fn is_broken_pipe(&self) -> bool {
        matches!(
            self,
            Self::Io {
                source,
                ..
            } if source.kind() == io::ErrorKind::BrokenPipe
        )
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(message) => formatter.write_str(message),
            Self::Io { context, source } => write!(formatter, "{context}: {source}"),
        }
    }
}

impl Error for AppError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Message(_) => None,
            Self::Io { source, .. } => Some(source),
        }
    }
}

type Result<T> = std::result::Result<T, AppError>;

pub fn main() -> ExitCode {
    let config = Config::parse(env::args().skip(1));
    let config = match config {
        Ok(config) => config,
        Err(error) => {
            eprintln!("vdump: {error}");
            return ExitCode::from(2);
        }
    };

    let result = match config.action {
        Action::Help => print_text(cli::HELP),
        Action::Version => print_text(concat!("vdump ", env!("CARGO_PKG_VERSION"), "\n")),
        Action::Run => run(&config),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) if error.is_broken_pipe() => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vdump: {error}");
            ExitCode::FAILURE
        }
    }
}

fn print_text(text: &str) -> Result<()> {
    io::stdout()
        .lock()
        .write_all(text.as_bytes())
        .map_err(|error| AppError::io("cannot write stdout", error))
}

fn run(config: &Config) -> Result<()> {
    let contents = std::fs::read_to_string("/proc/self/maps")
        .map_err(|error| AppError::io("cannot read /proc/self/maps", error))?;
    let mappings = parse_maps(&contents)?;
    let selected = select_mappings(config, &mappings)?;
    let color = match config.color {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => io::stdout().is_terminal() && env::var_os("NO_COLOR").is_none(),
    };
    let palette = Palette::new(color);
    let stdout = io::stdout();
    let mut output = io::BufWriter::new(stdout.lock());

    if config.output == OutputMode::List {
        for (segment, mapping) in selected {
            match mapping {
                Some(mapping) => write_mapping_header(&mut output, mapping, None, &palette)?,
                None => write_missing(&mut output, segment, &palette)?,
            }
        }
        return output
            .flush()
            .map_err(|error| AppError::io("cannot write stdout", error));
    }

    let mut memory = MemoryReader::open()?;

    if config.output == OutputMode::Raw {
        let (segment, mapping) = selected
            .into_iter()
            .next()
            .expect("raw selection has exactly one entry");
        let mapping = mapping.ok_or_else(|| missing_mapping_error(segment))?;
        let dump = memory.read(mapping)?;
        let unreadable = dump.unreadable_count();
        if unreadable != 0 && config.strict {
            return Err(AppError::Message(format!(
                "{} contains {} unreadable bytes; refusing an incomplete raw dump",
                segment.name(),
                unreadable
            )));
        }
        if unreadable != 0 {
            eprintln!(
                "vdump: warning: {} unreadable bytes in {} replaced with zeroes",
                unreadable,
                segment.name()
            );
        }
        output
            .write_all(&dump.bytes)
            .map_err(|error| AppError::io("cannot write stdout", error))?;
    } else {
        let mut first = true;
        for (segment, mapping) in selected {
            if !first {
                writeln!(output).map_err(|error| AppError::io("cannot write stdout", error))?;
            }
            first = false;
            match mapping {
                Some(mapping) => {
                    let dump = memory.read(mapping)?;
                    write_mapping_header(&mut output, mapping, Some(&dump), &palette)?;
                    match config.output {
                        OutputMode::Hex => {
                            write_hexdump(&mut output, mapping, &dump, config.width, &palette)?;
                        }
                        OutputMode::Decoded => {
                            write_decoded(&mut output, mapping, &dump, &palette)?;
                        }
                        OutputMode::Raw | OutputMode::List => unreachable!(),
                    }
                }
                None => write_missing(&mut output, segment, &palette)?,
            }
        }
    }

    output
        .flush()
        .map_err(|error| AppError::io("cannot write stdout", error))
}

fn select_mappings<'a>(
    config: &Config,
    mappings: &'a [Mapping],
) -> Result<Vec<(Segment, Option<&'a Mapping>)>> {
    let selected: Vec<_> = config
        .segments
        .iter()
        .copied()
        .map(|segment| {
            let mapping = mappings.iter().find(|mapping| mapping.segment == segment);
            (segment, mapping)
        })
        .collect();

    if config.explicit_segments
        && let Some((segment, _)) = selected.iter().find(|(_, mapping)| mapping.is_none())
    {
        return Err(missing_mapping_error(*segment));
    }

    Ok(selected)
}

fn missing_mapping_error(segment: Segment) -> AppError {
    AppError::Message(format!(
        "{} is not present in /proc/self/maps (expected {})",
        segment.name(),
        segment.expected_kernel_name()
    ))
}
