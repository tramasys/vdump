use super::{AppError, Result};

pub(super) const HELP: &str = "\
Inspect this process's Linux vDSO and vvar mappings.

Usage: vdump [OPTIONS] [SEGMENT]...

Segments:
  vdso          The virtual dynamic shared object
  vvar          Kernel timekeeping data
  vvar-clock    Architecture-specific clock data

With no segment, vdump shows every mapping present on this system.

Options:
  -x, --hex            Show a colored hex/ASCII dump
  -r, --raw            Write raw bytes (exactly one segment)
      --strict         Fail instead of zero-filling unreadable raw bytes
  -l, --list           Show mapping metadata only
  -w, --width BYTES    Bytes per dump row [default: 16]
      --color WHEN     Color output: auto, always, never [default: auto]
  -h, --help           Print help
  -V, --version        Print version
";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Segment {
    Vdso,
    Vvar,
    VvarClock,
}

impl Segment {
    pub(super) const ALL: [Self; 3] = [Self::Vdso, Self::Vvar, Self::VvarClock];

    fn parse(value: &str) -> Option<Self> {
        match value {
            "vdso" | "[vdso]" => Some(Self::Vdso),
            "vvar" | "[vvar]" => Some(Self::Vvar),
            "vvar-clock" | "vvar_clock" | "vvar-vclock" | "vvar_vclock" | "[vvar_clock]"
            | "[vvar_vclock]" => Some(Self::VvarClock),
            _ => None,
        }
    }

    pub(super) fn from_kernel_name(value: &str) -> Option<Self> {
        match value {
            "[vdso]" => Some(Self::Vdso),
            "[vvar]" => Some(Self::Vvar),
            "[vvar_clock]" | "[vvar_vclock]" => Some(Self::VvarClock),
            _ => None,
        }
    }

    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Vdso => "vdso",
            Self::Vvar => "vvar",
            Self::VvarClock => "vvar-clock",
        }
    }

    pub(super) const fn expected_kernel_name(self) -> &'static str {
        match self {
            Self::Vdso => "[vdso]",
            Self::Vvar => "[vvar]",
            Self::VvarClock => "[vvar_vclock]",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ColorChoice {
    Auto,
    Always,
    Never,
}

impl ColorChoice {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "always" => Some(Self::Always),
            "never" => Some(Self::Never),
            _ => None,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Config {
    pub(super) segments: Vec<Segment>,
    pub(super) explicit_segments: bool,
    pub(super) output: OutputMode,
    pub(super) strict: bool,
    pub(super) width: usize,
    pub(super) color: ColorChoice,
    pub(super) action: Action,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum Action {
    Run,
    Help,
    Version,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OutputMode {
    Decoded,
    Hex,
    Raw,
    List,
}

impl Config {
    pub(super) fn parse<I>(arguments: I) -> Result<Self>
    where
        I: IntoIterator<Item = String>,
    {
        let mut output = OutputMode::Decoded;
        let mut strict = false;
        let mut width = 16;
        let mut color = ColorChoice::Auto;
        let mut segments = Vec::with_capacity(3);
        let mut action = Action::Run;
        let mut arguments = arguments.into_iter();
        let mut options = true;

        while let Some(argument) = arguments.next() {
            if options && argument == "--" {
                options = false;
                continue;
            }

            if options {
                match argument.as_str() {
                    "-x" | "--hex" => {
                        set_output_mode(&mut output, OutputMode::Hex)?;
                        continue;
                    }
                    "-r" | "--raw" => {
                        set_output_mode(&mut output, OutputMode::Raw)?;
                        continue;
                    }
                    "--strict" => {
                        strict = true;
                        continue;
                    }
                    "-l" | "--list" => {
                        set_output_mode(&mut output, OutputMode::List)?;
                        continue;
                    }
                    "-h" | "--help" => {
                        action = Action::Help;
                        continue;
                    }
                    "-V" | "--version" => {
                        action = Action::Version;
                        continue;
                    }
                    "-w" | "--width" => {
                        let value = arguments.next().ok_or_else(|| {
                            AppError::Message(format!("{argument} requires a value"))
                        })?;
                        width = parse_width(&value)?;
                        continue;
                    }
                    "--color" => {
                        let value = arguments
                            .next()
                            .ok_or_else(|| AppError::Message("--color requires a value".into()))?;
                        color = parse_color(&value)?;
                        continue;
                    }
                    _ => {}
                }

                if let Some(value) = argument.strip_prefix("--width=") {
                    width = parse_width(value)?;
                    continue;
                }
                if let Some(value) = argument.strip_prefix("--color=") {
                    color = parse_color(value)?;
                    continue;
                }
                if argument.starts_with('-') {
                    return Err(AppError::Message(format!(
                        "unknown option '{argument}' (try --help)"
                    )));
                }
            }

            let segment = Segment::parse(&argument).ok_or_else(|| {
                AppError::Message(format!(
                    "unknown segment '{argument}'; expected vdso, vvar, or vvar-clock"
                ))
            })?;
            if !segments.contains(&segment) {
                segments.push(segment);
            }
        }

        let explicit_segments = !segments.is_empty();
        if !explicit_segments {
            segments.extend(Segment::ALL);
        }

        if action == Action::Run {
            validate_run_options(output, strict, segments.len())?;
        }

        Ok(Self {
            segments,
            explicit_segments,
            output,
            strict,
            width,
            color,
            action,
        })
    }
}

fn validate_run_options(output: OutputMode, strict: bool, segment_count: usize) -> Result<()> {
    if output == OutputMode::Raw && segment_count != 1 {
        return Err(AppError::Message(
            "--raw requires exactly one segment".into(),
        ));
    }
    if strict && output != OutputMode::Raw {
        return Err(AppError::Message("--strict requires --raw".into()));
    }
    Ok(())
}

fn set_output_mode(current: &mut OutputMode, requested: OutputMode) -> Result<()> {
    if *current != OutputMode::Decoded && *current != requested {
        return Err(AppError::Message(
            "--hex, --raw, and --list cannot be combined".into(),
        ));
    }
    *current = requested;
    Ok(())
}

fn parse_width(value: &str) -> Result<usize> {
    let width = value
        .parse::<usize>()
        .map_err(|_| AppError::Message(format!("invalid width '{value}'")))?;
    if !(1..=64).contains(&width) {
        return Err(AppError::Message(
            "width must be between 1 and 64 bytes".into(),
        ));
    }
    Ok(width)
}

fn parse_color(value: &str) -> Result<ColorChoice> {
    ColorChoice::parse(value).ok_or_else(|| {
        AppError::Message(format!(
            "invalid color mode '{value}'; expected auto, always, or never"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_clock_aliases_and_deduplicates() {
        let config = Config::parse([
            "vvar-clock".into(),
            "vvar_vclock".into(),
            "[vvar_clock]".into(),
        ])
        .unwrap();

        assert_eq!(config.segments, vec![Segment::VvarClock]);
        assert!(config.explicit_segments);
    }

    #[test]
    fn defaults_to_all_segments() {
        let config = Config::parse(Vec::<String>::new()).unwrap();

        assert_eq!(config.segments, Segment::ALL);
        assert!(!config.explicit_segments);
        assert_eq!(config.width, 16);
    }

    #[test]
    fn validates_raw_options() {
        let error = Config::parse(["--raw".into()]).unwrap_err();
        assert_eq!(error.to_string(), "--raw requires exactly one segment");

        let error = Config::parse(["--strict".into(), "vdso".into()]).unwrap_err();
        assert_eq!(error.to_string(), "--strict requires --raw");

        let error = Config::parse(["--hex".into(), "--list".into()]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "--hex, --raw, and --list cannot be combined"
        );

        let config = Config::parse(["--hex".into(), "vdso".into()]).unwrap();
        assert_eq!(config.output, OutputMode::Hex);
    }
}
