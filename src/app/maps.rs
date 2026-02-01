use super::cli::Segment;
use super::{AppError, Result};

#[derive(Debug)]
pub(super) struct Mapping {
    pub(super) segment: Segment,
    pub(super) kernel_name: String,
    pub(super) permissions: String,
    pub(super) start: usize,
    pub(super) end: usize,
}

impl Mapping {
    pub(super) const fn len(&self) -> usize {
        self.end - self.start
    }
}

pub(super) fn parse_maps(contents: &str) -> Result<Vec<Mapping>> {
    let mut mappings = Vec::with_capacity(3);

    for line in contents.lines() {
        let mut fields = line.split_whitespace();
        let Some(range) = fields.next() else {
            continue;
        };
        let permissions = fields.next().unwrap_or_default();
        let _offset = fields.next();
        let _device = fields.next();
        let _inode = fields.next();
        let Some(kernel_name) = fields.next() else {
            continue;
        };
        let Some(segment) = Segment::from_kernel_name(kernel_name) else {
            continue;
        };
        let (start, end) = range.split_once('-').ok_or_else(|| {
            AppError::Message(format!("malformed range in /proc/self/maps: '{range}'"))
        })?;
        let start = usize::from_str_radix(start, 16).map_err(|_| {
            AppError::Message(format!("malformed address in /proc/self/maps: '{start}'"))
        })?;
        let end = usize::from_str_radix(end, 16).map_err(|_| {
            AppError::Message(format!("malformed address in /proc/self/maps: '{end}'"))
        })?;
        if end <= start {
            return Err(AppError::Message(format!(
                "invalid range in /proc/self/maps: '{range}'"
            )));
        }

        mappings.push(Mapping {
            segment,
            kernel_name: kernel_name.into(),
            permissions: permissions.into(),
            start,
            end,
        });
    }

    Ok(mappings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_mappings() {
        let maps = "\
00400000-00401000 r--p 00000000 08:01 1 /usr/bin/vdump
7ffff7fc6000-7ffff7fca000 r--p 00000000 00:00 0 [vvar]
7ffff7fca000-7ffff7fcc000 r--p 00000000 00:00 0 [vvar_vclock]
7ffff7fcc000-7ffff7fce000 r-xp 00000000 00:00 0 [vdso]
";
        let mappings = parse_maps(maps).unwrap();

        assert_eq!(mappings.len(), 3);
        assert_eq!(mappings[0].segment, Segment::Vvar);
        assert_eq!(mappings[0].len(), 0x4000);
        assert_eq!(mappings[1].segment, Segment::VvarClock);
        assert_eq!(mappings[2].segment, Segment::Vdso);
        assert_eq!(mappings[2].permissions, "r-xp");
    }
}
