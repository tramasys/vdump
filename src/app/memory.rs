use std::ffi::c_void;
use std::fs::File;
use std::io::{self, PipeReader, PipeWriter, Read};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::FileExt;

use super::maps::Mapping;
use super::{AppError, Result};

const FALLBACK_PAGE_SIZE: usize = 4096;
const AT_PAGESZ: usize = 6;
const EFAULT: i32 = 14;

#[derive(Debug)]
pub(super) struct Dump {
    pub(super) bytes: Vec<u8>,
    pub(super) readable: Vec<bool>,
    pub(super) readable_count: usize,
}

impl Dump {
    fn complete(bytes: Vec<u8>) -> Self {
        let readable_count = bytes.len();
        let readable = vec![true; bytes.len()];
        Self {
            bytes,
            readable,
            readable_count,
        }
    }

    pub(super) const fn unreadable_count(&self) -> usize {
        self.bytes.len() - self.readable_count
    }
}

pub(super) struct MemoryReader {
    memory: File,
    kernel_copy: Option<(PipeReader, PipeWriter)>,
    block_size: usize,
}

impl MemoryReader {
    pub(super) fn open() -> Result<Self> {
        let memory = File::open("/proc/self/mem")
            .map_err(|error| AppError::io("cannot open /proc/self/mem", error))?;
        Ok(Self {
            memory,
            kernel_copy: None,
            block_size: page_size(),
        })
    }

    pub(super) fn read(&mut self, mapping: &Mapping) -> Result<Dump> {
        let mut bytes = vec![0; mapping.len()];
        if self
            .memory
            .read_exact_at(&mut bytes, mapping.start as u64)
            .is_ok()
        {
            return Ok(Dump::complete(bytes));
        }

        self.read_via_kernel_copy(mapping, bytes)
    }

    fn read_via_kernel_copy(&mut self, mapping: &Mapping, mut bytes: Vec<u8>) -> Result<Dump> {
        if self.kernel_copy.is_none() {
            self.kernel_copy = Some(
                io::pipe()
                    .map_err(|error| AppError::io("cannot create memory-copy pipe", error))?,
            );
        }
        let (receiver, sender) = self.kernel_copy.as_mut().expect("pipe initialized");
        let mut readable = vec![false; bytes.len()];
        let mut readable_count = 0;

        for block_start in (0..bytes.len()).step_by(self.block_size) {
            let block_end = (block_start + self.block_size).min(bytes.len());
            let mut offset = block_start;

            while offset < block_end {
                let address = mapping.start.checked_add(offset).ok_or_else(|| {
                    AppError::Message("mapping address overflowed this architecture".into())
                })?;
                let count = block_end - offset;

                // `write(2)` performs a guarded kernel copy from our mapping. Unlike a
                // Rust dereference, an unbacked vvar page is reported as EFAULT rather
                // than terminating the process with SIGBUS. The raw pointer is never
                // dereferenced in Rust and the requested range came from /proc/self/maps.
                let copied = unsafe {
                    write_from_address(sender.as_raw_fd(), address as *const c_void, count)
                };
                if copied < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    if error.raw_os_error() != Some(EFAULT) {
                        return Err(AppError::io("cannot copy mapping bytes", error));
                    }
                    break;
                }
                if copied == 0 {
                    break;
                }
                let copied = usize::try_from(copied).expect("positive isize fits usize");
                receiver
                    .read_exact(&mut bytes[offset..offset + copied])
                    .map_err(|error| AppError::io("cannot receive copied mapping bytes", error))?;
                readable[offset..offset + copied].fill(true);
                readable_count += copied;
                offset += copied;
            }
        }

        Ok(Dump {
            bytes,
            readable,
            readable_count,
        })
    }
}

fn page_size() -> usize {
    // SAFETY: `getauxval` takes a value and has no pointer preconditions.
    let size = unsafe { libc_getauxval(AT_PAGESZ) };
    if size.is_power_of_two() && size >= FALLBACK_PAGE_SIZE {
        size
    } else {
        FALLBACK_PAGE_SIZE
    }
}

unsafe extern "C" {
    #[link_name = "write"]
    fn libc_write(fd: RawFd, buffer: *const c_void, count: usize) -> isize;

    #[link_name = "getauxval"]
    fn libc_getauxval(kind: usize) -> usize;
}

unsafe fn write_from_address(fd: RawFd, address: *const c_void, count: usize) -> isize {
    // SAFETY: The caller supplies a live file descriptor. The kernel validates the
    // raw userspace range and returns EFAULT when a page cannot be read.
    unsafe { libc_write(fd, address, count) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::cli::Segment;
    use crate::app::{elf, maps::parse_maps};

    #[test]
    fn reads_the_live_vdso() {
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        let mappings = parse_maps(&maps).unwrap();
        let vdso = mappings
            .iter()
            .find(|mapping| mapping.segment == Segment::Vdso)
            .unwrap();
        let mut memory = MemoryReader::open().unwrap();

        let dump = memory.read(vdso).unwrap();

        assert_eq!(&dump.bytes[..4], b"\x7fELF");
        assert_eq!(dump.unreadable_count(), 0);
        let info = elf::parse(&dump.bytes).unwrap();
        assert!(!info.exports.is_empty());
        assert!(info.exports.iter().all(|symbol| {
            info.runtime_address(vdso.start, vdso.len(), symbol)
                .is_some()
        }));
    }

    #[test]
    fn safely_probes_the_live_vvar() {
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        let mappings = parse_maps(&maps).unwrap();
        let Some(vvar) = mappings
            .iter()
            .find(|mapping| mapping.segment == Segment::Vvar)
        else {
            return;
        };

        let mut memory = MemoryReader::open().unwrap();
        let dump = memory
            .read_via_kernel_copy(vvar, vec![0; vvar.len()])
            .unwrap();

        assert_eq!(dump.bytes.len(), vvar.len());
        assert_eq!(dump.readable.len(), vvar.len());
    }

    #[test]
    fn uses_a_valid_kernel_page_size() {
        let size = page_size();
        assert!(size >= FALLBACK_PAGE_SIZE);
        assert!(size.is_power_of_two());
    }
}
