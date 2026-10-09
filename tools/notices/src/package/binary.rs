use crate::{Result, error};

use super::Target;

mod elf;
mod mach;

#[cfg(test)]
mod tests;

use serde_json::Value;

/// # Errors
/// Rejects an unsupported executable header, invalid Mach-O command extent,
/// binary-parser failures, invalid load metadata, and an oversized JSON report.
pub fn requirements(target: Target, input: &[u8]) -> Result<Value> {
    check(target, input)?;
    if matches!(target, Target::MacArm | Target::MacX86) {
        let commands = u32::from_le_bytes(bytes(input, 16)?);
        let size = usize::try_from(u32::from_le_bytes(bytes(input, 20)?))?;
        let minimum = usize::try_from(commands)?
            .checked_mul(8)
            .ok_or("invalid binary load command extent")?;
        let end = size
            .checked_add(32)
            .ok_or("invalid binary load command extent")?;
        if commands > 4096 || size < minimum || end > input.len() {
            return Err(error("invalid binary load command extent"));
        }
        mach::validate_commands(
            input.get(32..end).ok_or("missing load command region")?,
            commands,
        )?;
    }
    let requirements = match target {
        Target::MacArm | Target::MacX86 => {
            mach::requirements(&goblin::mach::MachO::parse(input, 0)?)?
        }
        Target::LinuxArm | Target::LinuxX86 => elf::requirements(
            &goblin::elf::Elf::parse(input)?,
            u64::try_from(input.len())?,
        )?,
    };
    if serde_json::to_vec(&requirements)?.len() > 16_usize << 10_u32 {
        return Err(error("binary load requirement report exceeds limit"));
    }
    Ok(requirements)
}

#[derive(Default)]
struct TextBudget {
    bytes: usize,
    strings: usize,
}

impl TextBudget {
    /// # Errors
    /// Rejects empty, oversized, NUL-containing, or line-breaking text, excessive
    /// string count, and overflow or excess in the combined JSON text budget.
    fn admit(&mut self, value: &str) -> Result<()> {
        if self.strings >= 256
            || value.is_empty()
            || value.len() > 4096
            || value.contains(['\0', '\n', '\r'])
        {
            return Err(error("invalid binary load requirement string or count"));
        }
        let bytes = self
            .bytes
            .checked_add(serde_json::to_vec(value)?.len())
            .ok_or_else(|| error("binary load text size overflow"))?;
        if bytes > 8_usize << 10_u32 {
            return Err(error("binary load requirement text exceeds limit"));
        }
        self.bytes = bytes;
        self.strings = self
            .strings
            .checked_add(1)
            .ok_or("binary load string count overflow")?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when any string fails admission to the shared text and
    /// count budgets.
    fn strings<'text, Values>(&mut self, values: Values) -> Result<Vec<&'text str>>
    where
        Values: Iterator<Item = &'text str>,
    {
        let mut result = Vec::new();
        for value in values {
            self.admit(value)?;
            result.push(value);
        }
        Ok(result)
    }
}

/// # Errors
/// Rejects offset overflow or a truncated fixed-width field.
fn bytes<const N: usize>(input: &[u8], start: usize) -> Result<[u8; N]> {
    let end = start
        .checked_add(N)
        .ok_or_else(|| error("invalid binary header offset"))?;
    Ok(input
        .get(start..end)
        .ok_or_else(|| error("truncated binary header"))?
        .try_into()?)
}

/// # Errors
/// Rejects an executable with the wrong format, architecture, or file type,
/// a truncated header field, or a forbidden workstation path marker.
pub fn check(target: Target, input: &[u8]) -> Result<()> {
    let matches = match target {
        Target::MacArm => check_mach(input, 0x0100_000c)?,
        Target::MacX86 => check_mach(input, 0x0100_0007)?,
        Target::LinuxArm => check_elf(input, 183)?,
        Target::LinuxX86 => check_elf(input, 62)?,
    };
    if !matches {
        return Err(error("binary header differs from packaging target"));
    }
    for marker in [b"/Users/".as_slice(), b"/home/", b"/private/var/folders/"] {
        if input.windows(marker.len()).any(|part| part == marker) {
            return Err(error(
                "binary contains a disallowed workstation path marker",
            ));
        }
    }
    Ok(())
}

/// # Errors
/// Returns an error if a required Mach-O header field cannot be read.
/// Unsupported header values return `Ok(false)`.
fn check_mach(input: &[u8], machine: u32) -> Result<bool> {
    Ok(input.len() >= 32
        && u32::from_le_bytes(bytes(input, 0)?) == 0xfeed_facf
        && u32::from_le_bytes(bytes(input, 4)?) == machine
        && u32::from_le_bytes(bytes(input, 12)?) == 2)
}

/// # Errors
/// Returns an error if a required ELF header field cannot be read.
/// Unsupported header values return `Ok(false)`.
fn check_elf(input: &[u8], machine: u16) -> Result<bool> {
    Ok(input.len() >= 64
        && bytes::<7>(input, 0)? == *b"\x7fELF\x02\x01\x01"
        && matches!(u16::from_le_bytes(bytes(input, 16)?), 2 | 3)
        && u16::from_le_bytes(bytes(input, 18)?) == machine
        && u32::from_le_bytes(bytes(input, 20)?) == 1
        && u16::from_le_bytes(bytes(input, 52)?) == 64)
}
