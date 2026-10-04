use crate::{Result, error};

use super::Target;

mod elf;
mod mach;

#[cfg(test)]
mod tests;

use serde_json::Value;

pub fn requirements(target: Target, input: &[u8]) -> Result<Value> {
    check(target, input)?;
    if matches!(target, Target::MacArm | Target::MacX86) {
        let commands = u32::from_le_bytes(bytes(input, 16)?);
        let size = usize::try_from(u32::from_le_bytes(bytes(input, 20)?))?;
        if commands > 4096
            || size < usize::try_from(commands)? * 8
            || size.checked_add(32).is_none_or(|end| end > input.len())
        {
            return Err(error("invalid binary load command extent"));
        }
        mach::validate_commands(
            input
                .get(32..32 + size)
                .ok_or("missing load command region")?,
            commands,
        )?;
    }
    let requirements = match target {
        Target::MacArm | Target::MacX86 => {
            mach::requirements(&goblin::mach::MachO::parse(input, 0)?)?
        }
        Target::LinuxArm | Target::LinuxX86 => elf::requirements(&goblin::elf::Elf::parse(input)?)?,
    };
    if serde_json::to_vec(&requirements)?.len() > 16 << 10 {
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
    fn strings<'a>(&mut self, values: impl Iterator<Item = &'a str>) -> Result<Vec<&'a str>> {
        let mut result = Vec::new();
        for value in values {
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
            if bytes > 8 << 10 {
                return Err(error("binary load requirement text exceeds limit"));
            }
            self.bytes = bytes;
            self.strings += 1;
            result.push(value);
        }
        Ok(result)
    }
}

fn bytes<const N: usize>(input: &[u8], start: usize) -> Result<[u8; N]> {
    let end = start
        .checked_add(N)
        .ok_or_else(|| error("invalid binary header offset"))?;
    Ok(input
        .get(start..end)
        .ok_or_else(|| error("truncated binary header"))?
        .try_into()?)
}

pub fn check(target: Target, input: &[u8]) -> Result<()> {
    let matches = match target {
        Target::MacArm | Target::MacX86 => {
            let machine = match target {
                Target::MacArm => 0x0100_000c,
                _ => 0x0100_0007,
            };
            input.len() >= 32
                && u32::from_le_bytes(bytes(input, 0)?) == 0xfeed_facf
                && u32::from_le_bytes(bytes(input, 4)?) == machine
                && u32::from_le_bytes(bytes(input, 12)?) == 2
        }
        Target::LinuxArm | Target::LinuxX86 => {
            let machine = match target {
                Target::LinuxArm => 183,
                _ => 62,
            };
            input.len() >= 64
                && bytes::<7>(input, 0)? == *b"\x7fELF\x02\x01\x01"
                && matches!(u16::from_le_bytes(bytes(input, 16)?), 2 | 3)
                && u16::from_le_bytes(bytes(input, 18)?) == machine
                && u32::from_le_bytes(bytes(input, 20)?) == 1
                && u16::from_le_bytes(bytes(input, 52)?) == 64
        }
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
