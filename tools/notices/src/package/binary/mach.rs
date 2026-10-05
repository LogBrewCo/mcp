use crate::{Result, error};
use goblin::{
    container::Endian,
    mach::{
        MachO,
        load_command::{CommandVariant, LoadCommand},
    },
};
use serde_json::{Value, json};

use super::{TextBudget, bytes};

/// # Errors
/// Rejects truncated, misaligned, overflowing, unsupported, or inconsistent
/// load commands, invalid command strings, and out-of-bounds record arrays.
pub fn validate_commands(region: &[u8], count: u32) -> Result<()> {
    let mut offset = 0_usize;
    for _ in 0..count {
        let size_offset = offset.checked_add(4).ok_or("command offset overflow")?;
        let size = usize::try_from(u32::from_le_bytes(bytes(region, size_offset)?))?;
        let end = offset.checked_add(size).ok_or("command size overflow")?;
        if size < 8 || !size.is_multiple_of(8) {
            return Err(error("invalid 64-bit load command size"));
        }
        let command = region
            .get(offset..end)
            .ok_or("load command exceeds its region")?;
        let parsed = LoadCommand::parse(command, &mut 0, Endian::Little)?;
        let string = match parsed.command {
            CommandVariant::LoadDylib(value)
            | CommandVariant::LoadUpwardDylib(value)
            | CommandVariant::ReexportDylib(value)
            | CommandVariant::LoadWeakDylib(value)
            | CommandVariant::LazyLoadDylib(value)
            | CommandVariant::IdDylib(value) => Some((24, value.dylib.name)),
            CommandVariant::Rpath(value) => Some((12, value.path)),
            CommandVariant::BuildVersion(value) => {
                contained_records(command, 24, 8, value.ntools)?;
                None
            }
            CommandVariant::Segment64(value) => {
                contained_records(command, 72, 80, value.nsects)?;
                None
            }
            CommandVariant::Segment32(value) => {
                contained_records(command, 56, 68, value.nsects)?;
                None
            }
            CommandVariant::Uuid(_)
            | CommandVariant::Symtab(_)
            | CommandVariant::Symseg(_)
            | CommandVariant::Thread(_)
            | CommandVariant::Unixthread(_)
            | CommandVariant::LoadFvmlib(_)
            | CommandVariant::IdFvmlib(_)
            | CommandVariant::Ident(_)
            | CommandVariant::Fvmfile(_)
            | CommandVariant::Prepage(_)
            | CommandVariant::Dysymtab(_)
            | CommandVariant::LoadDylinker(_)
            | CommandVariant::IdDylinker(_)
            | CommandVariant::PreboundDylib(_)
            | CommandVariant::Routines32(_)
            | CommandVariant::Routines64(_)
            | CommandVariant::SubFramework(_)
            | CommandVariant::SubUmbrella(_)
            | CommandVariant::SubClient(_)
            | CommandVariant::SubLibrary(_)
            | CommandVariant::TwolevelHints(_)
            | CommandVariant::PrebindCksum(_)
            | CommandVariant::CodeSignature(_)
            | CommandVariant::SegmentSplitInfo(_)
            | CommandVariant::EncryptionInfo32(_)
            | CommandVariant::EncryptionInfo64(_)
            | CommandVariant::DyldInfo(_)
            | CommandVariant::DyldInfoOnly(_)
            | CommandVariant::VersionMinMacosx(_)
            | CommandVariant::VersionMinIphoneos(_)
            | CommandVariant::FunctionStarts(_)
            | CommandVariant::DyldEnvironment(_)
            | CommandVariant::Main(_)
            | CommandVariant::DataInCode(_)
            | CommandVariant::FilesetEntry(_)
            | CommandVariant::SourceVersion(_)
            | CommandVariant::DylibCodeSignDrs(_)
            | CommandVariant::LinkerOption(_)
            | CommandVariant::LinkerOptimizationHint(_)
            | CommandVariant::VersionMinTvos(_)
            | CommandVariant::VersionMinWatchos(_)
            | CommandVariant::DyldExportsTrie(_)
            | CommandVariant::DyldChainedFixups(_)
            | CommandVariant::Note(_)
            | CommandVariant::Unimplemented(_) => None,
            // Review future Goblin variants before accepting their command layout.
            _ => return Err(error("unsupported binary load command")),
        };
        if let Some((minimum, start)) = string {
            validate_string(command, minimum, start)?;
        }
        offset = end;
    }
    if offset != region.len() {
        return Err(error("load command sizes differ from declared region"));
    }
    Ok(())
}

/// # Errors
/// Rejects an invalid string offset or a string without a NUL terminator
/// inside its own load command.
fn validate_string(command: &[u8], minimum: usize, start: u32) -> Result<()> {
    let start = usize::try_from(start)?;
    if start < minimum || !command.get(start..).is_some_and(|value| value.contains(&0)) {
        return Err(error("load command string exceeds its command"));
    }
    Ok(())
}

/// # Errors
/// Rejects count conversion or size arithmetic overflow and record arrays
/// that extend beyond the command.
fn contained_records(command: &[u8], header: usize, record: usize, count: u32) -> Result<()> {
    let required = usize::try_from(count)?
        .checked_mul(record)
        .and_then(|size| size.checked_add(header));
    if required.is_none_or(|size| size > command.len()) {
        return Err(error("load command records exceed their command"));
    }
    Ok(())
}

fn version(value: u32) -> String {
    format!("{}.{}.{}", value >> 16, (value >> 8) & 255, value & 255)
}

/// # Errors
/// Rejects excess or inconsistent commands, unsupported command variants,
/// missing or conflicting macOS deployment targets, unexpected self-library
/// identity, and invalid or excessive library and search-path text.
pub fn requirements(binary: &MachO<'_>) -> Result<Value> {
    let mut text = TextBudget::default();
    if binary.load_commands.len() > 4096 || binary.load_commands.len() != binary.header.ncmds {
        return Err(error("invalid binary load command count"));
    }
    let mut deployment = None;
    for command in &binary.load_commands {
        let record = match command.command {
            CommandVariant::BuildVersion(build) if build.platform == 1 => {
                Some(json!({"kind":"build_version",
                "platform":build.platform,"minimum_os":version(build.minos),"sdk":version(build.sdk)}))
            }
            CommandVariant::BuildVersion(_)
            | CommandVariant::VersionMinIphoneos(_)
            | CommandVariant::VersionMinTvos(_)
            | CommandVariant::VersionMinWatchos(_) => {
                return Err(error("non-macOS deployment command"));
            }
            CommandVariant::VersionMinMacosx(build) => Some(json!({"kind":"version_min_macos",
                "minimum_os":version(build.version),"sdk":version(build.sdk)})),
            CommandVariant::Segment32(_)
            | CommandVariant::Segment64(_)
            | CommandVariant::Uuid(_)
            | CommandVariant::Symtab(_)
            | CommandVariant::Symseg(_)
            | CommandVariant::Thread(_)
            | CommandVariant::Unixthread(_)
            | CommandVariant::LoadFvmlib(_)
            | CommandVariant::IdFvmlib(_)
            | CommandVariant::Ident(_)
            | CommandVariant::Fvmfile(_)
            | CommandVariant::Prepage(_)
            | CommandVariant::Dysymtab(_)
            | CommandVariant::LoadDylib(_)
            | CommandVariant::IdDylib(_)
            | CommandVariant::LoadDylinker(_)
            | CommandVariant::IdDylinker(_)
            | CommandVariant::PreboundDylib(_)
            | CommandVariant::Routines32(_)
            | CommandVariant::Routines64(_)
            | CommandVariant::SubFramework(_)
            | CommandVariant::SubUmbrella(_)
            | CommandVariant::SubClient(_)
            | CommandVariant::SubLibrary(_)
            | CommandVariant::TwolevelHints(_)
            | CommandVariant::PrebindCksum(_)
            | CommandVariant::LoadWeakDylib(_)
            | CommandVariant::Rpath(_)
            | CommandVariant::CodeSignature(_)
            | CommandVariant::SegmentSplitInfo(_)
            | CommandVariant::ReexportDylib(_)
            | CommandVariant::LazyLoadDylib(_)
            | CommandVariant::EncryptionInfo32(_)
            | CommandVariant::EncryptionInfo64(_)
            | CommandVariant::DyldInfo(_)
            | CommandVariant::DyldInfoOnly(_)
            | CommandVariant::LoadUpwardDylib(_)
            | CommandVariant::FunctionStarts(_)
            | CommandVariant::DyldEnvironment(_)
            | CommandVariant::Main(_)
            | CommandVariant::DataInCode(_)
            | CommandVariant::FilesetEntry(_)
            | CommandVariant::SourceVersion(_)
            | CommandVariant::DylibCodeSignDrs(_)
            | CommandVariant::LinkerOption(_)
            | CommandVariant::LinkerOptimizationHint(_)
            | CommandVariant::DyldExportsTrie(_)
            | CommandVariant::DyldChainedFixups(_)
            | CommandVariant::Note(_)
            | CommandVariant::Unimplemented(_) => None,
            // Review future Goblin variants before accepting their requirements.
            _ => return Err(error("unsupported binary load requirement command")),
        };
        if let Some(record) = record
            && deployment.replace(record).is_some()
        {
            return Err(error("ambiguous macOS deployment metadata"));
        }
    }
    let deployment = deployment.ok_or_else(|| error("missing macOS deployment metadata"))?;
    if binary.libs.first().copied() != Some("self") {
        return Err(error("unexpected executable library identity"));
    }
    Ok(json!({"format":"Mach-O","deployment":deployment,
        "libraries":text.strings(binary.libs.iter().copied().skip(1))?,"rpaths":text.strings(binary.rpaths.iter().copied())?}))
}
