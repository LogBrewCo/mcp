use crate::{Result, error};
use goblin::elf::{Elf, program_header::PT_LOAD};
use serde_json::{Value, json};

use super::TextBudget;

pub fn requirements(binary: &Elf<'_>) -> Result<Value> {
    let mut text = TextBudget::default();
    if binary.program_headers.len() > 4096
        || !binary
            .program_headers
            .iter()
            .any(|header| header.p_type == PT_LOAD)
    {
        return Err(error("missing or invalid executable load segments"));
    }
    let libraries = text.strings(binary.libraries.iter().copied())?;
    if libraries.len()
        != binary
            .dynamic
            .as_ref()
            .map_or(0, |dynamic| dynamic.info.needed_count)
    {
        return Err(error("libraries differ from dynamic loader count"));
    }
    let interpreter = binary.interpreter;
    if let Some(value) = interpreter {
        text.strings(std::iter::once(value))?;
    } else if !libraries.is_empty() {
        return Err(error("dynamic executable has no interpreter"));
    }
    let expected = usize::try_from(
        binary
            .dynamic
            .as_ref()
            .map_or(0, |dynamic| dynamic.info.verneednum),
    )?;
    if expected > 256 {
        return Err(error("version library count exceeded"));
    }
    let mut requirements = Vec::new();
    if let Some(section) = &binary.verneed {
        for need in section {
            if requirements.len() >= 256 {
                return Err(error("version library count exceeded"));
            }
            let library = binary
                .dynstrtab
                .get_at(need.vn_file)
                .ok_or_else(|| error("missing version library"))?;
            text.strings(std::iter::once(library))?;
            let mut versions = Vec::new();
            for auxiliary in &need {
                if versions.len() >= 1024 {
                    return Err(error("symbol version count exceeded"));
                }
                let name = binary
                    .dynstrtab
                    .get_at(auxiliary.vna_name)
                    .ok_or_else(|| error("missing symbol version"))?;
                text.strings(std::iter::once(name))?;
                versions.push(
                    json!({"name":name,"flags":auxiliary.vna_flags,"index":auxiliary.vna_other}),
                );
            }
            if versions.len() != usize::from(need.vn_cnt) {
                return Err(error("incomplete symbol version records"));
            }
            requirements.push(
                json!({"library":library,"structure_version":need.vn_version,"versions":versions}),
            );
        }
    }
    if requirements.len() != expected {
        return Err(error("version records differ from dynamic loader count"));
    }
    Ok(
        json!({"format":"ELF","interpreter":interpreter,"libraries":libraries,
        "rpaths":text.strings(binary.rpaths.iter().copied())?,"runpaths":text.strings(binary.runpaths.iter().copied())?,
        "symbol_version_requirements":requirements}),
    )
}
