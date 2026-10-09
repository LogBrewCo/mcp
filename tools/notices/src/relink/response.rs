use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};

use super::paths::Remapper;
use crate::{Result, error, relative_path};

/// # Errors
/// Rejects NULs, unterminated quotes and incomplete escapes.
pub(super) fn tokenize(text: &str) -> Result<Vec<String>> {
    let mut chars = text.chars();
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut started = false;
    let mut quote = None;
    while let Some(character) = chars.next() {
        if character == '\0' {
            return Err(error("NUL in relink response"));
        }
        if character == '\\' {
            token.push(
                chars
                    .next()
                    .filter(|next| *next != '\0')
                    .ok_or_else(|| error("incomplete relink response escape"))?,
            );
            started = true;
        } else if quote == Some(character) {
            quote = None;
        } else if quote.is_some() {
            token.push(character);
        } else if matches!(character, '\'' | '"') {
            quote = Some(character);
            started = true;
        } else if matches!(character, ' ' | '\t' | '\r' | '\n') {
            flush(&mut tokens, &mut token, &mut started);
        } else {
            token.push(character);
            started = true;
        }
    }
    if quote.is_some() {
        return Err(error("unterminated relink response quote"));
    }
    if started {
        tokens.push(token);
    }
    Ok(tokens)
}

fn flush(tokens: &mut Vec<String>, token: &mut String, started: &mut bool) {
    if *started {
        tokens.push(core::mem::take(token));
    }
    *started = false;
}

fn serialize(tokens: &[String]) -> String {
    let mut response = String::new();
    for token in tokens {
        quote(token, &mut response);
    }
    response
}

fn quote(token: &str, output: &mut String) {
    output.push('"');
    for character in token.chars() {
        if matches!(character, '\\' | '"') {
            output.push('\\');
        }
        output.push(character);
    }
    output.push_str("\"\n");
}

struct State<'inputs, 'maps> {
    files: &'inputs BTreeMap<String, Vec<u8>>,
    remapper: &'inputs mut Remapper<'maps>,
    target: &'inputs str,
    seen: BTreeSet<String>,
    outputs: BTreeSet<String>,
    inputs: usize,
}

impl State<'_, '_> {
    /// # Errors
    /// Rejects duplicate singleton options and unsafe or colliding output paths.
    fn output(&mut self, flag: &str, value: &str) -> Result<String> {
        self.singleton(flag)?;
        let _path: &std::path::Path = relative_path(value)?;
        if value == "MANIFEST.json" || !self.outputs.insert(value.to_owned()) {
            return Err(error("duplicate or reserved relink output"));
        }
        Ok(value.to_owned())
    }

    /// # Errors
    /// Rejects repeated singleton options.
    fn singleton(&mut self, flag: &str) -> Result<()> {
        if !self.seen.insert(flag.to_owned()) {
            return Err(error("duplicate relink response option"));
        }
        Ok(())
    }

    /// # Errors
    /// Rejects unsupported operands or options and unsafe directory paths.
    fn operand(&mut self, flag: &str, value: &str) -> Result<String> {
        match flag {
            "-o" | "--Map" | "--dependency-file" | "--why-extract" => self.output(flag, value),
            "-L" => {
                let _path: &std::path::Path = relative_path(value)?;
                self.remapper.map(value)
            }
            "-l" if !value.is_empty()
                && value.len() <= 128
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
                }) =>
            {
                Ok(value.to_owned())
            }
            "--chroot" if value == "." => {
                self.singleton(flag)?;
                Ok(value.to_owned())
            }
            "-m" if value
                == match self.target {
                    "aarch64-unknown-linux-gnu" => "aarch64linux",
                    "x86_64-unknown-linux-gnu" => "elf_x86_64",
                    _ => return Err(error("unsupported relink target")),
                } =>
            {
                self.singleton(flag)?;
                Ok(value.to_owned())
            }
            "-dynamic-linker"
                if value
                    == match self.target {
                        "aarch64-unknown-linux-gnu" => "/lib/ld-linux-aarch64.so.1",
                        "x86_64-unknown-linux-gnu" => "/lib64/ld-linux-x86-64.so.2",
                        _ => return Err(error("unsupported relink target")),
                    } =>
            {
                self.singleton(flag)?;
                Ok(value.to_owned())
            }
            "-z" if matches!(value, "relro" | "now" | "noexecstack") => Ok(value.to_owned()),
            "--hash-style" if value == "gnu" => Ok(value.to_owned()),
            "-O" if value == "1" => Ok(value.to_owned()),
            _ => Err(error("unsupported relink response operand")),
        }
    }

    /// # Errors
    /// Rejects absent, reserved or unsafe bare input paths.
    fn input(&mut self, value: &str) -> Result<String> {
        let _path: &std::path::Path = relative_path(value)?;
        if matches!(value, "response.txt" | "version.txt" | "MANIFEST.json")
            || !self.files.contains_key(value)
        {
            return Err(error(
                "relink response references an absent or reserved input",
            ));
        }
        self.inputs = self
            .inputs
            .checked_add(1)
            .ok_or_else(|| error("relink input count overflow"))?;
        self.remapper.map(value)
    }

    /// # Errors
    /// Rejects incomplete commands and outputs that can overwrite archive materials.
    fn finish(&mut self) -> Result<()> {
        if self.inputs == 0
            || ["--chroot", "-o", "-m", "-dynamic-linker"]
                .iter()
                .any(|flag| !self.seen.contains(*flag))
        {
            return Err(error("incomplete relink response"));
        }
        for path in self.files.keys() {
            self.check_input(path)?;
        }
        if self
            .outputs
            .iter()
            .any(|output| conflicts(output, "MANIFEST.json"))
        {
            return Err(error("relink output conflicts with manifest"));
        }
        if self.outputs.iter().any(|first| {
            self.outputs
                .iter()
                .any(|second| first != second && conflicts(first, second))
        }) {
            return Err(error("conflicting relink output paths"));
        }
        Ok(())
    }

    /// # Errors
    /// Rejects mapped control files and outputs that overwrite input paths.
    fn check_input(&mut self, path: &str) -> Result<()> {
        let mapped = self.remapper.map(path)?;
        if matches!(path, "response.txt" | "version.txt") && mapped != path {
            return Err(error("relink control files cannot be mapped"));
        }
        if self.outputs.iter().any(|output| conflicts(output, &mapped)) {
            return Err(error("relink output would overwrite an input"));
        }
        Ok(())
    }
}

pub(super) fn conflicts(first: &str, second: &str) -> bool {
    first == second
        || first
            .strip_prefix(second)
            .is_some_and(|tail| tail.starts_with('/'))
        || second
            .strip_prefix(first)
            .is_some_and(|tail| tail.starts_with('/'))
}

/// # Errors
/// Rejects malformed syntax, unsupported arguments, incomplete commands, absent
/// inputs and unsafe paths. Rewrites only input and search-directory prefixes.
pub(super) fn rewrite(
    text: &str,
    files: &BTreeMap<String, Vec<u8>>,
    remapper: &mut Remapper<'_>,
    target: &str,
) -> Result<String> {
    let mut args = tokenize(text)?.into_iter();
    let mut output = Vec::new();
    let mut state = State {
        files,
        remapper,
        target,
        seen: BTreeSet::new(),
        outputs: BTreeSet::new(),
        inputs: 0,
    };
    while let Some(arg) = args.next() {
        if matches!(
            arg.as_str(),
            "-EL"
                | "--eh-frame-hdr"
                | "-pie"
                | "--fix-cortex-a53-843419"
                | "--as-needed"
                | "-Bstatic"
                | "-Bdynamic"
                | "--gc-sections"
                | "--strip-all"
        ) {
            output.push(arg);
        } else if matches!(
            arg.as_str(),
            "--chroot"
                | "-o"
                | "-m"
                | "-dynamic-linker"
                | "-L"
                | "-l"
                | "-z"
                | "--hash-style"
                | "-O"
                | "--Map"
                | "--dependency-file"
                | "--why-extract"
        ) {
            let value = args
                .next()
                .ok_or_else(|| error("missing relink response operand"))?;
            let relocated = state.operand(&arg, &value)?;
            output.push(arg);
            output.push(relocated);
        } else if let Some(value) = arg.strip_prefix("--why-extract=") {
            output.push(format!(
                "--why-extract={}",
                state.output("--why-extract", value)?
            ));
        } else if arg.starts_with(['-', '@']) {
            return Err(error("unsupported relink response option"));
        } else {
            output.push(state.input(&arg)?);
        }
    }
    state.finish()?;
    let response = serialize(&output);
    if response.len() > super::RESPONSE_BYTES {
        return Err(error("rewritten relink response exceeds limit"));
    }
    Ok(response)
}
