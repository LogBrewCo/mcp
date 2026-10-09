use alloc::{collections::BTreeSet, string::String, vec, vec::Vec};

use super::PathMap;
use crate::{Result, error, relative_path};

/// # Errors
/// Rejects unsafe or overlapping source prefixes and invalid marker limits.
pub(super) fn validate(maps: &[PathMap], markers: &[String]) -> Result<()> {
    if maps.len() > 32
        || markers.is_empty()
        || markers.len() > 16
        || markers.iter().any(|marker| {
            marker.is_empty()
                || marker.len() > 256
                || marker.contains(['\0', '\n', '\r'])
                || !marker.is_ascii()
        })
    {
        return Err(error("invalid relink mapping or marker limits"));
    }
    let mut seen = BTreeSet::new();
    for mapping in maps {
        let _from: &std::path::Path = relative_path(&mapping.from)?;
        let _to: &std::path::Path = relative_path(&mapping.to)?;
        if !seen.insert(&mapping.from) || mapping.from == mapping.to {
            return Err(error("duplicate or unchanged relink mapping"));
        }
    }
    for (index, first) in maps.iter().enumerate() {
        if maps.iter().skip(index.saturating_add(1)).any(|second| {
            suffix(&first.from, &second.from).is_some()
                || suffix(&second.from, &first.from).is_some()
        }) {
            return Err(error("overlapping relink source prefixes"));
        }
    }
    Ok(())
}

fn suffix<'value>(value: &'value str, prefix: &str) -> Option<&'value str> {
    value
        .strip_prefix(prefix)
        .filter(|tail| tail.is_empty() || tail.starts_with('/'))
}

pub(super) struct Remapper<'maps> {
    maps: &'maps [PathMap],
    used: Vec<bool>,
}

impl<'maps> Remapper<'maps> {
    pub(super) fn new(maps: &'maps [PathMap]) -> Self {
        Self {
            maps,
            used: vec![false; maps.len()],
        }
    }

    /// # Errors
    /// Propagates an inconsistent mapping-use record.
    pub(super) fn map(&mut self, value: &str) -> Result<String> {
        let Some((index, mapping, tail)) =
            self.maps.iter().enumerate().find_map(|(index, mapping)| {
                suffix(value, &mapping.from).map(|tail| (index, mapping, tail))
            })
        else {
            return Ok(value.to_owned());
        };
        let used = self
            .used
            .get_mut(index)
            .ok_or_else(|| error("invalid relink mapping record"))?;
        *used = true;
        Ok(format!("{}{tail}", mapping.to))
    }

    /// # Errors
    /// Rejects a declared mapping absent from files and response arguments.
    pub(super) fn finish(self) -> Result<()> {
        if self.used.iter().any(|used| !used) {
            return Err(error("unused relink path mapping"));
        }
        Ok(())
    }
}

/// # Errors
/// Rejects any exact selected marker in paths, material bytes or metadata.
pub(super) fn check_markers(bytes: &[u8], markers: &[String]) -> Result<()> {
    if markers.iter().any(|marker| {
        !marker.is_empty()
            && bytes
                .windows(marker.len())
                .any(|part| part == marker.as_bytes())
    }) {
        return Err(error("relink material contains a selected private marker"));
    }
    Ok(())
}
