//! Exact client authorization from trusted operator configuration.

use std::{collections::BTreeSet, fmt};

use serde::Deserialize;

use crate::{Failure, error::Kind, json, upstream::valid_token};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: String,
    clients: Vec<String>,
}

/// A bounded set of issuer-confirmed client IDs. The default empty set denies every client.
#[derive(Default)]
pub struct ClientAllowlist(BTreeSet<String>);

impl ClientAllowlist {
    /// Decode a version 1 JSON object without resolving IDs or contacting clients.
    /// IDs are compared exactly, including case, URL spelling, and trailing slashes.
    ///
    /// # Errors
    /// Rejects duplicate fields or IDs, unknown fields, invalid IDs, more than
    /// 64 entries, IDs above 2048 bytes, and documents above 16 KiB.
    pub fn decode(bytes: &[u8]) -> Result<Self, Failure> {
        let value =
            json::object(bytes, 16 << 10).map_err(|_| Failure::from(Kind::Configuration))?;
        let document: Document =
            serde_json::from_value(value).map_err(|_| Failure::from(Kind::Configuration))?;
        if document.version != "1" || document.clients.len() > 64 {
            return Err(Kind::Configuration.into());
        }
        let mut clients = BTreeSet::new();
        for client in document.clients {
            if client.len() > 2048 || !valid_token(&client) || !clients.insert(client) {
                return Err(Kind::Configuration.into());
            }
        }
        Ok(Self(clients))
    }

    pub(crate) fn contains(&self, client: &str) -> bool {
        self.0.contains(client)
    }
}

impl fmt::Debug for ClientAllowlist {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("client allowlist [redacted]")
    }
}
