//! Per-client admission for requests that have not yet proven authority.
//!
//! Every MCP request reserves one unit from its client's budget before it
//! takes a request slot or starts introspection. A request whose token
//! verifies returns the unit, so only unauthenticated and failed requests
//! spend the budget. Memory is bounded: clients past the tracked limit share
//! one overflow budget.

use alloc::collections::BTreeMap;
use core::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use std::sync::{Mutex, PoisonError};

use axum::http::HeaderMap;
use serde::Deserialize;
use tokio::time::Instant;

use crate::{Failure, error::Kind};

#[cfg(test)]
mod tests;

/// Operator limits for requests without verified authority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    /// Requests one client may start in a burst, 1 to 64.
    pub burst: u32,
    /// Sustained requests per minute for one client, 1 to 60000.
    pub per_minute: u32,
    /// Distinct clients tracked, 1 to 100000; the rest share one budget.
    pub tracked_clients: u32,
    /// Seconds a rejected token is refused without introspection, 0 to 300.
    pub rejected_token_seconds: u32,
    /// The single proxy whose `X-Real-IP` header names the client.
    #[serde(default)]
    pub trusted_proxy: Option<IpAddr>,
}

impl Admission {
    /// Check operator limits.
    ///
    /// # Errors
    /// Rejects values outside their documented ranges.
    pub fn validate(self) -> Result<Self, Failure> {
        if (1..=64).contains(&self.burst)
            && (1..=60_000).contains(&self.per_minute)
            && (1..=100_000).contains(&self.tracked_clients)
            && self.rejected_token_seconds <= 300
        {
            Ok(self)
        } else {
            Err(Kind::Configuration.into())
        }
    }

    pub(crate) fn rejected_token_ttl(self) -> Duration {
        Duration::from_secs(u64::from(self.rejected_token_seconds))
    }
}

/// Theoretical arrival times per client (GCRA), with one overflow budget.
pub(crate) struct Limiter {
    interval: Duration,
    tolerance: Duration,
    tracked: usize,
    trusted_proxy: Option<IpAddr>,
    state: Mutex<State>,
}

struct State {
    clients: BTreeMap<IpAddr, Instant>,
    overflow: Instant,
}

/// One reserved unit; `refund` returns it after authority is verified.
#[derive(Clone, Copy)]
pub(crate) struct Ticket {
    client: Option<IpAddr>,
}

impl Limiter {
    /// Build a limiter from validated operator limits.
    ///
    /// # Errors
    /// Rejects limits outside their documented ranges.
    pub(crate) fn new(admission: Admission) -> Result<Self, Failure> {
        let admission = admission.validate()?;
        let interval = Duration::from_secs(60)
            .checked_div(admission.per_minute)
            .ok_or(Kind::Configuration)?;
        let tolerance = interval
            .checked_mul(admission.burst)
            .ok_or(Kind::Configuration)?;
        let now = Instant::now();
        Ok(Self {
            interval,
            tolerance,
            tracked: usize::try_from(admission.tracked_clients)
                .map_err(Failure::redact(Kind::Configuration))?,
            trusted_proxy: admission.trusted_proxy,
            state: Mutex::new(State {
                clients: BTreeMap::new(),
                overflow: now,
            }),
        })
    }

    /// Name the client: the peer address, or `X-Real-IP` from the trusted proxy.
    /// IPv6 clients are grouped by /64, the smallest prefix a host is assigned.
    pub(crate) fn client(&self, peer: Option<SocketAddr>, headers: &HeaderMap) -> Option<IpAddr> {
        let peer = peer?.ip().to_canonical();
        let forwarded = || {
            let mut values = headers.get_all("x-real-ip").iter();
            let value = values.next()?;
            values
                .next()
                .is_none()
                .then(|| value.to_str().ok()?.parse::<IpAddr>().ok())
                .flatten()
        };
        let client = if Some(peer) == self.trusted_proxy {
            forwarded().map_or(peer, |client| client.to_canonical())
        } else {
            peer
        };
        Some(match client {
            IpAddr::V6(address) => IpAddr::V6(Ipv6Addr::from_bits(
                address.to_bits() & !u128::from(u64::MAX),
            )),
            IpAddr::V4(_) => client,
        })
    }

    /// Reserve one unit for the client.
    ///
    /// # Errors
    /// Returns the wait before the client's next unit is available.
    pub(crate) fn reserve(&self, client: Option<IpAddr>) -> Result<Ticket, Duration> {
        let now = Instant::now();
        let client = self.reserve_locked(
            &mut self.state.lock().unwrap_or_else(PoisonError::into_inner),
            client,
            now,
        )?;
        Ok(Ticket { client })
    }

    /// Advance the client's arrival time by one interval if within tolerance.
    ///
    /// # Errors
    /// Returns the wait before the client's next unit is available.
    fn reserve_locked(
        &self,
        state: &mut State,
        client: Option<IpAddr>,
        now: Instant,
    ) -> Result<Option<IpAddr>, Duration> {
        let tracked = client.filter(|address| self.track(state, *address, now));
        let arrival = arrival(state, tracked).ok_or(Duration::ZERO)?;
        let next = (*arrival)
            .max(now)
            .checked_add(self.interval)
            .ok_or(Duration::ZERO)?;
        let ahead = next.saturating_duration_since(now);
        if ahead > self.tolerance {
            return Err(ahead.saturating_sub(self.tolerance));
        }
        *arrival = next;
        Ok(tracked)
    }

    /// Return a reserved unit after the request proved its authority.
    pub(crate) fn refund(&self, ticket: Ticket) {
        let now = Instant::now();
        if let Some(arrival) = arrival(
            &mut self.state.lock().unwrap_or_else(PoisonError::into_inner),
            ticket.client,
        ) {
            *arrival = arrival.checked_sub(self.interval).unwrap_or(now).max(now);
        }
    }

    /// Track a client if it is known or there is room, evicting idle clients
    /// whose budget has fully refilled. Returns false for the overflow budget.
    fn track(&self, state: &mut State, client: IpAddr, now: Instant) -> bool {
        if state.clients.contains_key(&client) {
            return true;
        }
        if state.clients.len() >= self.tracked {
            state.clients.retain(|_, arrival| *arrival > now);
        }
        if state.clients.len() >= self.tracked {
            return false;
        }
        let _previous: Option<Instant> = state.clients.insert(client, now);
        true
    }

    #[cfg(test)]
    fn tracked_len(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clients
            .len()
    }
}

/// The arrival time for a tracked client, or the shared overflow budget.
fn arrival(state: &mut State, client: Option<IpAddr>) -> Option<&mut Instant> {
    match client {
        Some(address) => state.clients.get_mut(&address),
        None => Some(&mut state.overflow),
    }
}
