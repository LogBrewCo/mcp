//! Match only the configured HTTPS host and effective port.

use axum::{
    extract::Request,
    http::{header, uri::Authority},
};

pub(super) struct HttpsAuthority {
    authority: Authority,
    port: u16,
}

impl HttpsAuthority {
    pub(super) fn parse(value: &str) -> Option<Self> {
        let authority: Authority = value.parse().ok()?;
        let port = effective_port(&authority)?;
        Some(Self { authority, port })
    }

    pub(super) fn allows(&self, request: &Request) -> bool {
        let mut hosts = request.headers().get_all(header::HOST).iter();
        let host = hosts.next();
        if hosts.next().is_some() {
            return false;
        }
        let uri_authority = request.uri().authority();
        if host.is_none() && uri_authority.is_none() {
            return false;
        }
        if uri_authority.is_some_and(|authority| !self.matches(authority))
            || host
                .is_some_and(|value| !value.to_str().is_ok_and(|value| self.matches_value(value)))
        {
            return false;
        }
        let mut origins = request.headers().get_all(header::ORIGIN).iter();
        let origin = origins.next();
        origins.next().is_none()
            && origin
                .is_none_or(|value| value.to_str().is_ok_and(|value| self.matches_origin(value)))
    }

    fn matches_value(&self, value: &str) -> bool {
        value
            .parse::<Authority>()
            .is_ok_and(|authority| self.matches(&authority))
    }

    fn matches_origin(&self, value: &str) -> bool {
        value.split_once("://").is_some_and(|(scheme, authority)| {
            scheme.eq_ignore_ascii_case("https") && self.matches_value(authority)
        })
    }

    fn matches(&self, authority: &Authority) -> bool {
        self.authority.host().eq_ignore_ascii_case(authority.host())
            && effective_port(authority) == Some(self.port)
    }
}

fn effective_port(authority: &Authority) -> Option<u16> {
    let host = authority.host();
    if host.is_empty() {
        return None;
    }
    // Authority::port_u16 returns None for invalid ports as well as absent ports.
    // Inspect the exact suffix so userinfo, empty and nonnumeric ports cannot
    // acquire the HTTPS default. IPv6 host colons remain inside the brackets.
    match authority.as_str().strip_prefix(host)? {
        "" => Some(443),
        suffix => {
            let port = suffix.strip_prefix(':')?;
            if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            port.parse().ok()
        }
    }
}
