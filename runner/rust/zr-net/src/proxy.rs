//! Proxy settings from the environment, as curl reads them: `HTTPS_PROXY` for https URLs, `HTTP_PROXY`
//! for http ones (each also in lower case, which wins), and `NO_PROXY` for what goes direct: `*`,
//! host names (a name also matches its subdomains, a leading dot is the same), IP addresses, CIDR
//! blocks, each with an optional `:port`. Loopback is never proxied. Only `http://` proxies, with an
//! optional `user:password@`, which become a Basic `Proxy-Authorization`; https URLs are tunnelled
//! with CONNECT (client.rs).
use std::net::IpAddr;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    /// `Basic <base64>`, when the URL had credentials.
    pub authorization: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Rule {
    Any,
    Name { name: String, port: Option<u16> },
    Ip { ip: IpAddr, port: Option<u16> },
    Cidr { ip: IpAddr, bits: u8 },
}

#[derive(Clone, Debug, Default)]
pub struct Proxy {
    http: Option<Target>,
    https: Option<Target>,
    no: Vec<Rule>,
}

pub fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for c in input.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

fn parse_target(s: &str) -> Option<Target> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let rest = match s.split_once("://") {
        Some(("http", r)) => r,
        Some(_) => return None,
        None => s,
    };
    let rest = rest.split('/').next()?;
    let (auth, hostport) = match rest.rsplit_once('@') {
        Some((a, h)) => (Some(a), h),
        None => (None, rest),
    };
    let (host, port) = split_host_port(hostport)?;
    Some(Target {
        host: host.to_ascii_lowercase(),
        port: port.unwrap_or(80),
        authorization: auth.map(|a| format!("Basic {}", base64(a.as_bytes()))),
    })
}

/// `host`, `host:port`, `[v6]`, `[v6]:port`.
fn split_host_port(s: &str) -> Option<(&str, Option<u16>)> {
    if let Some(r) = s.strip_prefix('[') {
        let (h, after) = r.split_once(']')?;
        return match after.strip_prefix(':') {
            Some(p) => Some((h, Some(p.parse().ok()?))),
            None if after.is_empty() => Some((h, None)),
            None => None,
        };
    }
    if s.matches(':').count() > 1 {
        // A bare IPv6 address.
        return Some((s, None));
    }
    match s.split_once(':') {
        Some((h, p)) => Some((h, Some(p.parse().ok()?))),
        None => Some((s, None)),
    }
}

fn parse_rules(s: &str) -> Vec<Rule> {
    s.split([',', ' '])
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .filter_map(|e| {
            if e == "*" {
                return Some(Rule::Any);
            }
            if let Some((ip, bits)) = e.split_once('/') {
                let ip: IpAddr = ip.trim_matches(['[', ']']).parse().ok()?;
                let bits: u8 = bits.parse().ok()?;
                let max = if ip.is_ipv4() { 32 } else { 128 };
                return (bits <= max).then_some(Rule::Cidr { ip, bits });
            }
            let (host, port) = split_host_port(e)?;
            let host = host.trim_start_matches('.').to_ascii_lowercase();
            match host.parse::<IpAddr>() {
                Ok(ip) => Some(Rule::Ip { ip, port }),
                Err(_) => Some(Rule::Name { name: host, port }),
            }
        })
        .collect()
}

fn in_cidr(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    }
}

impl Proxy {
    /// From values, as `from_env` reads them: for tests and for callers with their own.
    pub fn new(http: &str, https: &str, no: &str) -> Proxy {
        Proxy { http: parse_target(http), https: parse_target(https), no: parse_rules(no) }
    }

    pub fn from_env() -> Proxy {
        let get = |upper: &str, lower: &str| {
            std::env::var(lower).ok().filter(|v| !v.is_empty()).or_else(|| std::env::var(upper).ok()).unwrap_or_default()
        };
        Proxy::new(&get("HTTP_PROXY", "http_proxy"), &get("HTTPS_PROXY", "https_proxy"), &get("NO_PROXY", "no_proxy"))
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.http.is_none() && self.https.is_none()
    }

    /// The proxy a request to `host:port` goes through, if any.
    pub fn for_url(&self, https: bool, host: &str, port: u16) -> Option<&Target> {
        let target = if https { self.https.as_ref() } else { self.http.as_ref() }?;
        if self.bypass(host, port) {
            return None;
        }
        Some(target)
    }

    fn bypass(&self, host: &str, port: u16) -> bool {
        let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
        let ip = host.parse::<IpAddr>().ok();
        if host == "localhost" || host.ends_with(".localhost") || ip.is_some_and(|i| i.is_loopback()) {
            return true;
        }
        self.no.iter().any(|r| match r {
            Rule::Any => true,
            Rule::Name { name, port: p } => {
                p.is_none_or(|p| p == port) && ip.is_none() && (host == *name || host.ends_with(&format!(".{name}")))
            }
            Rule::Ip { ip: rule, port: p } => p.is_none_or(|p| p == port) && ip == Some(*rule),
            Rule::Cidr { ip: net, bits } => ip.is_some_and(|i| in_cidr(i, *net, *bits)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_rfc_vectors() {
        for (i, o) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("foobar", "Zm9vYmFy")] {
            assert_eq!(base64(i.as_bytes()), o);
        }
    }

    #[test]
    fn urls_with_and_without_scheme_credentials_and_ports() {
        let t = parse_target("http://user:p%40ss@Proxy.Example:3128/").unwrap();
        assert_eq!((t.host.as_str(), t.port), ("proxy.example", 3128));
        assert_eq!(t.authorization.as_deref(), Some(&*format!("Basic {}", base64(b"user:p%40ss"))));
        assert_eq!(parse_target("proxy:8080").unwrap().port, 8080);
        assert_eq!(parse_target("http://[::1]:3128").unwrap().host, "::1");
        assert_eq!(parse_target("socks5://x:1"), None);
        assert_eq!(parse_target(""), None);
    }

    #[test]
    fn no_proxy_as_curl_documents_it() {
        let p = Proxy::new("http://hp:1", "http://sp:2", "example.com, .internal ,10.0.0.0/8,192.168.1.5,fd00::/8,special:8443");
        // https goes through the https proxy, http through the http one.
        assert_eq!(p.for_url(true, "api.github.com", 443).unwrap().host, "sp");
        assert_eq!(p.for_url(false, "api.github.com", 80).unwrap().host, "hp");
        // Names match themselves and their subdomains, not look-alikes.
        assert!(p.for_url(true, "example.com", 443).is_none());
        assert!(p.for_url(true, "a.b.example.com", 443).is_none());
        assert!(p.for_url(true, "notexample.com", 443).is_some());
        assert!(p.for_url(true, "svc.internal", 443).is_none());
        // Addresses and blocks.
        assert!(p.for_url(true, "10.2.3.4", 443).is_none());
        assert!(p.for_url(true, "11.2.3.4", 443).is_some());
        assert!(p.for_url(true, "192.168.1.5", 443).is_none());
        assert!(p.for_url(true, "[fd12::1]", 443).is_none());
        // A port narrows a rule.
        assert!(p.for_url(true, "special", 8443).is_none());
        assert!(p.for_url(true, "special", 443).is_some());
        // Loopback is never proxied; `*` is everything.
        assert!(p.for_url(true, "127.0.0.1", 443).is_none());
        assert!(p.for_url(true, "localhost", 443).is_none());
        assert!(Proxy::new("http://hp:1", "", "*").for_url(false, "x.org", 80).is_none());
        // No proxy variable, no proxy.
        assert!(Proxy::new("", "", "").for_url(true, "x.org", 443).is_none());
        assert!(Proxy::new("", "", "").is_empty());
    }
}
