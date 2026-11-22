//! The configuration file: one section per site.
//!
//! ```text
//! [vw.example.org]
//! upstream  = 127.0.0.1:3678
//! cert      = /etc/letsencrypt/live/vw.example.org/fullchain.pem
//! key       = /etc/letsencrypt/live/vw.example.org/privkey.pem
//! websocket = yes
//! allow     = /etc/shioko/cloudflare.txt 10.0.0.0/8
//! max-body  = 525M
//! ```

use crate::net::{self, Range};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// The largest request body a site takes unless it says otherwise.
const DEFAULT_MAX_BODY: u64 = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Site {
    /// The host name, in lower case.
    pub name: String,
    /// `host:port` of the HTTP/1.1 server the site is forwarded to.
    pub upstream: String,
    /// The certificate chain and its private key. Without them the site is
    /// served over plain HTTP.
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    /// WebSocket upgrades are let through.
    pub websocket: bool,
    /// Who may connect; `None` is everyone.
    pub allow: Option<Vec<Range>>,
    /// The largest request body, in bytes.
    pub max_body: u64,
}

impl Site {
    pub fn allows(&self, address: IpAddr) -> bool {
        self.allow.as_ref().is_none_or(|ranges| ranges.iter().any(|r| r.contains(address)))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub sites: Vec<Site>,
}

impl Config {
    /// The site with this host name, compared without case.
    pub fn site(&self, name: &[u8]) -> Option<&Site> {
        self.sites.iter().find(|site| name.eq_ignore_ascii_case(site.name.as_bytes()))
    }

    /// Reads and checks a configuration file.
    pub fn load(path: &Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Config::parse(&text, &|file| std::fs::read_to_string(file).map_err(|e| e.to_string()))
            .map_err(|message| format!("{}: {message}", path.display()))
    }

    /// Checks `text`. `read` is how the files it names are read.
    pub fn parse(text: &str, read: &dyn Fn(&Path) -> Result<String, String>) -> Result<Config, String> {
        let mut sites: Vec<Site> = Vec::new();
        let mut section: Option<Section> = None;
        for (index, raw) in text.lines().enumerate() {
            let number = index.saturating_add(1);
            let fail = |message: String| format!("line {number}: {message}");
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
                if let Some(done) = section.take() {
                    sites.push(done.finish()?);
                }
                let name = name.trim().to_ascii_lowercase();
                if !is_host_name(&name) {
                    return Err(fail(format!("'{name}' is not a host name")));
                }
                if sites.iter().any(|site| site.name == name) {
                    return Err(fail(format!("site '{name}' is defined twice")));
                }
                section = Some(Section::new(name, number));
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(fail("expected '[hostname]' or 'key = value'".into()));
            };
            let Some(current) = section.as_mut() else {
                return Err(fail("a setting before the first '[hostname]'".into()));
            };
            current.set(key.trim(), value.trim(), read).map_err(fail)?;
        }
        if let Some(done) = section.take() {
            sites.push(done.finish()?);
        }
        Ok(Config { sites })
    }
}

fn is_host_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// A section while it is being read.
struct Section {
    name: String,
    line: usize,
    upstream: Option<String>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    websocket: Option<bool>,
    allow: Option<Vec<Range>>,
    max_body: Option<u64>,
}

impl Section {
    fn new(name: String, line: usize) -> Section {
        Section { name, line, upstream: None, cert: None, key: None, websocket: None, allow: None, max_body: None }
    }

    fn set(
        &mut self,
        key: &str,
        value: &str,
        read: &dyn Fn(&Path) -> Result<String, String>,
    ) -> Result<(), String> {
        let repeated = match key {
            "upstream" => self.upstream.is_some(),
            "cert" => self.cert.is_some(),
            "key" => self.key.is_some(),
            "websocket" => self.websocket.is_some(),
            "allow" => self.allow.is_some(),
            "max-body" => self.max_body.is_some(),
            _ => return Err(format!("unknown setting '{key}'")),
        };
        if repeated {
            return Err(format!("'{key}' is set twice"));
        }
        if value.is_empty() {
            return Err(format!("'{key}' has no value"));
        }
        match key {
            "upstream" => self.upstream = Some(upstream(value)?),
            "cert" | "key" => {
                let path = PathBuf::from(value);
                read(&path).map_err(|e| format!("cannot read {value}: {e}"))?;
                if key == "cert" { self.cert = Some(path) } else { self.key = Some(path) }
            }
            "websocket" => {
                self.websocket = Some(match value {
                    "yes" => true,
                    "no" => false,
                    _ => return Err(format!("websocket is 'yes' or 'no', not '{value}'")),
                });
            }
            "allow" => self.allow = Some(allow(value, read)?),
            _ => self.max_body = Some(size(value).ok_or(format!("'{value}' is not a size"))?),
        }
        Ok(())
    }

    fn finish(self) -> Result<Site, String> {
        let fail = |message: &str| format!("line {}: site '{}' {message}", self.line, self.name);
        let upstream = self.upstream.ok_or_else(|| fail("has no upstream"))?;
        if self.cert.is_some() != self.key.is_some() {
            return Err(fail("needs both cert and key, or neither"));
        }
        Ok(Site {
            name: self.name,
            upstream,
            cert: self.cert,
            key: self.key,
            websocket: self.websocket.unwrap_or(false),
            allow: self.allow,
            max_body: self.max_body.unwrap_or(DEFAULT_MAX_BODY),
        })
    }
}

/// Checks `host:port`. A loopback address at port 80 or 443 is refused:
/// that would be shioko itself, and every request would go round for ever.
fn upstream(value: &str) -> Result<String, String> {
    let bad = || format!("'{value}' is not host:port");
    let (host, port) = value.rsplit_once(':').ok_or_else(bad)?;
    let port: u16 = port.parse().map_err(|_| bad())?;
    let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    let address: Option<IpAddr> = bare.parse().ok();
    if port == 0 || !(address.is_some() || is_host_name(host)) {
        return Err(bad());
    }
    let to_ourselves = host == "localhost" || address.is_some_and(net::is_loopback);
    if to_ourselves && (port == 80 || port == 443) {
        return Err(format!("upstream {value} is shioko itself"));
    }
    Ok(value.to_string())
}

/// Reads address ranges, and files of address ranges (one per line).
fn allow(value: &str, read: &dyn Fn(&Path) -> Result<String, String>) -> Result<Vec<Range>, String> {
    let mut ranges = Vec::new();
    for item in value.split_whitespace() {
        if item.starts_with('/') {
            let text = read(Path::new(item)).map_err(|e| format!("cannot read {item}: {e}"))?;
            for (index, line) in text.lines().enumerate() {
                let line = line.split('#').next().unwrap_or("").trim();
                if line.is_empty() {
                    continue;
                }
                let range = Range::parse(line).ok_or_else(|| {
                    format!("{item} line {}: '{line}' is not an address range", index.saturating_add(1))
                })?;
                ranges.push(range);
            }
        } else {
            ranges.push(Range::parse(item).ok_or(format!("'{item}' is not an address range"))?);
        }
    }
    Ok(ranges)
}

/// Reads a size: a number of bytes, or a number followed by K, M or G.
fn size(value: &str) -> Option<u64> {
    let (digits, unit): (&str, u64) = match value.as_bytes().last()? {
        b'K' => (value.strip_suffix('K')?, 1 << 10),
        b'M' => (value.strip_suffix('M')?, 1 << 20),
        b'G' => (value.strip_suffix('G')?, 1 << 30),
        _ => (value, 1),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u64>().ok()?.checked_mul(unit)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    fn files(path: &Path) -> Result<String, String> {
        match path.to_str().unwrap() {
            "/certs/chain.pem" | "/certs/key.pem" => Ok("pem".into()),
            "/etc/ranges.txt" => Ok("# Cloudflare\n173.245.48.0/20\n\n2400:cb00::/32 # v6\n".into()),
            "/etc/broken.txt" => Ok("10.0.0.0/8\nnot a range\n".into()),
            _ => Err("no such file".into()),
        }
    }

    pub fn parse(text: &str) -> Result<Config, String> {
        Config::parse(text, &files)
    }

    #[test]
    fn every_setting() {
        let config = parse(
            "# the first site\n\
             [VW.Example.org]\n\
             upstream  = 127.0.0.1:3678\n\
             cert      = /certs/chain.pem\n\
             key       = /certs/key.pem   # comment\n\
             websocket = yes\n\
             allow     = /etc/ranges.txt 10.0.0.0/8\n\
             max-body  = 525M\n\
             \n\
             [plain.internal]\n\
             upstream = app:8080\n",
        )
        .unwrap();
        let site = config.site(b"vw.EXAMPLE.org").unwrap();
        assert_eq!(site.name, "vw.example.org");
        assert_eq!(site.upstream, "127.0.0.1:3678");
        assert_eq!(site.cert, Some(PathBuf::from("/certs/chain.pem")));
        assert!(site.websocket);
        assert_eq!(site.max_body, 525 << 20);
        assert!(site.allows("173.245.48.1".parse().unwrap()));
        assert!(site.allows("2400:cb00::1".parse().unwrap()));
        assert!(site.allows("10.1.1.1".parse().unwrap()));
        assert!(!site.allows("192.0.2.1".parse().unwrap()));
        let plain = config.site(b"plain.internal").unwrap();
        assert_eq!((plain.cert.clone(), plain.websocket, plain.max_body), (None, false, 1 << 20));
        assert!(plain.allows("192.0.2.1".parse().unwrap()));
        assert!(config.site(b"other.example.org").is_none());
    }

    #[test]
    fn configurations_like_the_examples() {
        let files = |_: &Path| Ok(String::from("173.245.48.0/20\n"));
        for text in [
            "[vault.example.org]\nupstream = 127.0.0.1:3678\ncert = /a\nkey = /b\nwebsocket = yes\nallow = /etc/shioko/cloudflare.txt\nmax-body = 525M\n",
            "[chat.example.org]\nupstream = 127.0.0.1:8787\ncert = /a\nkey = /b\nwebsocket = yes\n\n[files.example.net]\nupstream = 127.0.0.1:1443\ncert = /a\nkey = /b\nwebsocket = yes\n",
            "[media.example.org]\nupstream = 127.0.0.1:8096\ncert = /a\nkey = /b\nwebsocket = yes\n\n[wiki.internal]\nupstream = 10.0.0.5:8080\nallow = 10.0.0.0/8\n",
        ] {
            assert!(Config::parse(text, &files).is_ok(), "{text}");
        }
    }

    #[test]
    fn every_mistake_is_an_error_with_its_line() {
        for (text, message) in [
            ("upstream = a:1\n", "line 1: a setting before the first '[hostname]'"),
            ("[a]\nupstream = a:1\nnonsense\n", "line 3: expected '[hostname]' or 'key = value'"),
            ("[a]\nupstream = a:1\ncolour = red\n", "line 3: unknown setting 'colour'"),
            ("[a]\nupstream = a:1\nupstream = b:1\n", "line 3: 'upstream' is set twice"),
            ("[a]\nupstream = a:1\n\n[A]\nupstream = b:1\n", "line 4: site 'a' is defined twice"),
            ("[a b]\nupstream = a:1\n", "line 1: 'a b' is not a host name"),
            ("[]\n", "line 1: '' is not a host name"),
            ("[a]\nwebsocket = yes\n", "line 1: site 'a' has no upstream"),
            ("[a]\nupstream =\n", "line 2: 'upstream' has no value"),
            ("[a]\nupstream = nowhere\n", "line 2: 'nowhere' is not host:port"),
            ("[a]\nupstream = a:0\n", "line 2: 'a:0' is not host:port"),
            ("[a]\nupstream = a:70000\n", "line 2: 'a:70000' is not host:port"),
            ("[a]\nupstream = a b:80\n", "line 2: 'a b:80' is not host:port"),
            ("[a]\nupstream = 127.0.0.1:80\n", "line 2: upstream 127.0.0.1:80 is shioko itself"),
            ("[a]\nupstream = localhost:443\n", "line 2: upstream localhost:443 is shioko itself"),
            ("[a]\nupstream = [::1]:443\n", "line 2: upstream [::1]:443 is shioko itself"),
            ("[a]\nupstream = 0.0.0.0:80\n", "line 2: upstream 0.0.0.0:80 is shioko itself"),
            ("[a]\nupstream = a:1\ncert = /certs/chain.pem\n", "line 1: site 'a' needs both cert and key, or neither"),
            ("[a]\nupstream = a:1\nkey = /certs/key.pem\n", "line 1: site 'a' needs both cert and key, or neither"),
            ("[a]\nupstream = a:1\ncert = /missing\n", "line 3: cannot read /missing: no such file"),
            ("[a]\nupstream = a:1\nwebsocket = maybe\n", "line 3: websocket is 'yes' or 'no', not 'maybe'"),
            ("[a]\nupstream = a:1\nallow = 10.0.0.0/40\n", "line 3: '10.0.0.0/40' is not an address range"),
            ("[a]\nupstream = a:1\nallow = /missing\n", "line 3: cannot read /missing: no such file"),
            ("[a]\nupstream = a:1\nallow = /etc/broken.txt\n", "line 3: /etc/broken.txt line 2: 'not a range' is not an address range"),
            ("[a]\nupstream = a:1\nmax-body = lots\n", "line 3: 'lots' is not a size"),
            ("[a]\nupstream = a:1\nmax-body = 1T\n", "line 3: '1T' is not a size"),
            ("[a]\nupstream = a:1\nmax-body = 99999999999G\n", "line 3: '99999999999G' is not a size"),
        ] {
            assert_eq!(parse(text), Err(message.to_string()), "{text:?}");
        }
    }

    #[test]
    fn sizes() {
        assert_eq!(size("0"), Some(0));
        assert_eq!(size("1500"), Some(1500));
        assert_eq!(size("4K"), Some(4096));
        assert_eq!(size("1G"), Some(1 << 30));
        for bad in ["", "K", "1k", "1.5M", "-1", "1 M", "M1"] {
            assert_eq!(size(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn upstreams_that_are_fine() {
        for value in ["127.0.0.1:8080", "localhost:8096", "[::1]:8080", "app.internal:80", "10.0.0.5:443"] {
            assert_eq!(upstream(value), Ok(value.to_string()));
        }
    }
}
