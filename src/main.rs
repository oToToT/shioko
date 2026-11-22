//! shioko: a minimal TLS-terminating reverse proxy.
//!
//! ```text
//! shioko run [config]     serve
//! shioko check [config]   check the configuration and exit
//! ```

#![cfg_attr(test, allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic))]

/// Records a step of spec/Server.tla in `--features record` builds; in
/// other builds it is nothing at all.
macro_rules! record {
    ($($what:tt)*) => {
        #[cfg(feature = "record")]
        crate::record::step(&format!($($what)*));
    };
}

mod config;
mod crypto;
mod http;
mod log;
mod net;
mod pem;
#[cfg(feature = "record")]
mod record;
mod server;
mod stream;
mod tls;

use config::Config;
use log::Log;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use tls::conn::Identity;

const DEFAULT_CONFIG: &str = "/etc/shioko/shioko.conf";
/// Where `certbot --webroot -w /var/lib/shioko/acme` puts its tokens.
const ACME_DIRECTORY: &str = "/var/lib/shioko/acme/.well-known/acme-challenge";

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let mut words = arguments.iter().map(String::as_str);
    let (command, path) = (words.next(), words.next().unwrap_or(DEFAULT_CONFIG));
    if !matches!((command, words.next()), (Some("run" | "check"), None)) {
        eprintln!("usage: shioko run [config]\n       shioko check [config]");
        return ExitCode::from(2);
    }
    let loaded = Config::load(Path::new(path)).and_then(|config| {
        // Every site with a certificate has a key that goes with it.
        let identities = config.sites.iter().map(|site| match (&site.cert, &site.key) {
            (Some(cert), Some(key)) => Identity::load(cert, key)
                .map(Some)
                .map_err(|message| format!("{path}: site '{}': {message}", site.name)),
            _ => Ok(None),
        });
        Ok((identities.collect::<Result<Vec<_>, _>>()?, config))
    });
    let Ok((identities, config)) = loaded.map_err(|message| eprintln!("{message}")) else {
        return ExitCode::FAILURE;
    };
    if command == Some("check") {
        println!("{path}: {} sites, no problems found", config.sites.len());
        return ExitCode::SUCCESS;
    }

    // Ports 80 and 443 on every address, IPv4 and IPv6.
    let bind = |port: u16| {
        TcpListener::bind(("::", port)).map_err(|error| eprintln!("cannot listen on port {port}: {error}"))
    };
    let (Ok(plain), Ok(secure)) = (bind(80), bind(443)) else { return ExitCode::FAILURE };
    let log = log::Standard;
    let tls_sites = identities.iter().flatten().count();
    log.error(&format!("serving {} sites on port 80, {tls_sites} of them on port 443", config.sites.len()));
    // Opened now, so that a missing device stops the start, not a handshake.
    if crypto::random(&mut [0u8; 32]).is_err() {
        eprintln!("cannot read /dev/urandom");
        return ExitCode::FAILURE;
    }
    let cap = server::cap_for(&std::fs::read_to_string("/proc/self/limits").unwrap_or_default());
    if cap < server::CONNECTIONS {
        log.error(&format!(
            "the open-file limit leaves room for {cap} connections, not {}: raise it to {} (LimitNOFILE=, ulimit -n)",
            server::CONNECTIONS,
            2 * server::CONNECTIONS + server::RESERVED_FILES
        ));
    }
    let server = server::Server::new(config, identities, PathBuf::from(ACME_DIRECTORY), Box::new(log), cap);
    let shared = std::sync::Arc::clone(&server);
    if std::thread::Builder::new().spawn(move || server::listen(&shared, &plain, false)).is_err() {
        eprintln!("cannot start the listener for port 80");
        return ExitCode::FAILURE;
    }
    server::listen(&server, &secure, true);
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    /// Bug (found by the end-to-end run, ci/e2e): tokens were read from
    /// /var/lib/shioko/acme/<token>, but `certbot --webroot -w
    /// /var/lib/shioko/acme` writes them under .well-known/acme-challenge/
    /// there, so no certificate could have been renewed. The end-to-end
    /// checks have certbot get one through shioko.
    #[test]
    fn bug_acme_tokens_were_not_where_certbot_writes_them() {
        assert_eq!(super::ACME_DIRECTORY, "/var/lib/shioko/acme/.well-known/acme-challenge");
    }
}
