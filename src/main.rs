//! shioko: a minimal TLS-terminating reverse proxy.
//!
//! ```text
//! shioko run [config]     serve
//! shioko check [config]   check the configuration and exit
//! ```

#![cfg_attr(test, allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod config;
mod crypto;
mod http;
mod log;
mod net;
mod pem;
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
const ACME_DIRECTORY: &str = "/var/lib/shioko/acme";

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
    let server = server::Server::new(config, identities, PathBuf::from(ACME_DIRECTORY), Box::new(log), server::CONNECTIONS);
    let shared = std::sync::Arc::clone(&server);
    if std::thread::Builder::new().spawn(move || server::listen(&shared, &plain, false)).is_err() {
        eprintln!("cannot start the listener for port 80");
        return ExitCode::FAILURE;
    }
    server::listen(&server, &secure, true);
    ExitCode::SUCCESS
}
