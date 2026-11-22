//! shioko: a minimal TLS-terminating reverse proxy.
//!
//! ```text
//! shioko run [config]     serve
//! shioko check [config]   check the configuration and exit
//! ```

#![cfg_attr(
    test,
    allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

mod config;
// Nothing uses the crypto module yet; the TLS code arrives in a later milestone.
#[allow(dead_code)]
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

const DEFAULT_CONFIG: &str = "/etc/shioko/shioko.conf";
const ACME_DIRECTORY: &str = "/var/lib/shioko/acme";

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let mut words = arguments.iter().map(String::as_str);
    let (command, path) = (words.next(), words.next().unwrap_or(DEFAULT_CONFIG));
    let config = match (command, words.next()) {
        (Some("run" | "check"), None) => Config::load(Path::new(path)),
        _ => {
            eprintln!("usage: shioko run [config]\n       shioko check [config]");
            return ExitCode::from(2);
        }
    };
    let config = match config {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::FAILURE;
        }
    };
    // Every site with a certificate has a key that goes with it.
    let mut identities = Vec::with_capacity(config.sites.len());
    for site in &config.sites {
        let identity = match (&site.cert, &site.key) {
            (Some(cert), Some(key)) => match tls::conn::Identity::load(cert, key) {
                Ok(identity) => Some(identity),
                Err(message) => {
                    eprintln!("{path}: site '{}': {message}", site.name);
                    return ExitCode::FAILURE;
                }
            },
            _ => None,
        };
        identities.push(identity);
    }
    if command == Some("check") {
        println!("{path}: {} sites, no problems found", config.sites.len());
        return ExitCode::SUCCESS;
    }

    // Ports 80 and 443 on every address, IPv4 and IPv6.
    let bind = |port: u16| {
        TcpListener::bind(("::", port)).map_err(|error| eprintln!("cannot listen on port {port}: {error}"))
    };
    let (Ok(plain), Ok(secure)) = (bind(80), bind(443)) else {
        return ExitCode::FAILURE;
    };
    let log = log::Standard;
    let tls_sites = identities.iter().filter(|i| i.is_some()).count();
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
