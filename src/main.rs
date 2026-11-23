//! shioko: a minimal TLS-terminating reverse proxy.
//!
//! ```text
//! shioko run [config]     serve
//! shioko check [config]   check the configuration and exit
//! ```

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
use shioko::signals;
use shioko::config::Config;
use shioko::log::{self, Log};
use shioko::tls::conn::Identity;
use shioko::{crypto, server};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

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
    // SIGTERM and SIGINT stay pending in every thread, for the thread that
    // stops the server to take; this has to come before any thread starts.
    #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
    let graceful = signals::start().map_err(|why| {
        eprintln!("no graceful stop ({why}): SIGTERM and SIGINT end the server at once");
    });
    // Opened now, so that a missing device stops the start, not a handshake.
    if crypto::random(&mut [0u8; 32]).is_err() {
        eprintln!("cannot read /dev/urandom");
        return ExitCode::FAILURE;
    }
    let cap = server::cap_for(&std::fs::read_to_string("/proc/self/limits").unwrap_or_default());
    if cap < server::CONNECTIONS {
        log.error(&format!(
            "the open-file limit leaves room for {cap} connections in each pool, not {}: raise it to {} (LimitNOFILE=, ulimit -n)",
            server::CONNECTIONS,
            server::FILES_NEEDED
        ));
    }
    let server = server::Server::new(
        config, identities, PathBuf::from(ACME_DIRECTORY), Box::new(log), cap, server::PER_ADDRESS,
    );
    // On SIGTERM or SIGINT: let nobody in any more, cut the connections
    // that wait for a request and the tunnels, let the requests being
    // served finish (for up to DRAIN_TIMEOUT), and exit.
    #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
    if graceful.is_ok() {
        let stopping = std::sync::Arc::clone(&server);
        let stopper = std::thread::Builder::new().spawn(move || {
            let signal = match signals::wait() {
                Ok(signal) => signal,
                Err(why) => {
                    stopping.log.error(&format!("no graceful stop: {why}"));
                    // The signals reach this thread only: it must stay.
                    loop {
                        std::thread::park();
                    }
                }
            };
            stopping.log.error(&format!(
                "stopping on signal {signal}: letting nobody in, waiting up to {} s for the requests being served",
                server::DRAIN_TIMEOUT.as_secs()
            ));
            match stopping.drain(server::DRAIN_TIMEOUT) {
                0 => stopping.log.error("stopped"),
                left => stopping.log.error(&format!("stopped, cutting {left} connections")),
            }
            std::process::exit(0);
        });
        if stopper.is_err() {
            eprintln!("cannot start the thread that stops the server");
            return ExitCode::FAILURE;
        }
    }
    let watched = std::sync::Arc::clone(&server);
    if std::thread::Builder::new().spawn(move || server::watch(&watched)).is_err() {
        eprintln!("cannot start the certificate watcher");
        return ExitCode::FAILURE;
    }
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
