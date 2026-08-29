//! HTTP retrieval for hosts that have a network.
//!
//! One request per call, with no redirect following and no state carried between calls. The
//! compiler decides what to request next: it resolves a redirect's location, checks the host it
//! names against `remote.allowHosts`, and spends the redirect budget before asking for it. That
//! division is what keeps the allowlist a boundary rather than a suggestion, and it is why this
//! crate has no policy of its own beyond the deadline and the size cap it is handed.
//!
//! Nothing here is linked into the compiler core, which is what lets the same core compile to
//! WebAssembly as a module that declares no imports at all.

use std::sync::Arc;
use std::time::Duration;

use oasts_core::source::{FetchPolicy, FetchStep, FetcherHandle, RemoteFetcher};
use ureq::Agent;
use ureq::http::StatusCode;

/// Redirect status codes carry a `Location`; nothing else in the `3xx` range has to.
const LOCATION: &str = "location";

/// Retrieval over HTTP, with TLS verified against the Mozilla root program.
///
/// Verification is not configurable. A compiler that could be told to trust anything would make
/// `remote.integrity` the only thing standing between a document and the code generated from it,
/// and a digest recorded from a first fetch cannot vouch for that fetch.
#[derive(Clone, Copy, Debug, Default)]
pub struct HttpFetcher;

/// The handle a host with a network seats on the compiler.
#[must_use]
pub fn handle() -> FetcherHandle {
    FetcherHandle::from(Arc::new(HttpFetcher) as Arc<dyn RemoteFetcher>)
}

impl RemoteFetcher for HttpFetcher {
    fn fetch_once(&self, url: &str, policy: &FetchPolicy) -> Result<FetchStep, String> {
        let agent: Agent = Agent::config_builder()
            // The compiler follows redirects itself, one authorized hop at a time.
            .max_redirects(0)
            // A `404` is an answer about the document, reported as one rather than as a transport
            // failure, so the diagnostic says what the server said.
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_millis(policy.timeout_ms)))
            .build()
            .into();

        let mut response = agent
            .get(url)
            .call()
            .map_err(|error| format!("the request failed: {error}"))?;

        let status = response.status();
        if status.is_redirection() {
            let location = response
                .headers()
                .get(LOCATION)
                .ok_or_else(|| format!("the server answered {status} with no Location header"))?;
            return location
                .to_str()
                .map(|location| FetchStep::Redirect(location.to_owned()))
                .map_err(|error| format!("the Location header is not text: {error}"));
        }
        if status != StatusCode::OK {
            return Err(format!("the server answered {status}"));
        }
        response
            .body_mut()
            .with_config()
            .limit(policy.max_bytes)
            .read_to_vec()
            .map(FetchStep::Body)
            .map_err(|error| format!("the response body could not be read: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    use super::*;

    /// A loopback HTTP/1.1 server that answers every connection with one fixed response.
    ///
    /// Hand-rolled rather than borrowed: the tests need to answer things a server library will not
    /// produce — a redirect with no `Location`, a header value that is not text — and they must
    /// never reach a network. `127.0.0.1:0` also puts every test on an ephemeral port, which is
    /// what proves the allowlist matches on the host and admits any port on it.
    fn serving(response: &'static [u8], connections: usize) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("an ephemeral loopback port");
        let address = listener.local_addr().expect("the bound address");
        let server = thread::spawn(move || {
            for _ in 0..connections {
                let (mut stream, _) = listener.accept().expect("a client connects");
                drain_request(&mut stream);
                let _ = stream.write_all(response);
            }
        });
        // Handed back so every test joins its server: a thread still running at process exit has
        // not flushed its coverage counters, which is what makes a 100% line gate flap.
        (format!("http://{address}/openapi.yaml"), server)
    }

    /// Reads the request head so the client is not answered before it has finished asking.
    fn drain_request(stream: &mut TcpStream) {
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
            head.push(byte[0]);
        }
    }

    fn policy(max_bytes: u64) -> FetchPolicy {
        FetchPolicy {
            timeout_ms: 5_000,
            max_bytes,
        }
    }

    #[test]
    fn a_two_hundred_answers_with_the_body() {
        let (url, server) = serving(
            b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\nopenapi: 3.1.1\n",
            1,
        );

        assert_eq!(
            HttpFetcher.fetch_once(&url, &policy(1 << 20)),
            Ok(FetchStep::Body(b"openapi: 3.1.1\n".to_vec()))
        );
        server.join().expect("the server thread finishes");
    }

    #[test]
    fn a_redirect_is_reported_rather_than_followed() {
        let (url, server) = serving(
            b"HTTP/1.1 302 Found\r\nLocation: /moved.yaml\r\nContent-Length: 0\r\n\r\n",
            1,
        );

        assert_eq!(
            HttpFetcher.fetch_once(&url, &policy(1 << 20)),
            Ok(FetchStep::Redirect("/moved.yaml".to_owned()))
        );
        server.join().expect("the server thread finishes");
    }

    #[test]
    fn a_redirect_with_no_location_is_a_failure_naming_the_status() {
        let (url, server) = serving(b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n", 1);

        let error = HttpFetcher
            .fetch_once(&url, &policy(1 << 20))
            .expect_err("a redirect with nowhere to go");

        assert!(error.contains("302"), "{error}");
        assert!(error.contains("no Location header"), "{error}");
        server.join().expect("the server thread finishes");
    }

    #[test]
    fn a_location_that_is_not_text_is_reported() {
        let (url, server) = serving(
            b"HTTP/1.1 302 Found\r\nLocation: \xff\xfe\r\nContent-Length: 0\r\n\r\n",
            1,
        );

        let error = HttpFetcher
            .fetch_once(&url, &policy(1 << 20))
            .expect_err("a Location that is not text");

        assert!(error.contains("Location header is not text"), "{error}");
        server.join().expect("the server thread finishes");
    }

    #[test]
    fn a_status_that_is_not_two_hundred_is_reported_as_the_server_wrote_it() {
        let (url, server) = serving(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", 1);

        let error = HttpFetcher
            .fetch_once(&url, &policy(1 << 20))
            .expect_err("a document that is not there");

        assert!(error.contains("404"), "{error}");
        server.join().expect("the server thread finishes");
    }

    #[test]
    fn a_body_over_the_cap_is_abandoned() {
        let (url, server) = serving(
            b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\nopenapi: 3.1.1\n",
            1,
        );

        let error = HttpFetcher
            .fetch_once(&url, &policy(4))
            .expect_err("a body larger than the cap");

        assert!(error.contains("body could not be read"), "{error}");
        server.join().expect("the server thread finishes");
    }

    #[test]
    fn a_refused_connection_is_reported_as_a_failed_request() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("an ephemeral loopback port");
        let address = listener.local_addr().expect("the bound address");
        drop(listener);

        let error = HttpFetcher
            .fetch_once(&format!("http://{address}/openapi.yaml"), &policy(1 << 20))
            .expect_err("nothing is listening");

        assert!(error.contains("the request failed"), "{error}");
    }

    #[test]
    fn a_server_that_never_answers_hits_the_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("an ephemeral loopback port");
        let address = listener.local_addr().expect("the bound address");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("a client connects");
            // Held open, unanswered, until the process exits.
            std::mem::forget(stream);
        });

        let error = HttpFetcher
            .fetch_once(
                &format!("http://{address}/openapi.yaml"),
                &FetchPolicy {
                    timeout_ms: 250,
                    max_bytes: 1 << 20,
                },
            )
            .expect_err("a server that never answers");

        assert!(error.contains("the request failed"), "{error}");
        server.join().expect("the server thread finishes");
    }

    #[test]
    fn the_handle_seats_a_retriever() {
        let handle = handle();

        assert!(handle.get().is_some());
    }
}
