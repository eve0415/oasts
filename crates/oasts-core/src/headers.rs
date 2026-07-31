/// Whether Fetch forbids script-controlled requests from setting this header name.
pub(crate) fn forbidden_request_header_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("proxy-")
        || lower.starts_with("sec-")
        || matches!(
            lower.as_str(),
            "accept-charset"
                | "accept-encoding"
                | "access-control-request-headers"
                | "access-control-request-method"
                | "connection"
                | "content-length"
                | "cookie"
                | "cookie2"
                | "date"
                | "dnt"
                | "expect"
                | "host"
                | "keep-alive"
                | "origin"
                | "referer"
                | "set-cookie"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
                | "via"
        )
}
