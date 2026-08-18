//! L2 — plane router: the ordered candidate set for one logical call.
//!
//! The candidate list is built ONCE per logical call and its length is the
//! structural failover gate: the control plane and pinned clients resolve to
//! exactly one candidate, so the engine has nowhere to advance to — list
//! length is the gate, not a second flag
//! (`regional_failover_false_pins_the_client_to_one_host`,
//! `a_custom_base_url_is_never_redirected_to_a_public_alias` in
//! `tests/alias_failover.rs`).

use crate::client::{Client, Plane};
use crate::constants::{ALIAS_API_BASE_URLS, DEFAULT_API_BASE_URL};
use crate::{Error, Result};
use url::Url;

impl Client {
    /// Every candidate URL for a plane, in preference order.
    ///
    /// Inference walks the alias domains; the control plane keeps its single
    /// endpoint, because those calls are not what a domain outage strands.
    pub(crate) fn plane_urls(&self, plane: Plane, path: &str) -> Result<Vec<Url>> {
        match plane {
            Plane::Control => Ok(vec![self.relative_url(plane, path)?]),
            Plane::Inference => {
                let trimmed = path.trim_start_matches('/');
                if !path.starts_with('/') || path.starts_with("//") || path.contains('\\') {
                    return Err(Error::InvalidConfiguration(
                        "API path must be a root-relative path".to_owned(),
                    ));
                }
                let mut out = Vec::with_capacity(self.api_base_urls.len());
                for base in &self.api_base_urls {
                    out.push(
                        base.join(trimmed)
                            .map_err(|error| Error::InvalidConfiguration(error.to_string()))?,
                    );
                }
                Ok(out)
            }
        }
    }

    fn relative_url(&self, plane: Plane, path: &str) -> Result<Url> {
        if !path.starts_with('/') || path.starts_with("//") || path.contains('\\') {
            return Err(Error::InvalidConfiguration(
                "API path must be a root-relative path".to_owned(),
            ));
        }
        let base = match plane {
            Plane::Inference => &self.api_base_url,
            Plane::Control => &self.control_base_url,
        };
        base.join(path.trim_start_matches('/'))
            .map_err(|error| Error::InvalidConfiguration(error.to_string()))
    }
}

/// Parses and normalises a configured base URL (trailing slash appended so
/// `join` resolves against the full base path).
pub(crate) fn parse_base_url(value: &str, name: &str) -> Result<Url> {
    let mut url = Url::parse(value).map_err(|error| {
        Error::InvalidConfiguration(format!("invalid {name} base URL: {error}"))
    })?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(Error::InvalidConfiguration(format!(
            "{name} base URL must be an HTTP(S) origin"
        )));
    }
    if !url.path().ends_with('/') {
        url.set_path(&format!("{}/", url.path()));
    }
    Ok(url)
}

/// Builds the inference candidate list: primary first, then the alias domains.
///
/// Aliases are added ONLY for the default host. A caller who configured their
/// own base URL — a private deployment, a test server, a regional pin — gets
/// exactly that; silently redirecting their traffic to a public alias would be
/// worse than failing.
pub(crate) fn inference_base_urls(primary: &Url) -> Vec<Url> {
    // Compare through parse_base_url, not the raw constant: the builder
    // normalises a trailing slash onto the base so `join` resolves correctly,
    // so the parsed default and the stored primary differ textually even when
    // they are the same endpoint.
    let default = parse_base_url(DEFAULT_API_BASE_URL, "inference").ok();
    if default.as_ref() != Some(primary) {
        return vec![primary.clone()];
    }
    let mut out = vec![primary.clone()];
    for alias in ALIAS_API_BASE_URLS {
        if let Ok(url) = parse_base_url(alias, "inference") {
            out.push(url);
        }
    }
    out
}

/// Folds an already-resolved URL path to the semantic route the gateway sees:
/// ASCII percent escapes decoded, ASCII case folded, repeated separators
/// collapsed, and a trailing separator dropped.
///
/// This is deliberately the single route classifier shared by telemetry and
/// strict prompt-stream validation. Both callers first resolve through
/// [`Url`], so dot segments are handled by the same URL machinery that builds
/// the wire request rather than by a second, divergent path normalizer.
pub(crate) fn semantic_route(path: &str) -> String {
    let decoded = percent_decode_ascii(path);
    let mut route = String::with_capacity(decoded.len());
    for character in decoded.chars() {
        let character = character.to_ascii_lowercase();
        if character == '/' && route.ends_with('/') {
            continue;
        }
        route.push(character);
    }
    while route.len() > 1 && route.ends_with('/') {
        route.pop();
    }
    route
}

/// Resolves a caller-supplied root-relative path independently of any
/// configured API base, then returns its exact semantic logical route.
///
/// A dummy root deliberately makes `/x/../chat/completions` and percent-
/// encoded ASCII spellings comparable to `/chat/completions` without letting
/// an unrelated suffix such as `/custom/chat/completions` collapse to it.
pub(crate) fn semantic_request_route(path: &str) -> String {
    let Ok(root) = Url::parse("https://sdk.invalid/") else {
        return semantic_route(path);
    };
    let Ok(resolved) = root.join(path.trim_start_matches('/')) else {
        return semantic_route(path);
    };
    semantic_route(resolved.path())
}

/// Returns a response's exact semantic route relative to a configured base
/// when both URLs have the same origin and the response remains at or below
/// the base path. A component boundary is required, so `/v10` is not treated
/// as relative to `/v1`.
pub(crate) fn semantic_route_relative_to_base(base: &Url, response: &Url) -> Option<String> {
    if base.origin() != response.origin() {
        return None;
    }
    let base_path = semantic_route(base.path());
    let response_path = semantic_route(response.path());
    if base_path == "/" {
        return Some(response_path);
    }
    if response_path == base_path {
        return Some("/".to_owned());
    }
    let prefix = format!("{base_path}/");
    response_path
        .strip_prefix(&prefix)
        .map(|relative| format!("/{relative}"))
}

/// Decodes `%XX` escapes for semantic comparison only. Malformed escapes stay
/// literal, and decoded non-ASCII bytes cannot match an ASCII SDK route.
fn percent_decode_ascii(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' && index + 2 < bytes.len() {
            let high = char::from(bytes[index + 1]).to_digit(16);
            let low = char::from(bytes[index + 2]).to_digit(16);
            if let (Some(high), Some(low)) = (high, low) {
                out.push(char::from_u32(high * 16 + low).unwrap_or(char::REPLACEMENT_CHARACTER));
                index += 3;
                continue;
            }
        }
        out.push(char::from(byte));
        index += 1;
    }
    out
}

#[cfg(test)]
mod semantic_route_tests {
    use super::{semantic_request_route, semantic_route_relative_to_base};
    use url::Url;

    #[test]
    fn intended_routes_are_exact_after_url_and_ascii_normalisation() {
        for spelling in [
            "/chat/completions",
            "/x/../chat/completions",
            "/chat/%63ompletions",
            "/CHAT//COMPLETIONS/",
        ] {
            assert_eq!(
                semantic_request_route(spelling),
                "/chat/completions",
                "spelling {spelling}"
            );
        }
        assert_eq!(
            semantic_request_route("/custom/chat/completions"),
            "/custom/chat/completions"
        );
    }

    #[test]
    fn response_routes_are_exact_relative_to_matching_custom_bases() {
        let base = Url::parse("https://api.example/tenant/v2/").unwrap();
        let canonical = Url::parse("https://api.example/tenant/v2/chat/completions").unwrap();
        assert_eq!(
            semantic_route_relative_to_base(&base, &canonical).as_deref(),
            Some("/chat/completions")
        );

        let custom = Url::parse("https://api.example/tenant/v2/custom/chat/completions").unwrap();
        assert_eq!(
            semantic_route_relative_to_base(&base, &custom).as_deref(),
            Some("/custom/chat/completions")
        );

        let prefix_collision =
            Url::parse("https://api.example/tenant/v20/chat/completions").unwrap();
        assert!(semantic_route_relative_to_base(&base, &prefix_collision).is_none());
        let cross_origin = Url::parse("https://other.example/tenant/v2/chat/completions").unwrap();
        assert!(semantic_route_relative_to_base(&base, &cross_origin).is_none());
    }
}
