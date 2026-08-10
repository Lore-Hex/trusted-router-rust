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
