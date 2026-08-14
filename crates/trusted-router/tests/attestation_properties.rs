//! Property tests for the attestation policy boundary.
//!
//! The law is a soundness statement about verification:
//!
//! ```text
//! for every claims set K and policy P,
//!     verification succeeds  =>  K's image identity was in P's accepted set
//! ```
//!
//! Before the non-vacuity guard this was false, and falsifiably so. Both image
//! checks go through `require_one_of`:
//!
//! ```ignore
//! if !expected.is_empty() && !expected.iter().any(|v| safe_eq(actual, v)) { Err }
//! ```
//!
//! An EMPTY accepted set makes the whole condition false and the function
//! returns `Ok(())` — the check is skipped, not failed. And
//! `policy_from_trust_release` mapped a release with no image fields to exactly
//! that empty set: a truncated body, an error page that parsed as JSON, or a
//! schema change produced a policy under which both checks silently no-op.
//! Verification then succeeded against any genuinely-attested Confidential
//! Space workload while reporting success.
//!
//! `policy_from_trust_release` had no test coverage at all before this file,
//! which is how the shape survived.
//!
//! This crate ships a deliberately small dependency set and a committed
//! `Cargo.lock`, so rather than add proptest these tests drive a seeded
//! generator. The seed is fixed, so a failure reproduces exactly; raise `RUNS`
//! locally to search harder.
//!
//! Mirrors `tests/test_attestation_properties.py` in trusted-router-py and
//! `test/attestation-properties.test.js` in trusted-router-js.

use trusted_router::{policy_from_trust_release, AttestationPolicy, TrustRelease};

const RUNS: usize = 2_000;

/// mulberry32, so failures are reproducible without a dependency.
struct Rng(u32);

impl Rng {
    fn next_u32(&mut self) -> u32 {
        self.0 = self.0.wrapping_add(0x6d2b_79f5);
        let mut t = self.0;
        t = (t ^ (t >> 15)).wrapping_mul(t | 1);
        t ^= t.wrapping_add((t ^ (t >> 7)).wrapping_mul(t | 0x3d));
        t ^ (t >> 14)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next_u32() as usize) % n
    }

    fn bool(&mut self) -> bool {
        (self.next_u32() as usize).is_multiple_of(2)
    }
}

/// The shapes a degraded HTTP response actually takes: absent fields, empty
/// strings, empty lists, and lists whose only entries are empty.
fn maybe_string(rng: &mut Rng) -> String {
    match rng.below(4) {
        1 => "sha256:abc123".to_owned(),
        2 => "registry.example/img:tag".to_owned(),
        // 0 and 3 are the absent/empty cases, which is what a degraded
        // response most often produces.
        _ => String::new(),
    }
}

fn maybe_list(rng: &mut Rng) -> Vec<String> {
    match rng.below(4) {
        1 => vec![String::new()],
        2 => vec!["sha256:published".to_owned()],
        _ => Vec::new(),
    }
}

fn release(rng: &mut Rng) -> TrustRelease {
    TrustRelease {
        image_digest: maybe_string(rng),
        accepted_image_digests: maybe_list(rng),
        image_reference: maybe_string(rng),
        accepted_image_references: maybe_list(rng),
        ..Default::default()
    }
}

// ---------------------------------------------------------- non-vacuity ---

#[test]
fn policy_from_release_is_never_vacuous() {
    let mut rng = Rng(0x5eed);
    for _ in 0..RUNS {
        let release = release(&mut rng);
        match policy_from_trust_release(&release, None) {
            Ok(policy) => assert!(
                policy.pins_image_identity(),
                "built an unpinned policy from {release:?}"
            ),
            Err(error) => assert!(
                error.to_string().contains("pins no image identity"),
                "unexpected error for {release:?}: {error}"
            ),
        }
    }
}

#[test]
fn empty_release_is_refused() {
    let error = policy_from_trust_release(&TrustRelease::default(), None)
        .expect_err("an empty trust release must be refused");
    assert!(
        error.to_string().contains("pins no image identity"),
        "{error}"
    );
}

#[test]
fn release_whose_lists_hold_only_empty_strings_is_refused() {
    // The published-list branch is taken when the list is non-empty, so a list
    // of empty strings is a distinct path from an absent list.
    let release = TrustRelease {
        accepted_image_digests: vec![String::new()],
        accepted_image_references: vec![String::new()],
        ..Default::default()
    };
    match policy_from_trust_release(&release, None) {
        Ok(policy) => assert!(
            policy.pins_image_identity(),
            "accepted a policy whose only pins are empty strings"
        ),
        Err(error) => assert!(
            error.to_string().contains("pins no image identity"),
            "{error}"
        ),
    }
}

#[test]
fn a_release_with_only_one_identity_kind_is_accepted() {
    // Non-vacuity requires one of the two, not both.
    let release = TrustRelease {
        image_digest: "sha256:beef".to_owned(),
        ..Default::default()
    };
    let policy = policy_from_trust_release(&release, None).expect("digest-only release is usable");
    assert!(policy.pins_image_identity());
    assert_eq!(
        policy.expected_image_digests,
        vec!["sha256:beef".to_owned()]
    );
    assert!(policy.expected_image_references.is_empty());
}

#[test]
fn default_policy_pins_nothing() {
    // The state verification must refuse. Pinned explicitly so a future change
    // to Default cannot quietly make an unpinned policy look acceptable.
    assert!(!AttestationPolicy::default().pins_image_identity());
}

#[test]
fn a_cert_only_policy_pins_nothing() {
    let policy = AttestationPolicy {
        expected_cert_sha256: Some("a".repeat(64)),
        ..Default::default()
    };
    assert!(
        !policy.pins_image_identity(),
        "pinning the TLS cert alone says nothing about which build answered"
    );
}

// --------------------------- the guard agrees with what it guards ---------

#[test]
fn pins_image_identity_agrees_with_the_checks_it_guards() {
    let mut rng = Rng(0x1234);
    for _ in 0..RUNS {
        let policy = AttestationPolicy {
            expected_image_digest: rng.bool().then(|| "d".to_owned()),
            expected_image_digests: if rng.bool() {
                vec!["ds".to_owned()]
            } else {
                Vec::new()
            },
            expected_image_reference: rng.bool().then(|| "r".to_owned()),
            expected_image_references: if rng.bool() {
                vec!["rs".to_owned()]
            } else {
                Vec::new()
            },
            ..Default::default()
        };

        // Mirrors the two conditions that build the accepted sets in
        // verify_gateway_attestation. If the guard and the checks ever drift
        // apart, the hole reopens silently.
        let digest_check_runs =
            !policy.expected_image_digests.is_empty() || policy.expected_image_digest.is_some();
        let reference_check_runs = !policy.expected_image_references.is_empty()
            || policy.expected_image_reference.is_some();

        assert_eq!(
            policy.pins_image_identity(),
            digest_check_runs || reference_check_runs,
            "guard disagrees with the checks it guards for {policy:?}"
        );
    }
}
