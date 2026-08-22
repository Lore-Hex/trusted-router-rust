//! Captures the compiler release for the content-free SDK identity that
//! rides every telemetry beacon (client telemetry contract v1 §5.1,
//! `sdk.runtime`). The value is a closed-grammar version string, nothing
//! else, and a failure to read it never fails the build: the identity falls
//! back to `rustc/unknown`.

use std::env;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=RUSTC");
    println!("cargo:rerun-if-changed=build.rs");
    let release = env::var("RUSTC")
        .ok()
        .and_then(|rustc| Command::new(rustc).arg("-vV").output().ok())
        .filter(|output| output.status.success())
        .and_then(|output| {
            String::from_utf8(output.stdout).ok().and_then(|text| {
                text.lines()
                    .find_map(|line| line.strip_prefix("release: "))
                    .map(|value| value.trim().to_owned())
            })
        })
        .unwrap_or_default();
    println!("cargo:rustc-env=TRUSTED_ROUTER_RUSTC_RELEASE={release}");
}
