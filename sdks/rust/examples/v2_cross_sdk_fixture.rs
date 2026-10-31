//! Write the Rust cross-SDK fixture (SPEC-v2 §8.1):
//!
//! ```text
//! cargo run --example v2_cross_sdk_fixture [-- -out PATH]
//! ```
//!
//! The default output is `testvectors/v2/cross-sdk/rust.json`. Every run uses
//! fresh random keys and hedged ML-DSA-65 signatures; the fixture is verified
//! before it is written.

use std::path::PathBuf;
use std::process::ExitCode;

use ratify_protocol::v2::generate_cross_sdk_fixture_v2;

fn main() -> ExitCode {
    let mut out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testvectors/v2/cross-sdk/rust.json");
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match (arg.as_str(), args.next()) {
            ("-out" | "--out", Some(path)) => out = PathBuf::from(path),
            _ => {
                eprintln!("usage: v2_cross_sdk_fixture [-out PATH]");
                return ExitCode::from(2);
            }
        }
    }
    let generator = "cargo run --example v2_cross_sdk_fixture (Rust SDK, crate ratify-protocol)";
    let fixture = match generate_cross_sdk_fixture_v2("rust", env!("CARGO_PKG_VERSION"), generator) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("generate: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = std::fs::write(&out, fixture) {
        eprintln!("write {}: {e}", out.display());
        return ExitCode::FAILURE;
    }
    println!("wrote {}", out.display());
    ExitCode::SUCCESS
}
