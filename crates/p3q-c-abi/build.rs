// =============================================================================
// build.rs - cbindgen-driven C header generation for p3q-c-abi
// =============================================================================
//
// Generates `include/lux/p3q.h` next to the crate so consumers can copy
// it into their own `$LUXCPP_PREFIX/include/lux/` (or homebrew's
// `/opt/homebrew/include/lux/`) alongside `lux/crypto/metal_mlkem.h`.
//
// We do NOT write into `$OUT_DIR` because the header is consumed by
// non-Rust callers that don't know about cargo's output convention.
// The header is regenerated on every build so it stays in sync with
// `src/lib.rs` — never edit it by hand.
// =============================================================================

use std::env;
use std::path::PathBuf;

fn main() {
    // Re-run if src or cbindgen config changes.
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");

    let crate_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let out = PathBuf::from(&crate_dir)
        .join("include")
        .join("lux")
        .join("p3q.h");

    if let Err(e) = std::fs::create_dir_all(out.parent().unwrap()) {
        eprintln!("p3q-c-abi: could not create include dir: {e}");
        return;
    }

    let config = cbindgen::Config::from_file(PathBuf::from(&crate_dir).join("cbindgen.toml"))
        .unwrap_or_default();

    match cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        Ok(bindings) => {
            bindings.write_to_file(&out);
        }
        Err(e) => {
            // Don't fail the build on header-generation issues — the
            // .so / .dylib is the source of truth. Print so it's
            // visible in cargo's output.
            println!("cargo:warning=cbindgen failed: {e}");
        }
    }
}
