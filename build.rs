// See <https://doc.rust-lang.org/cargo/reference/build-scripts.html> to explain what this file is.

use const_gen::{const_declaration, CompileConst};
use std::{env, fs, path::Path};

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-env-changed=RNG_SEED");

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("const_gen.rs");

    let const_declarations = match std::env::var("RNG_SEED") {
        Ok(env_str) => match env_str.parse::<u64>() {
            Ok(n) => const_declaration!(
                /// RNG seed set at build time.
                pub RNG_SEED = n
            ),
            Err(e) => panic!("invalid env var `RNG_SEED` = '{env_str}': {e}"),
        },
        Err(e) => {
            println!("cargo:warning=`RNG_SEED` env var invalid; using fallback: {e}");
            const_declaration!(
                /// # WARNING
                /// **`RNG_SEED` env var unset or invalid; using fallback**
                ///
                /// RNG seed set at build time.
                pub RNG_SEED = 1234u64
            )
        }
    };

    fs::write(dest_path, const_declarations).unwrap();
}
