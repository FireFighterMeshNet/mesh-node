// See <https://doc.rust-lang.org/cargo/reference/build-scripts.html> to explain what this file is.

use const_gen::{const_declaration, CompileConst};
use std::{
    env::{self, VarError},
    fs,
    path::Path,
};

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-env-changed=RNG_SEED");

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("const_gen.rs");

    let default_rng_seed = const_declaration!(
        /// RNG seed set at build time.
        pub RNG_SEED = None::<u64>
    );
    let const_declarations = match std::env::var("RNG_SEED") {
        Ok(env_str) => match env_str.parse::<u64>() {
            Ok(n) => const_declaration!(
                /// RNG seed set at build time.
                pub RNG_SEED = Some(n)
            ),
            Err(e) => {
                println!("cargo:warning=`RNG_SEED` env var invalid: {e}");
                default_rng_seed
            }
        },
        Err(VarError::NotPresent) => default_rng_seed,
        Err(e) => {
            println!("cargo:warning=`RNG_SEED` env var invalid: {e}");
            default_rng_seed
        }
    };

    fs::write(dest_path, const_declarations).unwrap();
}
