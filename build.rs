// See <https://doc.rust-lang.org/cargo/reference/build-scripts.html> to explain what this file is.

use const_gen::{const_declaration, CompileConst};
use std::{
    env::{self, VarError},
    fs,
    path::Path,
    str::FromStr,
};

/// Like [`option_env!`] but tries to parse the environment variable as `T`.
fn parse_option_env<T>(env: &'static str) -> Option<T>
where
    T: FromStr,
    <T as FromStr>::Err: std::fmt::Display,
{
    println!("cargo::rerun-if-env-changed={}", env);
    match std::env::var(env) {
        Ok(env_str) => match env_str.parse() {
            Ok(s) => Some(s),
            Err(e) => {
                println!("cargo::warning={:?} env var invalid: {e}", env);
                None
            }
        },
        Err(VarError::NotPresent) => None,
        Err(e) => {
            println!("cargo::warning={:?} env var invalid: {e}", env);
            None
        }
    }
}

fn main() {
    println!("cargo::rerun-if-changed=build.rs");

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("const_gen.rs");

    let const_declarations = [
        const_declaration!(
            /// RNG seed set at build time.
            pub RNG_SEED = parse_option_env::<u64>("RNG_SEED")
        ),
        const_declaration!(
            /// Hardcoded tree level. This is `0` for the Root.
            pub TREE_LEVEL = parse_option_env::<u8>("TREE_LEVEL")
        ),
    ]
    .join("\n");

    fs::write(dest_path, const_declarations).unwrap();
}
