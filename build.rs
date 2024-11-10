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

fn parse_mac(env: &'static str) -> Vec<[u8; 6]> {
    println!("cargo::rerun-if-env-changed={}", env);
    match std::env::var(env) {
        Ok(env_str) => match {
            (|| {
                let mut macs = Vec::new();
                let mut i = 0;
                while i < env_str.len() {
                    let mac = [
                        u8::from_str_radix(&env_str[i + 0..i + 2], 16)?,
                        u8::from_str_radix(&env_str[i + 3..i + 5], 16)?,
                        u8::from_str_radix(&env_str[i + 6..i + 8], 16)?,
                        u8::from_str_radix(&env_str[i + 9..i + 11], 16)?,
                        u8::from_str_radix(&env_str[i + 12..i + 14], 16)?,
                        u8::from_str_radix(&env_str[i + 15..i + 17], 16)?,
                    ];
                    macs.push(mac);
                    i += 18; // skip 17 mac chars + 1 seperator char
                }
                Ok::<_, std::num::ParseIntError>(macs)
            })()
        } {
            Ok(s) => s,
            Err(e) => {
                println!("cargo::warning={:?} env var invalid: {e}", env);
                Vec::new()
            }
        },
        Err(VarError::NotPresent) => Vec::new(),
        Err(e) => {
            println!("cargo::warning={:?} env var invalid: {e}", env);
            Vec::new()
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
        const_declaration!(
            /// Deny listed macs (mostly for debugging) (don't connect to these)
            pub DENYLIST_MACS = parse_mac("DENYLIST_MACS").as_slice()
        ),
        const_declaration!(
            /// Unique per device id. In the range `1..=128`.
            // The range is entirely so the ip can reuse the uuid since we have less nodes than this anyway.
            UUID = {
                let out = parse_option_env::<u8>("UUID").expect("UUID env var should be set to value in [1,128]");
                if (1..=128).contains(&out) { out } else { panic!("UUID not in 1..=128") }
            }
        ),
    ]
    .join("\n");

    fs::write(dest_path, const_declarations).unwrap();
}
