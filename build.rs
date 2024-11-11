// See <https://doc.rust-lang.org/cargo/reference/build-scripts.html> to explain what this file is.

use const_gen::{const_declaration, CompileConst};
use std::{
    collections::HashMap,
    env::{self, VarError},
    fs,
    num::ParseIntError,
    path::Path,
    str::FromStr,
};

type MACAddress = [u8; 6];

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

/// Parse a single colon seperated mac like `12:34:56:78:9a:bc`.
fn parse_mac(s: &str) -> Result<(&str, MACAddress), ParseIntError> {
    Ok((
        &s[17..],
        [
            u8::from_str_radix(&s[0..2], 16)?,
            u8::from_str_radix(&s[3..5], 16)?,
            u8::from_str_radix(&s[6..8], 16)?,
            u8::from_str_radix(&s[9..11], 16)?,
            u8::from_str_radix(&s[12..14], 16)?,
            u8::from_str_radix(&s[15..17], 16)?,
        ],
    ))
}

/// Parse a list of macs like `12:34:56:78:9a:bc,12:34:56:78:9a:de`
fn parse_mac_list(env: &'static str) -> Vec<MACAddress> {
    println!("cargo::rerun-if-env-changed={}", env);
    match std::env::var(env) {
        Ok(env_str) => match {
            (|| {
                let mut macs = Vec::new();
                let mut i = 0;
                while i < env_str.len() {
                    let mac = parse_mac(&env_str[i..])?.1;
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

/// Parse a list of macs with an additional number like `12:34:56:78:9a:bc_01,12:34:56:78:9a:de_02`
fn parse_mac_to_uuid_map(env: &'static str) -> Vec<(MACAddress, u8)> {
    println!("cargo::rerun-if-env-changed={}", env);
    match std::env::var(env) {
        Ok(env_str) => match {
            (|| {
                let mut macs = Vec::new();
                let mut i = 0;
                while i < env_str.len() {
                    let (rest, mac) = parse_mac(&env_str[i..])?;
                    let rest = &rest[1..]; // skip `_` seperator
                    let uuid: u8 = u8::from_str_radix(&rest[0..2], 16)?;
                    if !(1..=128).contains(&uuid) {
                        panic!("UUIDs must be in 1..=128")
                    }
                    macs.push((mac, uuid));
                    i += 17 + 1 + 2 + 1; // skip 17 mac chars + 1 seperator + 2 uuid + 1 seperator
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
            pub DENYLIST_MACS = parse_mac_list("DENYLIST_MACS").as_slice()
        ),
        const_declaration!(
            /// Root MAC as an array.
            pub ROOT_MAC_ARR = parse_mac_list("ROOT_MAC").first().expect("ROOT_MAC should be set")
        ),
        const_declaration!(
            /// Translation from macs to uuid.
            pub MAC_TO_UUID = parse_mac_to_uuid_map("MAC_TO_UUID").into_iter().collect::<HashMap<MACAddress, u8>>()
        ),
    ]
    .join("\n");

    fs::write(dest_path, const_declarations).unwrap();
}
