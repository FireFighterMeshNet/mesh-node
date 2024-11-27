use std::{env::VarError, num::ParseIntError, str::FromStr};

pub type MACAddress = [u8; 6];

/// Like [`option_env!`] but tries to parse the environment variable as `T`.
pub fn parse_option_env<T>(env: &'static str) -> Option<T>
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
pub fn parse_mac(s: &str) -> Result<(&str, MACAddress), ParseIntError> {
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
pub fn parse_mac_list(env: &'static str) -> Vec<MACAddress> {
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
