use common::build::{parse_mac_list, parse_option_env};
use const_gen::{const_declaration, CompileConst};
use std::{env, fs, path::Path};

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
    ]
    .join("\n");

    fs::write(dest_path, const_declarations).unwrap();
}
