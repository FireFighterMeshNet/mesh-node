use const_gen::{const_declaration, CompileConst};
use std::{env, fs, path::Path};

fn main() {
    println!("cargo::rerun-if-changed=build.rs");

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("const_gen.rs");

    let const_declarations = [
        const_declaration!(
            /// Hardcoded tree level. This is `0` for the Root.
            pub TREE_LEVEL = common::build::parse_option_env::<u8>("TREE_LEVEL")
        ),
        const_declaration!(
            /// Deny listed macs (mostly for debugging) (don't connect to these)
            pub DENYLIST_MACS = common::build::parse_mac_list("DENYLIST_MACS").as_slice()
        ),
        const_declaration!(
            /// Maximum nodes in the mesh
            pub MAX_NODES = common::build::parse_option_env::<usize>("MAX_NODES").unwrap_or(5)
        ),
    ]
    .join("\n");

    fs::write(dest_path, const_declarations).unwrap();
}
