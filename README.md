# Intro to Embedded Rust
- See <https://doc.rust-lang.org/book/> for a tutorial on the language itself.
- See <https://docs.rust-embedded.org/book/intro/index.html> on extra information specific for embedded programming.

# Installation
See
- <https://docs.esp-rs.org/book/introduction.html>
- <https://docs.esp-rs.org/no_std-training/>

for installation instructions.
Choose the `no_std` option for the `exp32` with `Xtensa` architecture.

Note: Modifies environment variables as indicated in the ps1 file saved to `%userprofile%/export-esp.ps1`

# Flash and run
After following installation you should have `cargo` and `espflash` (if the second is missing do `cargo install espflash`) installed so `cargo run --release` when the board is plugged in should work. If it hangs on `Connecting...` cancel the command (`Ctrl-c`) and try again or try pressing the `RESET` button of the development board.

# Documentation
`cargo doc --open` should open the documentation for all dependencies and the project in your browser.\
`cargo doc --open --document-private-items` will show extra documentation for private items.

# Project Layout
- `crates` contains the various [crates](https://doc.rust-lang.org/book/ch07-01-packages-and-crates.html) of the project.
- The `tree_mesh` crate contains generic code for the maintaining and using the Wi-Fi mesh. This is mainly used by created a virtual device which forwards messages as needed based upon their ip address.
    - This is generic so that the mesh algorithm algorithm can be tested in software for correctness.
- The `ffmn` crate contains the integration crate which contains `fn main()`, uses `tree_mesh` for the mesh, sets up the board, configures the bluetooth, and generally has the specific code required for using the ESP32. This is what you should build and run to flash to the board.
- `common` contains various code shared by the other crates.

# Configuration

## Features
- `dump-packets` emits packets to uart debug interface for use in the wifishark extcap. Slows wifi down.

## Environment Variables
- `SSID`: (optional) custom SSID of WIFI STA and AP connection.
- `RNG_SEED`:  (optional) deterministic override of random seed.
- `TREE_LEVEL`: (optional) overrides the level of the node to the given value in the tree mesh.
    - For the mesh to organize correctly one node (no more or less) should run the software built with this environment variable set to `0`. That node is the unique root of the tree.
- `DENYLIST_MACS`: (optional) comma seperated list of hex code mac address like `12:34:56:78:9a:bc,12:34:56:78:9a:de` to ignore and not connect to.

See the `build.rs` for details.

# Security
- Currently, the implementation can easily be tricked by another AP with the same ssid sending custom beacons.
- Currently, the implementation doesn't encrypt data.

# Wifishark
- Follow [these instructions](https://github.com/Easyoakland/esp-hal/blob/raw-ieee/extras/esp-wifishark/README.md) to build, install, and use the wireshark extcap.

# Troubleshooting
- Stack overflow hangs instead of crashing and restarting even with watchdog enabled.
    - <https://github.com/espressif/esp-idf/issues/10110>
- If you get a ``linking with `xtensa-esp32-elf-gcc` failed ... undefined reference to ...`` then you likely need to enable a feature in the corresponding crate to provide the function (e.g. `_embassy_time_schedule_wake` comes from `generic-queue` in `embassy-time` or `integrated-timers` in `embassy-executor`)
    - Alternatively, the symbols might have been stripped out. I noticed this in the case of the `coex` feature enabled without using any ble functions.
- Invalid rustc version: Update rustc. If using `espup` you might have to specify a specific version with `espup install -v <version>` e.g. `espup install -v 1.84.0`
- CP2102 USB to UART Bridge Controller device missing drivers
    - Get them from <https://www.silabs.com/developer-tools/usb-to-uart-bridge-vcp-drivers>
