# Intro to Embedded Rust
- See <https://doc.rust-lang.org/book/> for a tutorial on the language itself.
- See <https://docs.rust-embedded.org/book/intro/index.html> on extra information specific for embedded programming.

# Installation
See
- <https://docs.esp-rs.org/book/introduction.html>
- <https://docs.esp-rs.org/no_std-training/>

for installation instructions.
Choose the `no_std` option for the `exp32` with `Xtensa` architecture.

# Flash and run
After following installation you should have `cargo` and `espflash` installed so `cargo run --release` when the board is plugged in should work. If it hangs on `Connecting...` cancel the command (`Ctrl-c`) and try again or try pressing the `RESET` button of the development board.

# Documentation
`cargo doc --open` should open the documentation for all dependencies and the project in your browser.

# Configuration

## Features
- `dump-packets` emits packets to uart debug interface for use in the wifishark extcap. Slows wifi down.

## Environment Variables
- `SSID`: (optional) custom SSID of WIFI STA and AP connection.
- `RNG_SEED`:  (optional) deterministic override of random seed.
- `TREE_LEVEL`: (optional) overrides the level of the node to the given value in the tree mesh.

# Security
- Currently, the implementation can easily be tricked by another AP with the same ssid sending custom beacons.
- Currently, the implementation doesn't encrypt data.

# Wifishark
- Follow [these instructions](https://github.com/Easyoakland/esp-hal/blob/raw-ieee/extras/esp-wifishark/README.md) to build, install, and use the wireshark extcap.

# Troubleshooting
- Stack overflow hangs instead of crashing and restarting even with watchdog enabled.
    - <https://github.com/espressif/esp-idf/issues/10110>
- If you get a ``linking with `xtensa-esp32-elf-gcc` failed ... undefined reference to ...`` then you likely need to enable a feature in the corresponding crate to provide the function (e.g. `_embassy_time_schedule_wake` comes from `generic-queue` in `embassy-time`)