# Installation
See
- <https://docs.esp-rs.org/book/introduction.html>
- <https://docs.esp-rs.org/no_std-training/>

for installation instructions.
Choose the `no_std` option for the `exp32` with `Xtensa` architecture.

# Flash and run
After following installation you should have `cargo` and `espflash` installed so `cargo run --release` when the board is plugged in should work. If it hangs on `Connecting...` cancel the command (`ctrl-c`) and try again.

## Configuration
The following environment variables should be set:
- `RNG_SEED` to a random `u64`.

# Troubleshooting
- Stack overflow hangs instead of crashing and restarting even with watchdog enabled.
    - <https://github.com/espressif/esp-idf/issues/10110>
- If you get a ``linking with `xtensa-esp32-elf-gcc` failed ... undefined reference to ...`` then you likely need to enable a feature in the corresponding crate to provide the function (e.g. `_embassy_time_schedule_wake` comes from `generic-queue` in `embassy-time`)