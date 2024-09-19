# Installation
See
- <https://docs.esp-rs.org/book/introduction.html>
- <https://docs.esp-rs.org/no_std-training/>
for installation instructions.
Choose the `no_std` option for the `exp32` with `Xtensa`.

# Flash and run
After following installation you should have `cargo`, `espflash` installed so `cargo run --release` when the board is plugged in should work. If it hangs on `Connecting...` cancel the command (`ctrl-c`) and try again.

# Troubleshooting
- Stack overflow hangs instead of crashing and restarting even with watchdog enabled.
    - <https://github.com/espressif/esp-idf/issues/10110>