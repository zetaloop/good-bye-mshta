# Good Bye MSHTA

<p align="center">
  <img src="good-bye-mshta.png" alt="Good Bye MSHTA Logo" width="150"/>
</p>

A simple tool that intercepts `mshta.exe` calls and helps transition legacy elevation scripts to modern alternatives.

## Why This Exists

After a Windows 11 update, my `mshta.exe` stopped working—it just exits silently without executing anything. This made debugging those old scripts more troublesome.

Since Microsoft has deprecated mshta anyway, I made this simple tool to keep my old scripts working and help me transition to newer alternatives.

## What It Does

When a script tries to call mshta:

- **For elevation requests** (like `vbscript:CreateObject("Shell.Application").ShellExecute(...)`):
  - Actually executes the request so your script keeps working
  - Shows a notification with equivalent PowerShell and Python commands you can use instead

- **For other mshta commands**:
  - Shows a deprecation notice letting you know mshta is no longer supported

Notifications are displayed in Chinese or English based on your system language.

## Setup

Written in Rust because I hate C's ecosystem—or lack thereof.

Build it:
```bash
cargo build --release
```

Get the compiled binary from `target/release/mshta.exe`.

Then put `mshta.exe` somewhere convenient and add that folder to your PATH. It should be placed **before** the System32 directory.

## License

MIT
