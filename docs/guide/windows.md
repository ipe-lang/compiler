# Installing on Windows

> **Experimental.** Windows support is not yet part of the tested release
> matrix: expect rough edges, and report them at
> <https://github.com/ipe-lang/compiler/issues>.

`ipe` compiles your project to Rust, so you need a Rust toolchain and a C linker
besides `ipe` itself. None of these steps needs administrator rights.

## 1. Rust

In PowerShell, then open a new terminal:

```powershell
winget install Rustlang.Rustup
rustup toolchain install stable-x86_64-pc-windows-gnu
rustup default stable-x86_64-pc-windows-gnu
```

The GNU toolchain links without the Visual Studio C++ Build Tools. If you have
administrator rights you can use the default MSVC toolchain instead (install the
"Desktop development with C++" workload) and skip the last two commands.

## 2. A C linker

```powershell
winget install BrechtSanders.WinLibs.POSIX.UCRT
```

Open a new terminal and check `gcc --version`. Skip this step with MSVC.

## 3. `ipe`

[`install.bat`](../../install.bat) downloads the **latest** release, verifies its
SHA-256, installs `ipe.exe` to `%USERPROFILE%\.ipe\bin` (override with
`IPE_INSTALL_DIR`) and offers to add that folder to your user `PATH`. Pin a
release with `IPE_VERSION`. It also checks for Rust and a C linker and, when
`winget` is available, offers to install what is missing (steps 1 and 2 are the
manual equivalent). Run it from PowerShell or `cmd`; run it again to upgrade:

```powershell
curl.exe -fsSLO https://raw.githubusercontent.com/ipe-lang/compiler/main/install.bat
.\install.bat
```

Open a new terminal and check `ipe --version`. From Git Bash, the README's
`install.sh` one-liner works too.

## 4. First run

```powershell
ipe init counter
cd counter
ipe dev run
```

The first build compiles the runtime's dependencies and takes minutes. The app
serves at <http://localhost:8000>. Next: [Getting started](getting-started.md).

## Troubleshooting

- **`rustup`, `gcc` or `ipe` not found** right after installing: open a new
  terminal so the updated `PATH` loads.
- **The build stalls at "resolving the emitted crate's dependencies"**: `cargo`
  is waiting on the network. Run `cargo --version`, then check that a proxy,
  firewall or antivirus is not blocking `index.crates.io` and `static.crates.io`.
