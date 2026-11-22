# Installing on Linux, macOS and FreeBSD

`ipe` compiles your project to Rust, so a build needs a Rust toolchain and the
C toolchain Rust links through, besides `ipe` itself. The installer needs only a
downloader and a SHA-256 tool; it names anything else your host lacks, with the
command that installs it. For Windows, see [Installing on Windows](windows.md).

## 1. Prerequisites

| Host | Downloader | C toolchain |
|------|------------|-------------|
| Debian, Ubuntu | `sudo apt install curl` | `sudo apt install build-essential` |
| Fedora, RHEL, Rocky | `sudo dnf install curl` | `sudo dnf install gcc` |
| Arch | `sudo pacman -S --needed curl` | `sudo pacman -S --needed base-devel` |
| Alpine | `sudo apk add curl` | `sudo apk add build-base` |
| openSUSE | `sudo zypper install curl` | `sudo zypper install gcc` |
| macOS | ships with curl | `xcode-select --install` |
| FreeBSD | ships with `fetch`; `sudo pkg install curl` for `ipe upgrade` | ships with `cc` |

The installer downloads with curl, or with GNU Wget when curl is absent, or
with `fetch` on FreeBSD. It verifies the download with `sha256sum`, `shasum`,
`sha256` or `openssl`, one of which every host above ships. A wget that is not
GNU Wget, such as the BusyBox wget on Alpine, is not used: install curl.

## 2. Rust

Install Rust 1.85 or later with [rustup](https://rustup.rs), then open a new
terminal:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Run from a terminal, the installer offers to do this for you. Run from a
script, it never installs Rust; it prints the command above instead.

## 3. `ipe`

```sh
curl -fsSL https://raw.githubusercontent.com/ipe-lang/compiler/main/install.sh -o ipe-install.sh && sh ipe-install.sh
```

Or, with GNU Wget:

```sh
wget -qO ipe-install.sh https://raw.githubusercontent.com/ipe-lang/compiler/main/install.sh && sh ipe-install.sh
```

The script is saved whole before it runs, so a cut-off download runs nothing.
It installs `ipe` into `~/.local/bin` (set `IPE_INSTALL_DIR` to choose another
dir) and offers to add that dir to your `PATH`.

Every download is HTTPS-only, redirects included, with TLS 1.2 or later and
certificate checks that no user config or environment variable can turn off.
The release archive is verified against the release's `SHA256SUMS` before
anything is extracted; a missing, malformed or mismatched checksum stops the
install. A `GITHUB_TOKEN` or `GH_TOKEN` in the environment is sent from a file
private to you, never on a command line.

When the host lacks a build prerequisite, the installer still installs `ipe`
and ends with a **Before your first build** block naming each missing tool and
its install command.

## 4. First run

```sh
ipe init counter
cd counter
ipe dev run
```

`ipe dev run` serves the app at <http://localhost:8000>.

## Troubleshooting

- **Exit status 3, "Missing prerequisite".** The host has no downloader or no
  SHA-256 tool. Install the tool the message names, then run the installer
  again.
- **Exit status 2, "No prebuilt binary".** The release has no binary for your
  OS and CPU yet. Build from source with
  `cargo install --git https://github.com/ipe-lang/compiler ipe`.
- **A checksum error.** The download did not match the release's `SHA256SUMS`.
  Run the installer again; if it persists, report it at
  <https://github.com/ipe-lang/compiler/issues>.
- **A size-ceiling message under Wget or `fetch`.** These downloaders stop on a
  stalled connection but not at a byte count, so the installer checks the size
  once the file is written and removes an oversized one. curl stops at the
  ceiling during the transfer.
- **Redirects under `fetch`.** FreeBSD `fetch` follows redirects itself; each
  file it writes is still verified against `SHA256SUMS`. Install curl for
  HTTPS-only redirects.
- **The rustup step.** The rustup bootstrap is trusted through its HTTPS
  connection to `sh.rustup.rs`, as rustup's own instructions do.
- **`ipe` reports a missing tool on its first build.** Install the tool it
  names with the command it prints — the same commands as the table above.
