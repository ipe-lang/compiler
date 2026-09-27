#![forbid(unsafe_code)]
//! `ipe` binary entry point — a thin wrapper over the [`ipe`] driver library.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match ipe::run_cli(&args) {
        Ok(()) => ExitCode::SUCCESS,
        // `--check --exit-code` carries a git-style numeric code (10/0/2); the
        // status line was already printed by `run_upgrade`. Deliver it as the
        // process exit code — `ExitCode` renders any byte, so no abrupt exit.
        Err(ipe::CliError::UpgradeCheckExit { code }) => {
            ExitCode::from(u8::try_from(code).unwrap_or(2))
        }
        // A wasm32-wasip1 module ran under embedded wasmtime and returned a
        // non-zero WASI exit code; the guest owns the outcome, so propagate its
        // exact code (mirroring how a native run surfaces a child's exit).
        Err(err @ ipe::CliError::WasiRunExited { code }) => {
            ipe::screen::report_error(&err);
            ExitCode::from(u8::try_from(code).unwrap_or(1))
        }
        // Every other failure renders through the one error frame: header,
        // the error in its fault's tone (or its own complete screen), then the
        // bug footer. An error that already wrote its output renders nothing.
        Err(err) => {
            ipe::screen::report_error(&err);
            ExitCode::FAILURE
        }
    }
}
