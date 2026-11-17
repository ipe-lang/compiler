#![forbid(unsafe_code)]
//! Refuses a build directory the host linker cannot open, end to end.
//!
//! The real `ipe` binary runs with a stub `rustc` reporting a
//! `x86_64-pc-windows-gnu` host (an ASCII-only linker family) and a stub
//! `cargo` that logs every call with the `CARGO_TARGET_DIR` it was handed. An
//! unlinkable pin or sysroot is refused with IPE-E0002 before any build; a
//! development build with no pin builds in the compiler's development
//! directory of the per-user cache, or, when that directory is not private, in
//! the project's own per-user cache directory; a release build under a pin
//! builds in the pin's `release-ipe`; and a link failure naming an input the
//! linker could not open is IPE-E0003, an environment fault, never the
//! IPE-I0001 compiler-bug frame.

#[cfg(test)]
#[cfg(unix)]
mod stubbed {
    use std::fs;
    use std::path::{Path, PathBuf};

    const SRC: &str = "module Main exposing (main)\n\nimport Ipe.Io\n\nmain = Io.println \"hi\"\n";

    /// The `rustc -vV` report of a `windows-gnu` host.
    const GNU_REPORT: &str = "rustc 1.98.1 (00000000 2026-01-01)\n\
                              binary: rustc\n\
                              host: x86_64-pc-windows-gnu\n\
                              release: 1.98.1\n";

    /// The stderr a `windows-gnu` link step prints when `ld` cannot open an input.
    const UNOPENABLE: &str = "error: linking with `x86_64-w64-mingw32-gcc` failed: exit code: 1
  |
  = note: \"x86_64-w64-mingw32-gcc\" \"-m64\" \"C:\\Users\\Jo\u{e3}o\\out\\rust\\target\\debug\\deps\\app.o\"
  = note: C:\\msys64\\mingw64\\bin\\ld.exe: cannot find C:\\Users\\Jo\u{e3}o\\out\\rust\\target\\debug\\deps\\app.o: No such file or directory
          collect2.exe: error: ld returned 1 exit status

error: could not compile `app` (bin \"app\") due to 1 previous error
";

    /// One scratch case: a project, its fake tools, and the per-user dirs.
    struct Case {
        root: PathBuf,
        project: PathBuf,
        bin: PathBuf,
        cache: PathBuf,
        home: PathBuf,
    }

    impl Case {
        /// A fresh case named `name`, its project under `project_dir`.
        fn new(name: &str, project_dir: &str) -> Self {
            let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
                .join(format!("ipe_target_dir_gnu_{name}"));
            e2e_support::scratch::fresh(&root);
            let case = Self {
                project: root.join(project_dir),
                bin: root.join("fakebin"),
                cache: root.join("cache"),
                home: root.join("ipe-home"),
                root,
            };
            for dir in [&case.project, &case.bin, &case.cache, &case.home] {
                fs::create_dir_all(dir).expect("make case dir");
            }
            fs::create_dir_all(case.project.join("src")).expect("make src dir");
            fs::write(
                case.project.join("package.ipe"),
                "module Package exposing (package)\n\n\npackage =\n    { name = \"app\" }\n",
            )
            .expect("write package.ipe");
            fs::write(case.project.join("src").join("Main.ipe"), SRC).expect("write source");
            fs::write(case.bin.join("unopenable.txt"), UNOPENABLE).expect("write link stderr");
            case
        }

        /// Install the stub `rustc`, reporting the gnu host and `sysroot`.
        fn gnu_rustc(&self, sysroot: &str) {
            fs::write(self.bin.join("report.txt"), GNU_REPORT).expect("write report");
            fs::write(self.bin.join("sysroot.txt"), format!("{sysroot}\n")).expect("sysroot");
            executable(
                &self.bin.join("rustc"),
                "#!/bin/sh\n\
                 here=\"$(dirname \"$0\")\"\n\
                 case \"$1\" in\n\
                 -vV) cat \"$here/report.txt\" ;;\n\
                 --print) cat \"$here/sysroot.txt\" ;;\n\
                 *) exit 1 ;;\n\
                 esac\n",
            );
        }

        /// Install the stub `cargo`: `metadata` reports the crate's own
        /// `target`, a lockfile resolves, every call is logged with its
        /// `CARGO_TARGET_DIR`, and a build fails with `build_stderr`'s contents.
        fn cargo(&self, build_stderr: &str) {
            executable(
                &self.bin.join("cargo"),
                &format!(
                    "#!/bin/sh\n\
                     here=\"$(dirname \"$0\")\"\n\
                     printf '%s %s\\n' \"$1\" \"${{CARGO_TARGET_DIR:-unset}}\" >> \"$here/calls.log\"\n\
                     case \"$1\" in\n\
                     metadata) printf '{{\"target_directory\":\"%s/target\"}}\\n' \"$PWD\"; exit 0 ;;\n\
                     generate-lockfile|update) exit 0 ;;\n\
                     *) cat \"$here/{build_stderr}\" 1>&2; exit 101 ;;\n\
                     esac\n"
                ),
            );
        }

        /// Run `ipe dev build` on the project with `extra` environment.
        fn build(&self, extra: &[(&str, &Path)]) -> (bool, String) {
            self.build_in(&self.project, Verb::Dev, extra)
        }

        /// Write a second project, `dir` under the case root, beside the first.
        fn another_project(&self, dir: &str) -> PathBuf {
            let project = self.root.join(dir);
            fs::create_dir_all(project.join("src")).expect("make src dir");
            fs::copy(
                self.project.join("package.ipe"),
                project.join("package.ipe"),
            )
            .expect("copy package.ipe");
            fs::write(project.join("src").join("Main.ipe"), SRC).expect("write source");
            project
        }

        /// Run `ipe <verb> build` on `project` with `extra` environment.
        fn build_in(&self, project: &Path, verb: Verb, extra: &[(&str, &Path)]) -> (bool, String) {
            let mut cmd = std::process::Command::new(e2e_support::cargo_bin!("ipe"));
            cmd.args([verb.word(), "build"])
                .arg(project)
                .arg("--out")
                .arg(project.join("out"));
            // A release builds only against the runtime the compiler embeds.
            match verb {
                Verb::Dev => {
                    cmd.env(
                        "IPE_RUNTIME_DIR",
                        e2e_support::require_runtime().into_path_buf(),
                    );
                }
                Verb::Release => {}
            }
            cmd.env(
                "PATH",
                std::env::join_paths([
                    self.bin.as_path(),
                    Path::new("/usr/bin"),
                    Path::new("/bin"),
                ])
                .expect("join PATH"),
            )
            .env("IPE_HOME", &self.home)
            .env("XDG_CACHE_HOME", &self.cache)
            .env("HOME", &self.root)
            .env("NO_COLOR", "1");
            e2e_support::target::clear_target_dir_env(&mut cmd);
            for (key, value) in extra {
                cmd.env(key, value);
            }
            let out = cmd.output().expect("spawn ipe");
            (
                out.status.success(),
                String::from_utf8_lossy(&out.stderr).into_owned(),
            )
        }

        /// The logged cargo calls, one `<subcommand> <CARGO_TARGET_DIR>` each.
        fn calls(&self) -> Vec<String> {
            fs::read_to_string(self.bin.join("calls.log"))
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect()
        }

        /// The `CARGO_TARGET_DIR` every logged `cargo build` was handed.
        fn build_dirs(&self) -> Vec<String> {
            self.calls()
                .iter()
                .filter_map(|call| call.strip_prefix("build "))
                .map(str::to_owned)
                .collect()
        }
    }

    /// The build verb a case runs.
    #[derive(Clone, Copy)]
    enum Verb {
        /// `ipe dev build`.
        Dev,
        /// `ipe release build`.
        Release,
    }

    impl Verb {
        /// The verb's command word.
        const fn word(self) -> &'static str {
            match self {
                Self::Dev => "dev",
                Self::Release => "release",
            }
        }
    }

    /// Whether `key` is a 16-digit hex digest.
    fn is_key(key: &str) -> bool {
        key.len() == 16 && key.chars().all(|c| c.is_ascii_hexdigit())
    }

    impl Drop for Case {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    /// Write `script` to `path` as an executable.
    fn executable(path: &Path, script: &str) {
        use std::os::unix::fs::PermissionsExt as _;
        fs::write(path, script).expect("write stub");
        let mut perms = fs::metadata(path).expect("stub metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).expect("make stub executable");
    }

    /// A non-ASCII `CARGO_TARGET_DIR` on a gnu host is IPE-E0002, and no
    /// `cargo build` runs.
    #[test]
    fn an_unlinkable_pin_is_refused_before_any_build() {
        let case = Case::new("pin", "app");
        case.gnu_rustc("/opt/rust/toolchain");
        case.cargo("unopenable.txt");
        let pin = case.root.join("t\u{e2}rget");
        let (ok, stderr) = case.build(&[("CARGO_TARGET_DIR", &pin)]);
        assert!(
            !ok,
            "an unlinkable pin must fail the build; stderr:\n{stderr}"
        );
        assert!(stderr.contains("IPE-E0002"), "stderr:\n{stderr}");
        assert!(!stderr.contains("IPE-I0001"), "stderr:\n{stderr}");
        assert!(
            case.build_dirs().is_empty(),
            "no cargo build may run before the parse: {:?}",
            case.calls()
        );
    }

    /// A development build with no pin builds in the compiler's development
    /// directory, `<cache>/ipe/t/dev-<key>`: one ASCII directory keyed by the
    /// compiler, never by the project, so a non-ASCII project builds there
    /// every time and a second project builds in the same directory.
    #[test]
    fn a_development_build_shares_the_compilers_development_directory() {
        let case = Case::new("devdir", "proj\u{e9}to");
        case.gnu_rustc("/opt/rust/toolchain");
        case.cargo("unopenable.txt");
        let other = case.another_project("outro\u{e9}");
        let _ = case.build(&[]);
        let _ = case.build(&[]);
        let _ = case.build_in(&other, Verb::Dev, &[]);
        let dirs = case.build_dirs();
        assert_eq!(dirs.len(), 3, "three builds ran: {:?}", case.calls());
        let shared_root = case.cache.join("ipe").join("t");
        for dir in &dirs {
            let dir = Path::new(dir);
            assert_eq!(
                dir.parent(),
                Some(shared_root.as_path()),
                "{} is in {}",
                dir.display(),
                shared_root.display()
            );
            assert!(
                dir.to_string_lossy().is_ascii(),
                "{} is ASCII",
                dir.display()
            );
            let name = dir
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            assert!(
                name.strip_prefix("dev-").is_some_and(is_key),
                "{name} is the compiler's development directory"
            );
        }
        assert!(
            dirs.windows(2).all(|pair| pair.first() == pair.last()),
            "every build of every project shares one directory: {dirs:?}"
        );
    }

    /// A development directory another user could write is never built in: a
    /// non-ASCII project falls back to its own per-user cache directory,
    /// keyed by the project the same on every build.
    #[test]
    #[allow(clippy::panic)] // a case whose first build did not run fails the test
    fn a_widened_development_directory_falls_back_to_the_project_cache() {
        use std::os::unix::fs::PermissionsExt as _;
        let case = Case::new("widened", "proj\u{e9}to");
        case.gnu_rustc("/opt/rust/toolchain");
        case.cargo("unopenable.txt");
        let _ = case.build(&[]);
        let first = case.build_dirs();
        let [planted] = first.as_slice() else {
            panic!("one build ran: {:?}", case.calls());
        };
        fs::set_permissions(planted, fs::Permissions::from_mode(0o777)).expect("widen");
        let _ = case.build(&[]);
        let _ = case.build(&[]);
        let dirs = case.build_dirs();
        let fallen = dirs.get(1..).unwrap_or_default();
        assert_eq!(fallen.len(), 2, "two more builds ran: {:?}", case.calls());
        let shared_root = case.cache.join("ipe").join("t");
        for dir in fallen {
            assert_ne!(dir, planted, "the widened directory is never built in");
            let dir = Path::new(dir);
            assert_eq!(
                dir.parent(),
                Some(shared_root.as_path()),
                "{}",
                dir.display()
            );
            assert!(
                dir.to_string_lossy().is_ascii(),
                "{} is ASCII",
                dir.display()
            );
            let key = dir
                .file_name()
                .and_then(|key| key.to_str())
                .unwrap_or_default();
            assert!(is_key(key), "{key} is a 16-digit project key");
        }
        assert_eq!(
            fallen.first(),
            fallen.last(),
            "the project key is the same every build"
        );
    }

    /// Under a `CARGO_TARGET_DIR` pin a development build builds in the pin and
    /// a release build in the pin's `release-ipe`, so a release never
    /// rebuilds over the development artifacts.
    #[test]
    fn a_pinned_release_builds_in_the_pins_release_directory() {
        let case = Case::new("release-pin", "app");
        case.gnu_rustc("/opt/rust/toolchain");
        case.cargo("unopenable.txt");
        let pin = case.root.join("pin");
        let _ = case.build(&[("CARGO_TARGET_DIR", &pin)]);
        let (_, stderr) =
            case.build_in(&case.project, Verb::Release, &[("CARGO_TARGET_DIR", &pin)]);
        let dirs = case.build_dirs();
        let release = pin.join("release-ipe");
        assert_eq!(
            dirs,
            [pin.display().to_string(), release.display().to_string()],
            "the development build in the pin, the release in its release-ipe: {:?}\n{stderr}",
            case.calls()
        );
    }

    /// A non-ASCII sysroot on a gnu host is IPE-E0002, and no `cargo build` runs.
    #[test]
    fn an_unlinkable_sysroot_is_refused_before_any_build() {
        let case = Case::new("sysroot", "app");
        case.gnu_rustc("/home/jos\u{e9}/.rustup/toolchains/stable-x86_64-pc-windows-gnu");
        case.cargo("unopenable.txt");
        let (ok, stderr) = case.build(&[]);
        assert!(
            !ok,
            "an unlinkable sysroot must fail the build; stderr:\n{stderr}"
        );
        assert!(stderr.contains("IPE-E0002"), "stderr:\n{stderr}");
        assert!(
            case.build_dirs().is_empty(),
            "no cargo build may run before the parse: {:?}",
            case.calls()
        );
    }

    /// A link step whose linker cannot open an input is IPE-E0003, an
    /// environment fault, never the compiler-bug frame.
    #[test]
    fn an_unopenable_link_input_is_an_environment_fault() {
        let case = Case::new("link", "app");
        case.gnu_rustc("/opt/rust/toolchain");
        case.cargo("unopenable.txt");
        let (ok, stderr) = case.build(&[]);
        assert!(!ok, "a failed link must fail the build; stderr:\n{stderr}");
        assert_eq!(
            case.build_dirs().len(),
            1,
            "the build ran: {:?}",
            case.calls()
        );
        assert!(stderr.contains("IPE-E0003"), "stderr:\n{stderr}");
        assert!(!stderr.contains("IPE-I0001"), "stderr:\n{stderr}");
        assert!(!stderr.contains("please report"), "stderr:\n{stderr}");
    }
}
