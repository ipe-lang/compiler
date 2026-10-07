//! Names every ambient-input path the crate's own `clippy.toml` denies, so
//! rustc resolves each.
//!
//! Each naming carries its own `#[expect]` of the clippy lint the entry
//! configures, so the file also proves each ban fires: an entry clippy stops
//! matching leaves its expectation unfulfilled, and `unfulfilled_lint_expectations`
//! under `-D warnings` fails the clippy run. rustc leaves tool-lint expectations
//! unchecked, so a plain build is unaffected. The `inv1_clippy_config` test
//! asserts the config and this file name the same set.

const _STD_FS: () = {
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::fs::read::<String>;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::fs::read_to_string::<String>;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::fs::read_dir::<String>;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::fs::read_link::<String>;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::fs::metadata::<String>;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::fs::symlink_metadata::<String>;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::fs::canonicalize::<String>;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::fs::exists::<String>;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::fs::write::<String, Vec<u8>>;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::fs::create_dir::<String>;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::fs::create_dir_all::<String>;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::fs::remove_file::<String>;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::fs::remove_dir::<String>;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::fs::remove_dir_all::<String>;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::fs::rename::<String, String>;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::fs::copy::<String, String>;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::fs::hard_link::<String, String>;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::fs::set_permissions::<String>;
};

const _STD_PATH: () = {
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::path::Path::exists;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::path::Path::try_exists;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::path::Path::is_file;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::path::Path::is_dir;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::path::Path::is_symlink;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::path::Path::metadata;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::path::Path::symlink_metadata;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::path::Path::read_dir;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::path::Path::read_link;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::path::Path::canonicalize;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::path::absolute::<String>;
};

const _STD_ENV: () = {
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::env::current_dir;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::env::set_current_dir::<String>;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::env::current_exe;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::env::args;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::env::args_os;
};

const _STD_PROCESS_IO: () = {
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::process::id;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::io::stdin;
};

const _STD_TIME: () = {
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::time::SystemTime::now;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::time::SystemTime::elapsed;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::time::Instant::now;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::time::Instant::elapsed;
};

const _STD_FS_TYPES: () = {
    #[expect(clippy::disallowed_types)]
    let _: Option<::std::fs::File> = None;
    #[expect(clippy::disallowed_types)]
    let _: Option<::std::fs::OpenOptions> = None;
    #[expect(clippy::disallowed_types)]
    let _: Option<::std::fs::DirBuilder> = None;
    #[expect(clippy::disallowed_types)]
    let _: Option<::std::fs::ReadDir> = None;
    #[expect(clippy::disallowed_types)]
    let _: Option<::std::fs::DirEntry> = None;
};
