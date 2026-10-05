## 00-standard-libs    
prints nothing

## 09-live-counter 
Console is poor - it is not run at a different port. Why? With Ctrl-C is the app gracefully shutting down?


## 10-live-component   Got a warning[IPE-T0011]: redundant case branch
  --> src/Counter.ipe:71:23
   |
71 |               [class "counter-buttons"]
   |                       ^ `_` is already handled
   |
   = note: run `ipe explain IPE-T0011` for more information

12-ipevote  Sign-up doesn't work. Sign in to vote too.
14-task-demo    OK
15-http-server  OK (is the server shutting down gracefully?)
16-ipehess OK
17-ipemon   Got a warning[IPE-T0011]: redundant case branch
   --> src/Lib/Auth.ipe:236:6
    |
236 |     else
    |      ^ `_` is already handled
    |
    = note: run `ipe explain IPE-T0011` for more information

warning[IPE-T0011]: redundant case branch
   --> src/Page/MonitorDetail.ipe:230:45
    |
230 |               [ onClick (Navigate DashboardPage), class "btn btn-primary" ]
    |                                             ^ `_` is already handled
    |
    = note: run `ipe explain IPE-T0011` for more information
   Other errors: "Add alert" doesn't work
18-job-queue    Gross error: error[E0507]: cannot move out of `insertRow`, a captured variable in an `Fn` closure
   --> src/main.rs:424:682
    |
424 | ...et insertRow = { let __ipe_fn: ::std::sync::Arc<dyn Fn(Db, i64) -...<Vec<ipe_runtime::db::SqlParam>>()) }); __ipe_fn }; ({ let writeAll = { let __ipe_fn: Box<dyn Fn(Db) -> IpeTask<i64> + Send + Sync + 'static> = Box::new(move |db: Db| -> IpeTask<i64> { (({ let db = db.clone(); { let __ipe_fn: Box<dyn Fn(IpeTask<i64>) -> IpeTask<i64> + Send + Sync + 'static> = Box::new(move |eta_0: IpeTask<i64>| -> IpeTask<i64> { task_and_then(eta_0, ({ let db = db.clone(); ({ let insertRow = insertRow.cl...
    |       ---------   --------------------------------------------------...--------------------------------------------------                                                                                                       ----------------------------- captured by this `Fn` closure                                                                                           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ `insertRow` is moved here                                         --------- variable moved due to use in closure
    |       |           |
    |       |           move occurs because `insertRow` has type `Arc<dyn Fn(Pool<Sqlite>, i64) -> Pin<Box<...>> + Send + Sync>`, which does not implement the `Copy` trait
    |       captured outer variable
    |
    = help: `Fn` and `FnMut` closures require captured values to be able to be consumed multiple times, but `FnOnce` closures may consume them only once
    = note: the full name for the type has been written to '/home/arthur/.cache/ipe/ipe-target/debug/deps/ipe_app-e8372183f7a9992f.long-type-934160679238325233.txt'
    = note: consider using `--verbose` to print the full type name to the console
help: consider cloning the value before moving it into the closure
    |
424 ~     ({ let insertRow = { let __ipe_fn: ::std::sync::Arc<dyn Fn(Db, i64) -> IpeTask<i64> + Send + Sync + 'static> = ::std::sync::Arc::new(move |db: Db, ts: i64| -> IpeTask<i64> { db_exec_params(db.clone(), "INSERT INTO snapshots (ok, failed, total, ts) VALUES (?, ?, ?, ?)".to_string(), (vec![okCount, failCount, total, ts]).into_iter().map(::core::convert::Into::into).collect::<Vec<ipe_runtime::db::SqlParam>>()) }); __ipe_fn }; ({ let writeAll = { let __ipe_fn: Box<dyn Fn(Db) -> IpeTask<i64> + Send + Sync + 'static> = Box::new(move |db: Db| -> IpeTask<i64> { (({ let db = db.clone(); { let value = insertRow.clone();
425 ~     let __ipe_fn: Box<dyn Fn(IpeTask<i64>) -> IpeTask<i64> + Send + Sync + 'static> = Box::new(move |eta_0: IpeTask<i64>| -> IpeTask<i64> { task_and_then(eta_0, ({ let db = db.clone(); ({ let insertRow = value.clone(); { let __ipe_fn: Box<dyn Fn(i64) -> IpeTask<i64> + Send + Sync + 'static> = Box::new(move |ts: i64| -> IpeTask<i64> { (insertRow)(db.clone(), ts) }); __ipe_fn } }) })) }); __ipe_fn } }))(({ let eta_0: IpeTask<i64> = db_exec_raw(db.clone(), main_create_snapshot_table()); task_and_then(eta_0, { let __ipe_fn: Box<dyn Fn(i64) -> IpeTask<i64> + Send + Sync + 'static> = Box::new(move |arg_5: i64| -> IpeTask<i64> { time_now(()) }); __ipe_fn }) })) }); __ipe_fn }; ({ let successMsg = format!("{}{}", "Snapshot saved (ok=".to_string(), format!("{}{}", string_from_int(okCount), format!("{}{}", " fail=".to_string(), format!("{}{}", string_from_int(failCount), ")".to_string())))); (({ let cap_0 = "snapshot.save".to_string(); { let __ipe_fn: Box<dyn Fn(IpeTask<String>) -> IpeTask<String> + Send + Sync + 'static> = Box::new(move |eta_0: IpeTask<String>| -> IpeTask<String> { main_with_error_reporting(cap_0.clone(), eta_0) }); __ipe_fn } }))(({ let eta_0: IpeTask<i64> = ({ let eta_0: IpeTask<Db> = db_open("sqlite".to_string(), main_db_path()); task_and_then(eta_0, writeAll) }); task_map({ let __ipe_fn: Box<dyn Fn(i64) -> String + Send + Sync + 'static> = Box::new(move |arg_4: i64| -> String { successMsg.clone() }); __ipe_fn }, eta_0) })) }) }) })
    |

error[E0507]: cannot move out of `selectRecent`, a captured variable in an `Fn` closure
   --> src/main.rs:427:790
    |
427 | ...et selectRecent = { let __ipe_fn: ::std::sync::Arc<dyn Fn(Db) -> Ipê...<Vec<ipe_runtime::db::SqlParam>>()) }); __ipe_fn }; ({ let readAll = { let __ipe_fn: Box<dyn Fn(Db) -> IpeTask<Vec<HashMap<String, String>>> + Send + Sync + 'static> = Box::new(move |db: Db| -> IpeTask<Vec<HashMap<String, String>>> { (({ let db = db.clone(); { let __ipe_fn: Box<dyn Fn(IpeTask<i64>) -> IpeTask<Vec<HashMap<String, String>>> + Send + Sync + 'static> = Box::new(move |eta_0: IpeTask<i64>| -> IpeTask<Vec<HashMap<String, String>>> { task_and_then(eta_0, ({ let db = db.clone(); ({ let selectRecent = selectRecent.cl...
    |       ------------   --------------------------------------------------...--------------------------------------------------                                                                                                                               ------------------------------------------------------ captured by this `Fn` closure                                                                                                                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ `selectRecent` is moved here                                         ------------ variable moved due to use in closure
    |       |              |
    |       |              move occurs because `selectRecent` has type `Arc<dyn Fn(Pool<Sqlite>) -> Pin<Box<...>> + Send + Sync>`, which does not implement the `Copy` trait
    |       captured outer variable
    |
    = help: `Fn` and `FnMut` closures require captured values to be able to be consumed multiple times, but `FnOnce` closures may consume them only once
    = note: the full name for the type has been written to '/home/arthur/.cache/ipe/ipe-target/debug/deps/ipe_app-e8372183f7a9992f.long-type-15239363051266467932.txt'
    = note: consider using `--verbose` to print the full type name to the console
help: consider cloning the value before moving it into the closure
    |
427 ~     ({ let selectRecent = { let __ipe_fn: ::std::sync::Arc<dyn Fn(Db) -> IpeTask<Vec<HashMap<String, String>>> + Send + Sync + 'static> = ::std::sync::Arc::new(move |db: Db| -> IpeTask<Vec<HashMap<String, String>>> { db_query_params(db.clone(), "SELECT ok, failed, total, ts FROM snapshots ORDER BY ts DESC LIMIT 5".to_string(), (Vec::<MainSqlValue>::new()).into_iter().map(::core::convert::Into::into).collect::<Vec<ipe_runtime::db::SqlParam>>()) }); __ipe_fn }; ({ let readAll = { let __ipe_fn: Box<dyn Fn(Db) -> IpeTask<Vec<HashMap<String, String>>> + Send + Sync + 'static> = Box::new(move |db: Db| -> IpeTask<Vec<HashMap<String, String>>> { (({ let db = db.clone(); { let value = selectRecent.clone();
428 ~     let __ipe_fn: Box<dyn Fn(IpeTask<i64>) -> IpeTask<Vec<HashMap<String, String>>> + Send + Sync + 'static> = Box::new(move |eta_0: IpeTask<i64>| -> IpeTask<Vec<HashMap<String, String>>> { task_and_then(eta_0, ({ let db = db.clone(); ({ let selectRecent = value.clone(); { let __ipe_fn: Box<dyn Fn(i64) -> IpeTask<Vec<HashMap<String, String>>> + Send + Sync + 'static> = Box::new(move |arg_6: i64| -> IpeTask<Vec<HashMap<String, String>>> { (selectRecent)(db.clone()) }); __ipe_fn } }) })) }); __ipe_fn } }))(db_exec_raw(db.clone(), main_create_snapshot_table())) }); __ipe_fn }; (({ let cap_0 = "snapshot.load".to_string(); { let __ipe_fn: Box<dyn Fn(IpeTask<Vec<RecFailedOkTotalTs>>) -> IpeTask<Vec<RecFailedOkTotalTs>> + Send + Sync + 'static> = Box::new(move |eta_0: IpeTask<Vec<RecFailedOkTotalTs>>| -> IpeTask<Vec<RecFailedOkTotalTs>> { main_with_error_reporting(cap_0.clone(), eta_0) }); __ipe_fn } }))(({ let eta_0: IpeTask<Vec<HashMap<String, String>>> = ({ let eta_0: IpeTask<Db> = db_open("sqlite".to_string(), main_db_path()); task_and_then(eta_0, readAll) }); task_map({ let __ipe_fn: Box<dyn Fn(Vec<HashMap<String, String>>) -> Vec<RecFailedOkTotalTs> + Send + Sync + 'static> = Box::new(move |rows: Vec<HashMap<String, String>>| -> Vec<RecFailedOkTotalTs> { list_map_consume({ let __ipe_fn: Box<dyn Fn(HashMap<String, String>) -> RecFailedOkTotalTs + Send + Sync + 'static> = Box::new(main_parse_snapshot); __ipe_fn }, rows) }); __ipe_fn }, eta_0) })) }) })
    |

For more information about this error, try `rustc --explain E0507`.

## 20-cli-counter
Compare to Go

## 24-tui-kitchen-sink Got a warning[IPE-L0124]: `Web.tea` routes list is non-empty but Model has no `page` field
   --> src/Main.ipe:497:13
    |
497 |             Live.app
    |             ^^^^^^^^ 1 route(s) declared but the Model has no `page` field — routing is disabled and the routes are ignored
    |
    = note: the `routes` list has 1 route(s) but the Model has no `page` field, so routing is disabled and every URL serves the same app. The routed-page field must be named exactly `page` (of the `Page` ADT whose constructors appear as route destinations). Rename the field to `page`, or remove the `routes` list if routing is not needed.
    = note: run `ipe explain IPE-L0124` for more information

Multiline is not working. 
Have to compare with Go

25-ipe-console  
warning[IPE-L0124]: `Web.tea` routes list is non-empty but Model has no `page` field
  --> src/Main.ipe:62:5
   |
62 |     app
   |     ^^^ 1 route(s) declared but the Model has no `page` field — routing is disabled and the routes are ignored
   |
   = note: the `routes` list has 1 route(s) but the Model has no `page` field, so routing is disabled and every URL serves the same app. The routed-page field must be named exactly `page` (of the `Page` ADT whose constructors appear as route destinations). Rename the field to `page`, or remove the `routes` list if routing is not needed.
   = note: run `ipe explain IPE-L0124` for more information


## 26-ui-showcase
Scroll is not working. I think fill portion is not working either. Compare with Go.

## 27-multi-session-chat   
Sending message is not working - it even appears on a second browser tab, but the message is never printed on sender's screen.

## 28-streaming-chat   
2026/07/15 23:39:36 [ipe.live] session store: memory (ttl=30m0s)
2026/07/15 23:39:36 [ipe.live] session store: memory (ttl=30m0s)
[ipe.console] inline console mounted as Ipe.Web sub-app at /_ipe/console mode=dev-open
[ipe.live] listening on http://0.0.0.0:8000
Ipe.Web listening on :8000
[error] ForeignError (ref 1df6ffd5): reqwest::Error { kind: Request, url: "http://localhost:8765/stream", source: hyper_util::client::legacy::Error(Connect, ConnectError("tcp connect error", 127.0.0.1:8765, Os { code: 111, kind: ConnectionRefused, message: "Connection refused" })) }
[error] ForeignError (ref 1a718632): reqwest::Error { kind: Request, url: "http://localhost:8765/stream", source: hyper_util::client::legacy::Error(Connect, ConnectError("tcp connect error", 127.0.0.1:8765, Os { code: 111, kind: ConnectionRefused, message: "Connection refused" })) }
[error] ForeignError (ref 03102b26): reqwest::Error { kind: Request, url: "http://localhost:8765/stream", source: hyper_util::client::legacy::Error(Connect, ConnectError("tcp connect error", 127.0.0.1:8765, Os { code: 111, kind: ConnectionRefused, message: "Connection refused" })) }


## 29-webview-threejs-spike    
error: failed to run custom build command for `libdbus-sys v0.2.7`

Caused by:
  process didn't exit successfully: `/home/arthur/.cache/ipe/ipe-target/debug/build/libdbus-sys-8a45b7e77791d9fa/build-script-build` (exit status: 101)
  --- stdout
  cargo:rerun-if-changed=build.rs
  cargo:rerun-if-changed=build_vendored.rs
  cargo:rerun-if-env-changed=DBUS_1_NO_PKG_CONFIG
  cargo:rerun-if-env-changed=PKG_CONFIG_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG
  cargo:rerun-if-env-changed=PKG_CONFIG
  cargo:rerun-if-env-changed=DBUS_1_STATIC
  cargo:rerun-if-env-changed=DBUS_1_DYNAMIC
  cargo:rerun-if-env-changed=PKG_CONFIG_ALL_STATIC
  cargo:rerun-if-env-changed=PKG_CONFIG_ALL_DYNAMIC
  cargo:rerun-if-env-changed=PKG_CONFIG_PATH_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_PATH_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG_PATH
  cargo:rerun-if-env-changed=PKG_CONFIG_PATH
  cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG_LIBDIR
  cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR
  cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG_SYSROOT_DIR
  cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR

  --- stderr
  pkg_config failed: 
  pkg-config exited with status code 1
  > PKG_CONFIG_ALLOW_SYSTEM_LIBS=1 PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1 pkg-config --libs --cflags dbus-1 'dbus-1 >= 1.6'

  pkg-config output:
    Package dbus-1 was not found in the pkg-config search path.
    Perhaps you should add the directory containing `dbus-1.pc'
    to the PKG_CONFIG_PATH environment variable
    No package 'dbus-1' found
    Package dbus-1 was not found in the pkg-config search path.
    Perhaps you should add the directory containing `dbus-1.pc'
    to the PKG_CONFIG_PATH environment variable
    No package 'dbus-1' found

  The system library `dbus-1` required by crate `libdbus-sys` was not found.
  The file `dbus-1.pc` needs to be installed and the PKG_CONFIG_PATH environment variable must contain its parent directory.
  The PKG_CONFIG_PATH environment variable is not set.

  HINT: if you have installed the library, try setting PKG_CONFIG_PATH to the directory containing `dbus-1.pc`.

  One possible solution is to check whether packages
  'libdbus-1-dev' and 'pkg-config' are installed:
  On Ubuntu:
  sudo apt install libdbus-1-dev pkg-config
  On Fedora:
  sudo dnf install dbus-devel pkgconf-pkg-config


  thread 'main' (538422) panicked at /home/arthur/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/libdbus-sys-0.2.7/build.rs:25:9:
  explicit panic
  note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
warning: build failed, waiting for other jobs to finish...
---
Good that the error messages are instructive, but it it exit-0-cargo-fails anyway
After installing this, another error:

warning: glib-sys@0.18.1: 
error: failed to run custom build command for `glib-sys v0.18.1`

Caused by:
  process didn't exit successfully: `/home/arthur/.cache/ipe/ipe-target/debug/build/glib-sys-e5a0a004c39a2ec5/build-script-build` (exit status: 1)
  --- stdout
  cargo:rerun-if-env-changed=GLIB_2.0_NO_PKG_CONFIG
  cargo:rerun-if-env-changed=PKG_CONFIG_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG
  cargo:rerun-if-env-changed=PKG_CONFIG
  cargo:rerun-if-env-changed=PKG_CONFIG_PATH_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_PATH_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG_PATH
  cargo:rerun-if-env-changed=PKG_CONFIG_PATH
  cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG_LIBDIR
  cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR
  cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG_SYSROOT_DIR
  cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR
  cargo:warning=
  pkg-config exited with status code 1
  > PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1 pkg-config --libs --cflags glib-2.0 'glib-2.0 >= 2.70'

  pkg-config output:
    Package glib-2.0 was not found in the pkg-config search path.
    Perhaps you should add the directory containing `glib-2.0.pc'
    to the PKG_CONFIG_PATH environment variable
    No package 'glib-2.0' found
    Package glib-2.0 was not found in the pkg-config search path.
    Perhaps you should add the directory containing `glib-2.0.pc'
    to the PKG_CONFIG_PATH environment variable
    No package 'glib-2.0' found

  The system library `glib-2.0` required by crate `glib-sys` was not found.
  The file `glib-2.0.pc` needs to be installed and the PKG_CONFIG_PATH environment variable must contain its parent directory.
  The PKG_CONFIG_PATH environment variable is not set.

  HINT: if you have installed the library, try setting PKG_CONFIG_PATH to the directory containing `glib-2.0.pc`.

warning: build failed, waiting for other jobs to finish...

------
I had to run "sudo apt-get install libglib2.0-dev", but it failed with:

error: failed to run custom build command for `gobject-sys v0.18.0`

Caused by:
  process didn't exit successfully: `/home/arthur/.cache/ipe/ipe-target/debug/build/gobject-sys-dbaa120ffd2ae1df/build-script-build` (exit status: 1)
  --- stdout
  cargo:rerun-if-env-changed=GOBJECT_2.0_NO_PKG_CONFIG
  cargo:rerun-if-env-changed=PKG_CONFIG_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG
  cargo:rerun-if-env-changed=PKG_CONFIG
  cargo:rerun-if-env-changed=PKG_CONFIG_PATH_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_PATH_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG_PATH
  cargo:rerun-if-env-changed=PKG_CONFIG_PATH
  cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG_LIBDIR
  cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR
  cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG_SYSROOT_DIR
  cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR
  cargo:warning=
  pkg-config exited with status code 1
  > PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1 pkg-config --libs --cflags gobject-2.0 'gobject-2.0 >= 2.70'

  pkg-config output:
    Requested 'gobject-2.0 >= 2.70' but version of GObject is 2.64.6

  The system library `gobject-2.0` required by crate `gobject-sys` was not found.
  The file `gobject-2.0.pc` needs to be installed and the PKG_CONFIG_PATH environment variable must contain its parent directory.
  The PKG_CONFIG_PATH environment variable is not set.

  HINT: if you have installed the library, try setting PKG_CONFIG_PATH to the directory containing `gobject-2.0.pc`.

I just gave up.


## 31-webview-stopwatch-ui 
  > PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1 pkg-config --libs --cflags gio-2.0 'gio-2.0 >= 2.70'

  pkg-config output:
    Requested 'gio-2.0 >= 2.70' but version of GIO is 2.64.6

  The system library `gio-2.0` required by crate `gio-sys` was not found.
  The file `gio-2.0.pc` needs to be installed and the PKG_CONFIG_PATH environment variable must contain its parent directory.
  The PKG_CONFIG_PATH environment variable is not set.

  HINT: if you have installed the library, try setting PKG_CONFIG_PATH to the directory containing `gio-2.0.pc`.

error: failed to run custom build command for `gdk-sys v0.18.2`

Caused by:
  process didn't exit successfully: `/home/arthur/.cache/ipe/ipe-target/debug/build/gdk-sys-daf9c1358d474747/build-script-build` (exit status: 1)
  --- stdout
  cargo:rerun-if-env-changed=GDK_3.0_NO_PKG_CONFIG
  cargo:rerun-if-env-changed=PKG_CONFIG_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG
  cargo:rerun-if-env-changed=PKG_CONFIG
  cargo:rerun-if-env-changed=PKG_CONFIG_PATH_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_PATH_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG_PATH
  cargo:rerun-if-env-changed=PKG_CONFIG_PATH
  cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG_LIBDIR
  cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR
  cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG_SYSROOT_DIR
  cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR

  --- stderr

  pkg-config exited with status code 1
  > PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1 pkg-config --libs --cflags gdk-3.0 'gdk-3.0 >= 3.22'

  pkg-config output:
    Package gdk-3.0 was not found in the pkg-config search path.
    Perhaps you should add the directory containing `gdk-3.0.pc'
    to the PKG_CONFIG_PATH environment variable
    No package 'gdk-3.0' found
    Package gdk-3.0 was not found in the pkg-config search path.
    Perhaps you should add the directory containing `gdk-3.0.pc'
    to the PKG_CONFIG_PATH environment variable
    No package 'gdk-3.0' found

  The system library `gdk-3.0` required by crate `gdk-sys` was not found.
  The file `gdk-3.0.pc` needs to be installed and the PKG_CONFIG_PATH environment variable must contain its parent directory.
  The PKG_CONFIG_PATH environment variable is not set.

  HINT: if you have installed the library, try setting PKG_CONFIG_PATH to the directory containing `gdk-3.0.pc`.

## 34-multi-tier-console   
OK, but compare with Go

## 36-composite-server 
OK, but compare with Go

## 37-composite-live-shop  
OK, but compare with Go

## 38-composite-ui-multibackend
"$IPEC_BIN" dev build src/Main.ipe --out out/rust && cargo +nightly build -Z unstable-options --manifest-path out/rust/Cargo.toml --artifact-dir ./out/rust/target/debug/ &&  ./out/rust/target/debug/ipe-app 
warning[IPE-L0124]: `Web.tea` routes list is non-empty but Model has no `page` field
   --> src/View.ipe:123:48
    |
123 |             , statTile "7-day avg" (String.fromInt weekAvg ++ "%")
    |                                                ^^^^^^^^ 1 route(s) declared but the Model has no `page` field — routing is disabled and the routes are ignored
    |
    = note: the `routes` list has 1 route(s) but the Model has no `page` field, so routing is disabled and every URL serves the same app. The routed-page field must be named exactly `page` (of the `Page` ADT whose constructors appear as route destinations). Rename the field to `page`, or remove the `routes` list if routing is not needed.
    = note: run `ipe explain IPE-L0124` for more information

    Updating crates.io index
     Locking 461 packages to latest Rust 1.99.0-nightly compatible versions
      Adding aes-gcm v0.10.3 (available: v0.11.0)
      Adding axum v0.7.9 (available: v0.8.9)
      Adding bcrypt v0.17.1 (available: v0.19.2)
      Adding chacha20poly1305 v0.10.1 (available: v0.11.0)
      Adding crossterm v0.28.1 (available: v0.29.0)
      Adding generic-array v0.14.7 (available: v0.14.9)
      Adding hmac v0.12.1 (available: v0.13.0)
      Adding jsonwebtoken v9.3.1 (available: v10.4.0)
      Adding md-5 v0.10.6 (available: v0.11.0)
      Adding pbkdf2 v0.12.2 (available: v0.13.0)
      Adding reqwest v0.12.28 (available: v0.13.4)
      Adding sha1 v0.10.7 (available: v0.11.0)
      Adding sha2 v0.10.9 (available: v0.11.0)
      Adding toml v0.8.2 (available: v0.8.23)
      Adding toml_datetime v0.6.3 (available: v0.6.11)
      Adding toml_edit v0.20.2 (available: v0.20.7)
      Adding tower-http v0.5.2 (available: v0.7.0)
      Adding unicode-width v0.1.14 (available: v0.2.2)
   Compiling glib-sys v0.18.1
   Compiling gobject-sys v0.18.0
   Compiling gio-sys v0.18.1
   Compiling gdk-sys v0.18.2
warning: gobject-sys@0.18.0: 
error: failed to run custom build command for `gobject-sys v0.18.0`

Caused by:
  process didn't exit successfully: `/home/arthur/.cache/ipe/ipe-target/debug/build/gobject-sys-dbaa120ffd2ae1df/build-script-build` (exit status: 1)
  --- stdout
  cargo:rerun-if-env-changed=GOBJECT_2.0_NO_PKG_CONFIG
  cargo:rerun-if-env-changed=PKG_CONFIG_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG
  cargo:rerun-if-env-changed=PKG_CONFIG
  cargo:rerun-if-env-changed=PKG_CONFIG_PATH_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_PATH_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG_PATH
  cargo:rerun-if-env-changed=PKG_CONFIG_PATH
  cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG_LIBDIR
  cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR
  cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG_SYSROOT_DIR
  cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR
  cargo:warning=
  pkg-config exited with status code 1
  > PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1 pkg-config --libs --cflags gobject-2.0 'gobject-2.0 >= 2.70'

  pkg-config output:
    Requested 'gobject-2.0 >= 2.70' but version of GObject is 2.64.6

  The system library `gobject-2.0` required by crate `gobject-sys` was not found.
  The file `gobject-2.0.pc` needs to be installed and the PKG_CONFIG_PATH environment variable must contain its parent directory.
  The PKG_CONFIG_PATH environment variable is not set.

  HINT: if you have installed the library, try setting PKG_CONFIG_PATH to the directory containing `gobject-2.0.pc`.

warning: build failed, waiting for other jobs to finish...
warning: glib-sys@0.18.1: 
error: failed to run custom build command for `glib-sys v0.18.1`

Caused by:
  process didn't exit successfully: `/home/arthur/.cache/ipe/ipe-target/debug/build/glib-sys-e5a0a004c39a2ec5/build-script-build` (exit status: 1)
  --- stdout
  cargo:rerun-if-env-changed=GLIB_2.0_NO_PKG_CONFIG
  cargo:rerun-if-env-changed=PKG_CONFIG_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG
  cargo:rerun-if-env-changed=PKG_CONFIG
  cargo:rerun-if-env-changed=PKG_CONFIG_PATH_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_PATH_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG_PATH
  cargo:rerun-if-env-changed=PKG_CONFIG_PATH
  cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG_LIBDIR
  cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR
  cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG_SYSROOT_DIR
  cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR
  cargo:warning=
  pkg-config exited with status code 1
  > PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1 pkg-config --libs --cflags glib-2.0 'glib-2.0 >= 2.70'

  pkg-config output:
    Requested 'glib-2.0 >= 2.70' but version of GLib is 2.64.6

  The system library `glib-2.0` required by crate `glib-sys` was not found.
  The file `glib-2.0.pc` needs to be installed and the PKG_CONFIG_PATH environment variable must contain its parent directory.
  The PKG_CONFIG_PATH environment variable is not set.

  HINT: if you have installed the library, try setting PKG_CONFIG_PATH to the directory containing `glib-2.0.pc`.

warning: gio-sys@0.18.1: 
error: failed to run custom build command for `gio-sys v0.18.1`

Caused by:
  process didn't exit successfully: `/home/arthur/.cache/ipe/ipe-target/debug/build/gio-sys-1f9f51dc511e42c9/build-script-build` (exit status: 1)
  --- stdout
  cargo:rerun-if-env-changed=GIO_2.0_NO_PKG_CONFIG
  cargo:rerun-if-env-changed=PKG_CONFIG_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG
  cargo:rerun-if-env-changed=PKG_CONFIG
  cargo:rerun-if-env-changed=PKG_CONFIG_PATH_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_PATH_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG_PATH
  cargo:rerun-if-env-changed=PKG_CONFIG_PATH
  cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG_LIBDIR
  cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR
  cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG_SYSROOT_DIR
  cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR
  cargo:warning=
  pkg-config exited with status code 1
  > PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1 pkg-config --libs --cflags gio-2.0 'gio-2.0 >= 2.70'

  pkg-config output:
    Requested 'gio-2.0 >= 2.70' but version of GIO is 2.64.6

  The system library `gio-2.0` required by crate `gio-sys` was not found.
  The file `gio-2.0.pc` needs to be installed and the PKG_CONFIG_PATH environment variable must contain its parent directory.
  The PKG_CONFIG_PATH environment variable is not set.

  HINT: if you have installed the library, try setting PKG_CONFIG_PATH to the directory containing `gio-2.0.pc`.

error: failed to run custom build command for `gdk-sys v0.18.2`

Caused by:
  process didn't exit successfully: `/home/arthur/.cache/ipe/ipe-target/debug/build/gdk-sys-daf9c1358d474747/build-script-build` (exit status: 1)
  --- stdout
  cargo:rerun-if-env-changed=GDK_3.0_NO_PKG_CONFIG
  cargo:rerun-if-env-changed=PKG_CONFIG_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG
  cargo:rerun-if-env-changed=PKG_CONFIG
  cargo:rerun-if-env-changed=PKG_CONFIG_PATH_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_PATH_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG_PATH
  cargo:rerun-if-env-changed=PKG_CONFIG_PATH
  cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG_LIBDIR
  cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR
  cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR_x86_64-unknown-linux-gnu
  cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR_x86_64_unknown_linux_gnu
  cargo:rerun-if-env-changed=HOST_PKG_CONFIG_SYSROOT_DIR
  cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR

  --- stderr

  pkg-config exited with status code 1
  > PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1 pkg-config --libs --cflags gdk-3.0 'gdk-3.0 >= 3.22'

  pkg-config output:
    Package gdk-3.0 was not found in the pkg-config search path.
    Perhaps you should add the directory containing `gdk-3.0.pc'
    to the PKG_CONFIG_PATH environment variable
    No package 'gdk-3.0' found
    Package gdk-3.0 was not found in the pkg-config search path.
    Perhaps you should add the directory containing `gdk-3.0.pc'
    to the PKG_CONFIG_PATH environment variable
    No package 'gdk-3.0' found

  The system library `gdk-3.0` required by crate `gdk-sys` was not found.
  The file `gdk-3.0.pc` needs to be installed and the PKG_CONFIG_PATH environment variable must contain its parent directory.
  The PKG_CONFIG_PATH environment variable is not set.

  HINT: if you have installed the library, try setting PKG_CONFIG_PATH to the directory containing `gdk-3.0.pc`.



