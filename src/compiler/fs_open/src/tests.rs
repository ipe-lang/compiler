//! Refusal tests: every open that must be turned away is driven to its exact refusal.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use super::{ByteCap, EntryCap, EntryName, FileKind, HeldDir, OpenRefusal, RegularFile};

/// A fresh, empty scratch directory unique to this test and process.
fn scratch(tag: &str) -> PathBuf {
    let dir = ipe_test_temp::temp_root().join(format!("ipe_fs_open_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::canonicalize(&dir).unwrap()
}

/// The entry name `text`, which the test knows to be one plain component.
fn name(text: &str) -> EntryName {
    EntryName::new(OsStr::new(text)).unwrap()
}

/// A byte cap of `bytes`, which the test knows to be non-zero.
fn cap(bytes: u64) -> ByteCap {
    ByteCap::new(bytes).unwrap()
}

/// The directory `dir`, held.
fn held(dir: &Path) -> HeldDir {
    HeldDir::open_root(dir).unwrap()
}

/// Make `path` a FIFO.
#[cfg(unix)]
fn make_fifo(path: &Path) {
    let made = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .unwrap();
    assert!(made.success(), "mkfifo creates the fixture");
}

/// Run `open` on a worker thread; `None` when it has not answered within five seconds.
#[cfg(unix)]
fn within_five_seconds(
    open: impl FnOnce() -> Result<RegularFile, OpenRefusal> + Send + 'static,
) -> Option<Result<u64, OpenRefusal>> {
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = send.send(open().map(|file| file.len()));
    });
    receive.recv_timeout(std::time::Duration::from_secs(5)).ok()
}

#[cfg(unix)]
#[test]
fn a_fifo_is_refused_without_blocking() {
    let dir = scratch("fifo");
    make_fifo(&dir.join("fifo"));
    let opened = within_five_seconds(move || held(&dir).open_regular(&name("fifo")));
    assert!(
        matches!(opened, Some(Err(OpenRefusal::NotRegular(FileKind::Fifo)))),
        "a FIFO is refused at once, got {opened:?}"
    );
}

#[test]
fn a_directory_is_not_regular() {
    let dir = scratch("dir");
    std::fs::create_dir(dir.join("sub")).unwrap();
    let opened = held(&dir).open_regular(&name("sub"));
    assert!(
        matches!(opened, Err(OpenRefusal::NotRegular(FileKind::Dir))),
        "a directory is refused, got {opened:?}"
    );
}

#[cfg(unix)]
#[test]
fn dev_null_is_a_device() {
    let through_handle = held(Path::new("/dev")).open_regular(&name("null"));
    assert!(
        matches!(
            through_handle,
            Err(OpenRefusal::NotRegular(FileKind::Device))
        ),
        "a device entry is refused, got {through_handle:?}"
    );
    let named = RegularFile::open_user_named(Path::new("/dev/null"));
    assert!(
        matches!(named, Err(OpenRefusal::NotRegular(FileKind::Device))),
        "a device the user names is refused, got {named:?}"
    );
}

#[cfg(unix)]
#[test]
fn a_final_symlink_is_link() {
    let dir = scratch("final_link");
    std::fs::write(dir.join("target.txt"), "secret").unwrap();
    std::os::unix::fs::symlink(dir.join("target.txt"), dir.join("link.txt")).unwrap();
    let held = held(&dir);
    let opened = held.open_regular(&name("link.txt"));
    assert!(
        matches!(opened, Err(OpenRefusal::Link)),
        "a final link is refused, got {opened:?}"
    );
    let kind = held.kind_of(&name("link.txt"));
    assert!(
        matches!(kind, Ok(Some(FileKind::Symlink))),
        "a link is classified without being followed, got {kind:?}"
    );
}

#[cfg(unix)]
#[test]
fn an_intermediate_symlink_dir_is_link() {
    let dir = scratch("inner_link");
    std::fs::create_dir(dir.join("real")).unwrap();
    std::fs::write(dir.join("real").join("f.txt"), "secret").unwrap();
    std::os::unix::fs::symlink(dir.join("real"), dir.join("link")).unwrap();
    let held = held(&dir);
    let through = held.open_rel(&[name("link"), name("f.txt")]);
    assert!(
        matches!(through, Err(OpenRefusal::Link)),
        "a linked level is refused, got {through:?}"
    );
    let child = held.child_dir(&name("link"));
    assert!(
        matches!(child, Err(OpenRefusal::Link)),
        "a linked subdirectory is refused, got {child:?}"
    );
    let plain = held.open_rel(&[name("real"), name("f.txt")]);
    assert!(
        matches!(plain, Ok(ref file) if file.len() == 6),
        "a plain level is walked, got {plain:?}"
    );
}

#[cfg(unix)]
#[test]
fn a_dir_swapped_for_a_link_after_entries_is_link() {
    let dir = scratch("swap_after_entries");
    std::fs::create_dir(dir.join("sub")).unwrap();
    std::fs::create_dir(dir.join("elsewhere")).unwrap();
    let held = held(&dir);
    let listed = held.entries(EntryCap::new(8).unwrap()).unwrap();
    assert!(
        listed
            .iter()
            .any(|(entry, kind)| entry == &name("sub") && *kind == FileKind::Dir),
        "the listing sees the directory, got {listed:?}"
    );
    std::fs::rename(dir.join("sub"), dir.join("sub.aside")).unwrap();
    std::os::unix::fs::symlink(dir.join("elsewhere"), dir.join("sub")).unwrap();
    let child = held.child_dir(&name("sub"));
    assert!(
        matches!(child, Err(OpenRefusal::Link)),
        "the link swapped in after the listing is refused, got {child:?}"
    );
}

#[test]
fn cap_minus_one_and_cap_read_and_cap_plus_one_is_too_large() {
    let dir = scratch("byte_cap");
    std::fs::write(dir.join("three"), "abc").unwrap();
    std::fs::write(dir.join("four"), "abcd").unwrap();
    std::fs::write(dir.join("five"), "abcde").unwrap();
    let held = held(&dir);
    let read = |entry: &str| {
        held.open_regular(&name(entry))
            .and_then(|file| file.read_bytes(cap(4)))
    };
    let three = read("three");
    assert!(
        matches!(three.as_deref(), Ok(b"abc")),
        "one under the cap is read, got {three:?}"
    );
    let four = read("four");
    assert!(
        matches!(four.as_deref(), Ok(b"abcd")),
        "exactly the cap is read, got {four:?}"
    );
    let five = read("five");
    assert!(
        matches!(five, Err(OpenRefusal::TooLarge(at)) if at == cap(4)),
        "one past the cap is refused, got {five:?}"
    );
}

#[test]
fn a_file_growing_past_its_fstat_length_is_too_large() {
    use std::io::Write as _;
    let dir = scratch("growing");
    std::fs::write(dir.join("grows"), "abc").unwrap();
    let file = held(&dir).open_regular(&name("grows")).unwrap();
    assert_eq!(file.len(), 3, "the proof saw three bytes");
    std::fs::OpenOptions::new()
        .append(true)
        .open(dir.join("grows"))
        .unwrap()
        .write_all(b"defghij")
        .unwrap();
    let read = file.read_bytes(cap(4));
    assert!(
        matches!(read, Err(OpenRefusal::TooLarge(at)) if at == cap(4)),
        "growth past the cap is refused, got {read:?}"
    );
}

#[test]
fn a_capped_reader_fails_past_its_cap() {
    use std::io::Read as _;
    let dir = scratch("capped_reader");
    std::fs::write(dir.join("five"), "abcde").unwrap();
    let file = held(&dir).open_regular(&name("five")).unwrap();
    let mut read = Vec::new();
    let result = file.into_reader(cap(4)).read_to_end(&mut read);
    assert!(
        matches!(&result, Err(e) if e.kind() == std::io::ErrorKind::FileTooLarge),
        "the reader fails one past the cap, got {result:?}"
    );
}

#[test]
fn invalid_utf8_is_not_utf8() {
    let dir = scratch("utf8");
    std::fs::write(dir.join("bad"), [0xff, 0xfe, 0x61]).unwrap();
    let read = held(&dir)
        .open_regular(&name("bad"))
        .and_then(|file| file.read_utf8(cap(16)));
    assert!(
        matches!(read, Err(OpenRefusal::NotUtf8)),
        "invalid UTF-8 is refused, got {read:?}"
    );
}

#[test]
fn entry_cap_plus_one_is_too_many_entries() {
    let dir = scratch("entry_cap");
    for entry in ["a", "b", "c"] {
        std::fs::write(dir.join(entry), entry).unwrap();
    }
    let entry_cap = EntryCap::new(3).unwrap();
    let held = held(&dir);
    let at_cap = held.entries(entry_cap);
    assert!(
        matches!(at_cap, Ok(ref found) if found.len() == 3
            && found.iter().all(|(_, kind)| *kind == FileKind::Regular)),
        "exactly the cap is listed, got {at_cap:?}"
    );
    std::fs::write(dir.join("d"), "d").unwrap();
    let past = held.entries(entry_cap);
    assert!(
        matches!(past, Err(OpenRefusal::TooManyEntries(at)) if at == entry_cap),
        "one past the cap is refused, got {past:?}"
    );
}

#[test]
fn entry_name_refuses() {
    for refused in ["", ".", "..", "a/b", "/", "a\0b"] {
        assert!(
            EntryName::new(OsStr::new(refused)).is_none(),
            "{refused:?} must not be an entry name"
        );
        assert!(
            matches!(
                EntryName::parse(OsStr::new(refused)),
                Err(OpenRefusal::BadName)
            ),
            "{refused:?} parses to the typed refusal"
        );
    }
    #[cfg(windows)]
    for refused in ["a:b", "a\\b", "CON", "con.txt", "NUL .txt", "a*"] {
        assert!(
            EntryName::new(OsStr::new(refused)).is_none(),
            "{refused:?} must not be an entry name on Windows"
        );
    }
    for kept in ["token", ".token.1.ab.tmp", "a b", "caf\u{e9}"] {
        assert!(
            EntryName::new(OsStr::new(kept)).is_some(),
            "{kept:?} is an entry name"
        );
    }
    #[cfg(windows)]
    for kept in ["x.", "x "] {
        assert!(
            EntryName::new(OsStr::new(kept)).is_some(),
            "{kept:?} stays reachable through a handle-relative open"
        );
    }
}

/// A name that is not valid Unicode is refused on Windows, never decoded lossily.
#[cfg(windows)]
#[test]
fn a_non_unicode_name_is_refused_on_windows() {
    use std::os::windows::ffi::OsStringExt as _;
    let lone_surrogate = std::ffi::OsString::from_wide(&[0xD800, 0x61]);
    assert!(EntryName::new(&lone_surrogate).is_none());
}

#[cfg(unix)]
#[test]
fn user_named_follows_a_final_link_but_refuses_a_fifo() {
    let dir = scratch("user_named");
    std::fs::write(dir.join("target.txt"), "named").unwrap();
    std::os::unix::fs::symlink(dir.join("target.txt"), dir.join("link.txt")).unwrap();
    let read = RegularFile::open_user_named(&dir.join("link.txt"))
        .and_then(|file| file.read_utf8(cap(16)));
    assert!(
        matches!(read.as_deref(), Ok("named")),
        "the link the user named is followed, got {read:?}"
    );
    let fifo = dir.join("fifo");
    make_fifo(&fifo);
    let opened = within_five_seconds(move || RegularFile::open_user_named(&fifo));
    assert!(
        matches!(opened, Some(Err(OpenRefusal::NotRegular(FileKind::Fifo)))),
        "a FIFO the user names is refused at once, got {opened:?}"
    );
}

#[test]
fn an_absent_entry_is_absent() {
    let dir = scratch("absent");
    let held = held(&dir);
    let opened = held.open_regular(&name("missing"));
    assert!(matches!(opened, Err(OpenRefusal::Absent)), "got {opened:?}");
    let child = held.child_dir(&name("missing"));
    assert!(matches!(child, Err(OpenRefusal::Absent)), "got {child:?}");
    let kind = held.kind_of(&name("missing"));
    assert!(matches!(kind, Ok(None)), "got {kind:?}");
    let rel = held.open_rel(&[]);
    assert!(matches!(rel, Err(OpenRefusal::BadName)), "got {rel:?}");
}

#[test]
fn a_file_is_not_a_child_directory() {
    let dir = scratch("file_child");
    std::fs::write(dir.join("f.txt"), "x").unwrap();
    let child = held(&dir).child_dir(&name("f.txt"));
    assert!(
        matches!(child, Err(OpenRefusal::NotRegular(FileKind::Regular))),
        "a file is refused as a directory, got {child:?}"
    );
    let root = HeldDir::open_root(&dir.join("f.txt"));
    assert!(
        matches!(root, Err(OpenRefusal::NotRegular(FileKind::Regular))),
        "a file is refused as a root, got {root:?}"
    );
}

/// Zero is not a cap: no constructor turns it into an unbounded read.
#[test]
fn zero_is_not_a_cap() {
    assert!(ByteCap::new(0).is_none());
    assert!(EntryCap::new(0).is_none());
}

/// A file another program holds open without sharing is refused, in use.
#[cfg(windows)]
#[test]
fn a_file_held_open_elsewhere_is_in_use() {
    use std::os::windows::fs::OpenOptionsExt as _;
    let dir = scratch("in_use");
    std::fs::write(dir.join("busy.txt"), "busy").unwrap();
    let other = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(dir.join("busy.txt"))
        .unwrap();
    let opened = held(&dir).open_regular(&name("busy.txt"));
    assert!(
        matches!(opened, Err(OpenRefusal::InUse)),
        "a file held without sharing is refused, got {opened:?}"
    );
    drop(other);
}

/// A link's stored target is read through the handle, never followed; a non-link is refused as what it is.
#[cfg(unix)]
#[test]
fn read_link_reads_the_stored_target_and_refuses_a_non_link() {
    let dir = scratch("read_link");
    std::fs::write(dir.join("plain.txt"), "plain").unwrap();
    std::os::unix::fs::symlink("../elsewhere/run", dir.join("link")).unwrap();
    let held = held(&dir);
    let target = held.read_link(&name("link"));
    assert_eq!(
        target.ok(),
        Some(PathBuf::from("../elsewhere/run")),
        "the stored target is returned verbatim, dangling or not"
    );
    let plain = held.read_link(&name("plain.txt"));
    assert!(
        matches!(plain, Err(OpenRefusal::NotRegular(FileKind::Regular))),
        "a regular file is not a link, got {plain:?}"
    );
    let absent = held.read_link(&name("absent"));
    assert!(
        matches!(absent, Err(OpenRefusal::Absent)),
        "an absent entry is absent, got {absent:?}"
    );
}

/// A second directory entry for a file shows in its link count.
#[test]
fn link_count_counts_a_hard_link() {
    let dir = scratch("link_count");
    std::fs::write(dir.join("one.txt"), "one").unwrap();
    let held = held(&dir);
    let alone = held.open_regular(&name("one.txt")).unwrap().link_count();
    assert_eq!(alone.ok(), Some(1), "a file with one name counts one");
    std::fs::hard_link(dir.join("one.txt"), dir.join("two.txt")).unwrap();
    let linked = held.open_regular(&name("one.txt")).unwrap().link_count();
    assert_eq!(linked.ok(), Some(2), "a hard link counts as a second name");
}
