//! Refusal tests: every open that must be turned away is driven to its exact refusal.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use super::{
    ByteCap, EntryCap, EntryName, FileId, FileKind, HeldDir, HintedKind, OpenRefusal, RegularFile,
    is_one_spelled_name,
};

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
    std::thread::Builder::new()
        .spawn(move || {
            let _ = send.send(open().map(|file| file.len()));
        })
        .expect("the OS starts the open worker thread");
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

/// Every text that is not one component opening as spelled is refused.
#[test]
fn a_smuggled_component_is_not_one_spelled_name() {
    for refused in [
        "", ".", "..", "a/b", "a/", "/a", "/", "./a", "a/..", "a\0b", "\0",
    ] {
        assert!(
            !is_one_spelled_name(OsStr::new(refused)),
            "{refused:?} must not be one spelled name"
        );
    }
    #[cfg(windows)]
    for refused in [
        "a\\b",
        "\\a",
        "C:",
        "C:a",
        "\\\\?\\C:",
        "\\\\server\\share",
        "a:stream",
        "out.",
        "out ",
        "...",
        "NUL",
        "con.txt",
        "aux .txt",
        "COM1",
        "a*",
        "a\u{1}b",
    ] {
        assert!(
            !is_one_spelled_name(OsStr::new(refused)),
            "{refused:?} must not be one spelled name on Windows"
        );
    }
}

/// A name one step past each refused shape is one spelled name.
#[test]
fn a_plain_name_is_one_spelled_name() {
    for kept in [
        "a",
        "k.json",
        ".hidden",
        "...a",
        "a b",
        " lead",
        "nullable",
        "COM10",
        "x.nul",
        "caf\u{e9}",
    ] {
        assert!(
            is_one_spelled_name(OsStr::new(kept)),
            "{kept:?} is one spelled name"
        );
    }
    #[cfg(not(windows))]
    for kept in ["out.", "out ", "NUL", "a:b", "a\\b"] {
        assert!(
            is_one_spelled_name(OsStr::new(kept)),
            "{kept:?} opens as spelled outside Windows"
        );
    }
}

/// A name that is not valid Unicode is not one spelled name on Windows.
#[cfg(windows)]
#[test]
fn a_non_unicode_name_is_not_one_spelled_name_on_windows() {
    use std::os::windows::ffi::OsStringExt as _;
    let lone_surrogate = std::ffi::OsString::from_wide(&[0xD800, 0x61]);
    assert!(!is_one_spelled_name(&lone_surrogate));
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

/// Every identity read of one file agrees: the proven handle, a raw handle, the path, and the no-follow entry.
#[test]
fn every_identity_read_of_one_file_agrees() {
    let dir = scratch("identity");
    std::fs::write(dir.join("f.txt"), "hello").unwrap();
    let held = held(&dir);
    let entry = held.entry_id(&name("f.txt")).unwrap().unwrap();
    let proven = held.open_regular(&name("f.txt")).unwrap();
    assert_eq!(proven.id().unwrap(), entry);
    let raw = std::fs::File::open(dir.join("f.txt")).unwrap();
    assert_eq!(FileId::of_file(&raw).unwrap(), entry);
    assert_eq!(FileId::of_path(&dir.join("f.txt")).unwrap(), entry);
    assert_eq!(proven.link_count().unwrap(), 1);
    std::fs::hard_link(dir.join("f.txt"), dir.join("g.txt")).unwrap();
    assert_eq!(proven.link_count().unwrap(), 2);
    assert_eq!(held.entry_id(&name("g.txt")).unwrap(), Some(entry));
}

/// Each platform builds a [`FileId`] in exactly one function, so no two identity reads can disagree on its form.
#[test]
fn each_platform_builds_a_file_id_in_one_place() {
    for (platform, source) in [
        ("unix.rs", include_str!("unix.rs")),
        ("windows.rs", include_str!("windows.rs")),
    ] {
        assert_eq!(
            source.matches("FileId {").count(),
            1,
            "{platform} builds a FileId in more than one place"
        );
    }
}

/// The kind listed for `entry`, `None` when the listing lacks it.
fn hinted_kind_of(listed: &[(EntryName, HintedKind)], entry: &str) -> Option<HintedKind> {
    listed
        .iter()
        .find(|(listed_name, _)| listed_name == &name(entry))
        .map(|(_, kind)| *kind)
}

#[test]
fn entries_hinted_charges_cap_at_listing() {
    let dir = scratch("hinted_cap");
    for entry in ["a", "b", "c"] {
        std::fs::write(dir.join(entry), entry).unwrap();
    }
    let entry_cap = EntryCap::new(3).unwrap();
    let held = held(&dir);
    let at_cap = held.entries_hinted(entry_cap);
    assert!(
        matches!(at_cap, Ok(ref found) if found.len() == 3),
        "exactly the cap is listed, got {at_cap:?}"
    );
    std::fs::write(dir.join("d"), "d").unwrap();
    let past = held.entries_hinted(entry_cap);
    assert!(
        matches!(past, Err(OpenRefusal::TooManyEntries(at)) if at == entry_cap),
        "one past the cap is refused at the listing, got {past:?}"
    );
}

/// An over-cap directory of dangling links is refused by its listing; the cap is charged per listed entry.
#[cfg(unix)]
#[test]
fn entries_hinted_refuses_over_cap_at_listing() {
    let dir = scratch("hinted_cap_dangling");
    for entry in ["a", "b", "c"] {
        std::os::unix::fs::symlink(dir.join("absent"), dir.join(entry)).unwrap();
    }
    let held = held(&dir);
    let entry_cap = EntryCap::new(2).unwrap();
    let past = held.entries_hinted(entry_cap);
    assert!(
        matches!(past, Err(OpenRefusal::TooManyEntries(at)) if at == entry_cap),
        "an over-cap directory is refused by its listing, got {past:?}"
    );
}

/// An over-cap directory of dangling links is refused by `entries` before any entry is stat'ed.
#[cfg(unix)]
#[test]
fn entries_refuses_over_cap_before_classifying() {
    let dir = scratch("entries_cap_dangling");
    for entry in ["a", "b", "c"] {
        std::os::unix::fs::symlink(dir.join("absent"), dir.join(entry)).unwrap();
    }
    let held = held(&dir);
    let entry_cap = EntryCap::new(2).unwrap();
    let past = held.entries(entry_cap);
    assert!(
        matches!(past, Err(OpenRefusal::TooManyEntries(at)) if at == entry_cap),
        "an over-cap directory is refused by its listing, got {past:?}"
    );
}

/// A held directory removed from its parent is refused, never listed as empty.
#[cfg(target_os = "linux")]
#[test]
fn a_removed_held_directory_is_absent() {
    let dir = scratch("removed_held");
    std::fs::create_dir(dir.join("sub")).unwrap();
    let sub = held(&dir.join("sub"));
    std::fs::remove_dir(dir.join("sub")).unwrap();
    let entry_cap = EntryCap::new(4).unwrap();
    let hinted = sub.entries_hinted(entry_cap);
    assert!(
        matches!(hinted, Err(OpenRefusal::Absent)),
        "a removed directory is absent, got {hinted:?}"
    );
    let entries = sub.entries(entry_cap);
    assert!(
        matches!(entries, Err(OpenRefusal::Absent)),
        "a removed directory is absent to entries too, got {entries:?}"
    );
}

/// A dangling link a following stat would fail on is still typed from the directory entry.
#[cfg(unix)]
#[test]
fn entries_hinted_types_a_dangling_link_without_following() {
    let dir = scratch("hinted_no_stat");
    std::fs::create_dir(dir.join("sub")).unwrap();
    std::fs::write(dir.join("file"), "x").unwrap();
    std::os::unix::fs::symlink(dir.join("absent"), dir.join("gone")).unwrap();
    let held = held(&dir);
    let listed = held.entries_hinted(EntryCap::new(8).unwrap());
    assert!(
        matches!(listed, Ok(ref found) if found.len() == 3),
        "a directory with a dangling link still lists, got {listed:?}"
    );
    let Ok(listed) = listed else { return };
    for (entry, expected) in [
        ("sub", HintedKind::Dir),
        ("file", HintedKind::Regular),
        ("gone", HintedKind::Link),
    ] {
        let hint = hinted_kind_of(&listed, entry);
        assert!(
            hint == Some(expected) || hint == Some(HintedKind::Unknown),
            "{entry} is typed from the listing or left unknown, got {hint:?}"
        );
    }
}

/// A head read stops at its cap and leaves the proof usable for an identity re-read.
#[test]
fn a_head_read_stops_at_its_cap_and_keeps_the_handle() {
    let dir = scratch("read_head");
    std::fs::write(dir.join("f.txt"), "hello").unwrap();
    let held = held(&dir);
    let proven = held.open_regular(&name("f.txt")).unwrap();
    assert_eq!(proven.read_head(cap(2)).unwrap(), b"he");
    assert_eq!(
        proven.id().unwrap(),
        held.entry_id(&name("f.txt")).unwrap().unwrap()
    );
    let whole = held.open_regular(&name("f.txt")).unwrap();
    assert_eq!(whole.read_head(cap(64)).unwrap(), b"hello");
}

/// A raw handle is classified from itself.
#[test]
fn a_raw_handle_is_classified_from_itself() {
    let dir = scratch("kind_of_file");
    std::fs::write(dir.join("f.txt"), "x").unwrap();
    let file = std::fs::File::open(dir.join("f.txt")).unwrap();
    assert_eq!(super::kind_of_file(&file).unwrap(), FileKind::Regular);
}

#[cfg(unix)]
#[test]
fn entries_hinted_reports_a_symlink_as_link_and_resolves_unknown() {
    let dir = scratch("hinted_kinds");
    std::fs::create_dir(dir.join("sub")).unwrap();
    std::fs::write(dir.join("file"), "x").unwrap();
    std::os::unix::fs::symlink(dir.join("sub"), dir.join("to_dir")).unwrap();
    std::os::unix::fs::symlink(dir.join("nowhere"), dir.join("dangling")).unwrap();
    make_fifo(&dir.join("fifo"));
    let held = held(&dir);
    let listed = held.entries_hinted(EntryCap::new(16).unwrap());
    assert!(
        matches!(listed, Ok(ref found) if found.len() == 5),
        "every entry is listed, got {listed:?}"
    );
    let Ok(listed) = listed else { return };
    for (entry, expected_hint, expected_kind) in [
        ("sub", HintedKind::Dir, FileKind::Dir),
        ("file", HintedKind::Regular, FileKind::Regular),
        ("to_dir", HintedKind::Link, FileKind::Symlink),
        ("dangling", HintedKind::Link, FileKind::Symlink),
        ("fifo", HintedKind::Other, FileKind::Fifo),
    ] {
        let hint = hinted_kind_of(&listed, entry);
        assert!(
            hint == Some(expected_hint) || hint == Some(HintedKind::Unknown),
            "{entry} is {expected_hint:?} or unknown, got {hint:?}"
        );
        if hint == Some(HintedKind::Unknown) {
            let settled = held.kind_of(&name(entry));
            assert!(
                matches!(settled, Ok(Some(kind)) if kind == expected_kind),
                "{entry} unknown settles to {expected_kind:?}, got {settled:?}"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn kind_of_classifies_without_following() {
    let dir = scratch("unknown_kinds");
    std::fs::create_dir(dir.join("sub")).unwrap();
    std::fs::write(dir.join("file"), "x").unwrap();
    std::os::unix::fs::symlink(dir.join("sub"), dir.join("to_dir")).unwrap();
    let held = held(&dir);
    for (entry, expected) in [
        ("sub", Some(FileKind::Dir)),
        ("file", Some(FileKind::Regular)),
        ("to_dir", Some(FileKind::Symlink)),
        ("missing", None),
    ] {
        let kind = held.kind_of(&name(entry));
        assert!(
            matches!(kind, Ok(found) if found == expected),
            "{entry} is {expected:?}, got {kind:?}"
        );
    }
}

/// A reparse point is a link whatever else its attributes say, never a directory.
#[cfg(windows)]
#[test]
fn entries_hinted_reports_reparse_as_link() {
    use super::sys::hint_of_attributes;
    const DIRECTORY: u32 = 0x10;
    const REPARSE_POINT: u32 = 0x400;
    const ARCHIVE: u32 = 0x20;
    const DEVICE: u32 = 0x40;
    assert_eq!(
        hint_of_attributes(DIRECTORY | REPARSE_POINT),
        HintedKind::Link
    );
    assert_eq!(hint_of_attributes(REPARSE_POINT), HintedKind::Link);
    assert_eq!(hint_of_attributes(DIRECTORY), HintedKind::Dir);
    assert_eq!(hint_of_attributes(ARCHIVE), HintedKind::Regular);
    assert_eq!(hint_of_attributes(DEVICE), HintedKind::Other);

    let dir = scratch("hinted_junction");
    std::fs::create_dir(dir.join("real")).unwrap();
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(dir.join("junction"))
        .arg(dir.join("real"))
        .status()
        .unwrap();
    assert!(made.success(), "mklink /J creates the junction fixture");
    let listed = held(&dir).entries_hinted(EntryCap::new(8).unwrap());
    assert!(
        matches!(listed, Ok(ref found) if found.len() == 2),
        "both entries are listed, got {listed:?}"
    );
    let Ok(listed) = listed else { return };
    assert_eq!(
        hinted_kind_of(&listed, "junction"),
        Some(HintedKind::Link),
        "a junction is never reported as a directory"
    );
    assert_eq!(hinted_kind_of(&listed, "real"), Some(HintedKind::Dir));
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
