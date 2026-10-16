//! SEAL: a use that leaves an `any`-returning helper's body variable open names `()` for it.
//!
//! `page : Int -> any` whose body is `Html.text "x"` lowers its return to a
//! generic over the body's message variable (`fn main_page<T1>(..) -> Html<T1>`)
//! so a caller can choose the message type. A use that renders the result
//! straight to a `String` never chooses one: the use's own node type lowers the
//! slot to `()`, so the emitted call must carry `::<()>` or rustc cannot infer
//! the generic (E0283) after ipe accepted the program. The same holds for a
//! non-UI constructor (`List v` from `[]`). A generic caller whose own `msg`
//! reaches the helper (`framed`, kept generic by `shown : Html Msg`) stays
//! unpinned.
//!
//! The emit gate asserts each pin; under `IPE_E2E=1` the emitted crate must
//! build and print every rendering.

use std::path::PathBuf;

const NAME: &str = "any_return_slot_pin";

const SOURCE: &str = r#"module Main exposing (main)

import Ipe.Html as Html
import Ipe.Io as Io
import Ipe.List as List
import Ipe.String as String


type Msg
    = Clicked


page : Int -> any
page n =
    Html.text "x"


empty : Int -> any
empty n =
    []


framed : Int -> Html msg
framed n =
    Html.div [] [ page n ]


shown : Html Msg
shown =
    framed 2


main : Task Error ()
main =
    Io.println
        (Html.render (page 1)
            ++ ","
            ++ Html.render shown
            ++ ","
            ++ String.fromInt (List.length (empty 3))
        )
"#;

/// The emitted calls whose `any`-return body variable this program leaves open.
const PINNED: [&str; 2] = ["main_page::<()>(", "main_empty::<()>("];

/// The call a generic caller makes: its own `msg` reaches `page`, so no pin.
const UNPINNED: &str = "crate::main_page(n)";

/// The program's stdout: each rendering, comma-separated.
const EXPECTED: &str = "x,<div>x</div>,0\n";

/// Write [`SOURCE`] as `src/Main.ipe` under a fresh scratch dir keyed by `suffix`, returning the entry.
fn write_entry(suffix: &str) -> Option<PathBuf> {
    let dir = crate::support::scratch_root().join(format!("ipec_{NAME}_{suffix}_src"));
    let _ = std::fs::remove_dir_all(&dir);
    let src = dir.join("src");
    std::fs::create_dir_all(&src).ok()?;
    let entry = src.join("Main.ipe");
    std::fs::write(&entry, SOURCE).ok()?;
    Some(entry)
}

/// Build the program into a fresh `out` dir, returning the emitted dir.
fn build(suffix: &str) -> PathBuf {
    let entry = write_entry(suffix);
    assert!(entry.is_some(), "{NAME}: scratch source setup failed");
    let out = crate::support::scratch_root().join(format!("ipec_{NAME}_{suffix}"));
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = entry.map(|entry| ipe::build_loose_file(&entry, &out, &runtime));
    assert!(
        matches!(built, Some(Ok(()))),
        "{NAME}: ipe dev build must accept the program, got: {built:?}"
    );
    out
}

/// Emit gate: every open body variable is pinned to `()`; a generic caller's use is not.
#[test]
fn any_return_slot_pin_emitted() {
    let out = build("emit");
    let emitted = crate::support::read_all_emitted_src(&out);
    for call in PINNED {
        assert!(
            emitted.contains(call),
            "{NAME}: a use leaving the body variable open must emit `{call}`; got:\n{emitted}"
        );
    }
    assert!(
        emitted.contains(UNPINNED),
        "{NAME}: a generic caller's use must stay unpinned as `{UNPINNED}`; got:\n{emitted}"
    );
}

/// THE SEAL: under `IPE_E2E=1` the emitted crate must `cargo build` and print every rendering.
#[test]
fn any_return_slot_pin_seal_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let out = build("e2e");
    let run = crate::support::build_and_run_emitted(NAME, &out);
    assert_eq!(
        run.exit_code,
        Some(0),
        "{NAME}: the emitted program must exit 0"
    );
    assert_eq!(run.stdout, EXPECTED, "{NAME}: stdout");
}
