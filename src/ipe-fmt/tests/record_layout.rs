//! Exact outputs for nested record layout.
//!
//! A multi-line record nested as a field value prints below its `=`, one tab
//! stop past the field, with its own fields aligned under its own brace, so the
//! printed indentation states which record each field belongs to.

/// Assert `src` formats to exactly `expected`, and `expected` to itself.
#[allow(clippy::expect_used)] // a refusal is the failure these tests report
fn golden(src: &str, expected: &str) {
    let once = ipe_fmt::format_source(src).expect("formats");
    assert_eq!(once, expected, "output differs for:\n{src}");
    let twice = ipe_fmt::format_source(&once).expect("second pass formats");
    assert_eq!(twice, once, "not a fixed point:\n{once}");
}

/// The scaffolded manifest's layout, already canonical.
const MANIFEST: &str = "module Package exposing (package)

import Ipe.Package exposing (..)


package : Package
package =
    { name = \"t1\"
    , version = \"0.1.0\"
    , delivery =
        { desktop = { title = \"t1\", width = 1024, height = 768 }
        , mobile = { bundleId = \"com.example.t1\", orientation = Any }
        , browser = { basePath = \"/\" }
        }
    }
";

#[test]
fn nested_record_is_its_own_fixed_point() {
    golden(MANIFEST, MANIFEST);
}

/// A nested record opened on its field's line drops below the `=`; its
/// fields never print at the outer record's indentation.
#[test]
fn nested_record_opened_on_the_field_line_indents_under_its_field() {
    let src = "module Package exposing (package)

import Ipe.Package exposing (..)


package : Package
package =
    { name = \"t1\"
    , version = \"0.1.0\"
    , delivery = { desktop = { title = \"t1\", width = 1024, height = 768 }
                 , mobile = { bundleId = \"com.example.t1\", orientation = Any }
                 , browser = { basePath = \"/\" }
                 }
    }
";
    golden(src, MANIFEST);
}

/// Every level of a deeper nest, and a nested record update, indents under its
/// own field.
#[test]
fn every_nesting_level_indents_under_its_field() {
    let src = "module M exposing (r)


r =
    { a = 1
    , b = { c = { d = 2
                , e = 3
                }
          , f = 4
          }
    , g = { model | h = { i = 5
                        , j = 6
                        } }
    }
";
    let expected = "module M exposing (r)


r =
    { a = 1
    , b =
        { c =
            { d = 2
            , e = 3
            }
        , f = 4
        }
    , g =
        { model
            | h =
                { i = 5
                , j = 6
                }
        }
    }
";
    golden(src, expected);
}
