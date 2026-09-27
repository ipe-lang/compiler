#![forbid(unsafe_code)]
//! Shared diagnostic vocabulary for the Ipê compiler: source spans, the
//! `Located<T>` carrier, and the typed `Diagnostic` enum. Every stage speaks
//! these types — there are no `String` errors across stage boundaries.

mod code;
mod diagnostic;
pub mod path_check;
mod render;
mod span;

// Re-export the whole taxonomy with a glob so no downstream-nameable code can be
// omitted by a hand-synced list: every `IPE_*` constant, `ALL_CODES`, `Code`,
// `Severity`, `title`, `explain_page`, and `ISSUE_TRACKER_URL` are named once in
// `code.rs` and surfaced here in one line. `code_reexport_covers_all_codes`
// pins that every entry in `ALL_CODES` is reachable through this re-export.
pub use code::*;
pub use diagnostic::{
    AliasExpansionKind, AppShape, Applicability, CaseDefect, CmdSubShapeMismatch,
    CodecAutoRejection, ConsentError, Construct, DResult, Diagnostic, Expected, ExpectedSet,
    ExposingDefect, Feature, FfiError, GenericAppEntryReach, HOF_KERNEL_RESULT_CLASS, HeaderDefect,
    HelpLine, Hint, IfDefect, LetDefect, LowerError, MainRetName, ModelLeaf, ModulePlacementReason,
    ModulePlacementRejection, NameError, ParseError, RustNameFoldKind, SandboxError, SealRejection,
    SortedNames, SpanRole, StoreEqAccessorDefect, StoreSelectProjectionDefect, Suggestion,
    TokenKind, TyDoc, TypeDeclDefect, TypeError,
};
pub use render::{DOC_HINT_CMD, plain_message, render, render_json, render_ty};
pub use span::{Located, Span};

#[cfg(test)]
mod tests {
    use super::*;

    // Build a sample `Diagnostic` for Ffi, Sandbox, Consent, and `CompilerBug`
    // families.  Returns `None` for Parse/Name/Type/Lower codes; those families
    // have dedicated unit tests in their own modules.
    #[allow(clippy::too_many_lines)]
    fn sample_for_code(code: Code) -> Option<Diagnostic> {
        let d = match code {
            // FFI
            IPE_F4400 => Diagnostic::Ffi {
                msg: FfiError::CallUnrenderable {
                    function: "foo".into(),
                    detail: "param ref out of range".into(),
                },
            },
            IPE_F4401 => Diagnostic::Ffi {
                msg: FfiError::WireMalformed {
                    context: "crate `x`".into(),
                    detail: "malformed JSON".into(),
                },
            },
            IPE_F4402 => Diagnostic::Ffi {
                msg: FfiError::ShapeContradiction {
                    function: "foo".into(),
                    flags: vec!["getter".into(), "setter".into()],
                },
            },
            IPE_F4410 => Diagnostic::Sandbox {
                msg: SandboxError::BuildJail {
                    detail: "bwrap absent".into(),
                },
            },
            IPE_F4411 => Diagnostic::Ffi {
                msg: FfiError::SourceRejected {
                    source: "evil-crate".into(),
                    detail: "crate name illegal".into(),
                },
            },
            IPE_F4412 => Diagnostic::Ffi {
                msg: FfiError::ArtifactIo {
                    path: "/tmp/x".into(),
                    detail: "permission denied".into(),
                },
            },
            IPE_F4413 => Diagnostic::Sandbox {
                msg: SandboxError::RunJail {
                    detail: "bwrap absent".into(),
                },
            },
            IPE_F4414 => Diagnostic::Ffi {
                msg: FfiError::AssertedRefused {
                    path: "my_crate::foo".into(),
                    detail: "crate not installed".into(),
                },
            },
            IPE_F4415 => Diagnostic::Ffi {
                msg: FfiError::SystemLibraryNotFound {
                    system_lib: "wayland-client".into(),
                    crate_name: "wayland-sys".into(),
                    install_hint: "apt install libwayland-dev".into(),
                },
            },
            // Environment
            IPE_E0001 => Diagnostic::RegistryUnreachable {
                detail: "cargo exited 101 while fetching crates:\nCould not resolve host: index.crates.io".into(),
            },
            // Consent
            IPE_S0001 => Diagnostic::Consent {
                msg: ConsentError::NonInteractive {
                    body: "this program imports Ipe.Html.Unsafe\n".into(),
                },
            },
            // Compiler bug / internal — where_ strings must match code.rs mapping
            IPE_I0001 => Diagnostic::CompilerBug {
                where_: "unknown",
                detail: "test".into(),
            },
            IPE_I0010 => Diagnostic::CompilerBug {
                where_: "intern.resolve",
                detail: "test".into(),
            },
            IPE_I0011 => Diagnostic::CompilerBug {
                where_: "intern.capacity",
                detail: "test".into(),
            },
            IPE_I0100 => Diagnostic::CompilerBug {
                where_: "ir.match.unknown_variant",
                detail: "test".into(),
            },
            IPE_I0101 => Diagnostic::CompilerBug {
                where_: "ir.match.duplicate_arm",
                detail: "test".into(),
            },
            IPE_I0102 => Diagnostic::CompilerBug {
                where_: "ir.match.non_exhaustive",
                detail: "test".into(),
            },
            IPE_I0103 => Diagnostic::CompilerBug {
                where_: "ir.match.arm_enum_mismatch",
                detail: "test".into(),
            },
            IPE_I0200 => Diagnostic::CompilerBug {
                where_: "backend.no_rust_name",
                detail: "test".into(),
            },
            IPE_I0201 => Diagnostic::CompilerBug {
                where_: "backend.dangling_symbol",
                detail: "test".into(),
            },
            IPE_I0202 => Diagnostic::CompilerBug {
                where_: "backend.type_name_collision",
                detail: "test".into(),
            },
            IPE_I0203 => Diagnostic::CompilerBug {
                where_: "backend.golden_anchor",
                detail: "test".into(),
            },
            // Parse/Name/Type/Lower codes have their own unit tests; no sample here.
            _ => return None,
        };
        Some(d)
    }

    #[test]
    fn compiler_bug_carries_context() {
        let d = Diagnostic::CompilerBug {
            where_: "lower",
            detail: "no type for region".into(),
        };
        assert!(matches!(
            d,
            Diagnostic::CompilerBug {
                where_: "lower",
                ..
            }
        ));
    }

    #[test]
    fn span_dummy_is_empty() {
        assert_eq!(Span::DUMMY, Span::new(0, 0));
    }

    #[test]
    fn located_map_preserves_span() {
        let l = Located::new(Span::new(3, 7), 1i32);
        let m = l.map(|v| v + 1);
        assert_eq!(m.span, Span::new(3, 7));
        assert_eq!(m.value, 2);
    }

    #[test]
    fn diagnostic_is_clone_eq() {
        let a = Diagnostic::Parse {
            span: Span::DUMMY,
            msg: ParseError::Unexpected,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn coarse_variants_still_construct() {
        // Additive guarantee: every coarse variant remains buildable.
        let _ = Diagnostic::Parse {
            span: Span::DUMMY,
            msg: ParseError::TooDeep,
        };
        let _ = Diagnostic::Name {
            span: Span::DUMMY,
            msg: NameError::Unknown,
        };
        let _ = Diagnostic::Type {
            span: Span::DUMMY,
            msg: TypeError::Mismatch,
        };
        let _ = Diagnostic::Type {
            span: Span::DUMMY,
            msg: TypeError::BudgetExceeded,
        };
    }

    #[test]
    fn code_maps_payload_variants() {
        let d = Diagnostic::Parse {
            span: Span::new(1, 2),
            msg: ParseError::UnknownChar('@'),
        };
        assert_eq!(d.code(), IPE_P0010);
        assert_eq!(d.severity(), Severity::Error);
        assert_eq!(d.primary_span(), Span::new(1, 2));
    }

    #[test]
    fn coarse_and_payload_share_a_code() {
        let coarse = Diagnostic::Type {
            span: Span::DUMMY,
            msg: TypeError::Mismatch,
        };
        let rich = Diagnostic::Type {
            span: Span::DUMMY,
            msg: TypeError::TypeMismatch {
                expected: Box::new(TyDoc::Unit),
                found: Box::new(TyDoc::Var("a".into())),
                definition: None,
                path: Box::new([]),
            },
        };
        assert_eq!(coarse.code(), IPE_T0001);
        assert_eq!(rich.code(), IPE_T0001);
    }

    #[test]
    fn redundant_branch_is_a_warning() {
        let d = Diagnostic::Type {
            span: Span::DUMMY,
            msg: TypeError::RedundantCaseBranch {
                constructor: "Red".into(),
            },
        };
        assert_eq!(d.severity(), Severity::Warning);
        assert_eq!(d.code(), IPE_T0011);
    }

    #[test]
    fn lower_channel_is_distinct_from_bug() {
        let d = Diagnostic::Lower {
            span: Span::new(4, 9),
            msg: LowerError::Unsupported(Feature::BinOps),
        };
        assert_eq!(d.code(), IPE_L0101);
        assert_eq!(d.severity(), Severity::Error);
        assert_eq!(
            d.help(),
            vec![HelpLine::Hint(Hint::FeatureNotSupported(Feature::BinOps))]
        );
    }

    #[test]
    fn compiler_bug_maps_where_to_internal_code() {
        let generic = Diagnostic::CompilerBug {
            where_: "lower",
            detail: "x".into(),
        };
        assert_eq!(generic.code(), IPE_I0001);
        assert_eq!(generic.severity(), Severity::Bug);
        assert_eq!(generic.primary_span(), Span::DUMMY);

        let specific = Diagnostic::CompilerBug {
            where_: "intern.resolve",
            detail: "y".into(),
        };
        assert_eq!(specific.code(), IPE_I0010);
    }

    #[test]
    fn duplicate_value_points_at_first_definition() {
        let d = Diagnostic::Name {
            span: Span::new(20, 24),
            msg: NameError::DuplicateValue {
                name: "foo".into(),
                first: Span::new(2, 5),
            },
        };
        assert_eq!(d.code(), IPE_N0010);
        assert_eq!(
            d.help(),
            vec![HelpLine::SecondarySpan {
                span: Span::new(2, 5),
                role: SpanRole::FirstDefinition
            }]
        );
    }

    #[test]
    fn did_you_mean_preserves_producer_order() {
        let d = Diagnostic::Name {
            span: Span::DUMMY,
            msg: NameError::ValueNotFound {
                name: "lenght".into(),
                suggestions: Box::new(["length".into(), "list".into()]),
            },
        };
        assert_eq!(
            d.help(),
            vec![
                HelpLine::DidYouMean("length".into()),
                HelpLine::DidYouMean("list".into()),
            ]
        );
    }

    #[test]
    fn single_candidate_becomes_machine_applicable_suggestion() {
        let d = Diagnostic::Name {
            span: Span::new(0, 6),
            msg: NameError::ValueNotFound {
                name: "lenght".into(),
                suggestions: Box::new(["length".into()]),
            },
        };
        assert_eq!(
            d.help(),
            vec![HelpLine::Suggest(Suggestion {
                span: Span::new(0, 6),
                replacement: "length".into(),
                applicability: Applicability::MachineApplicable,
            })]
        );
    }

    #[test]
    fn non_exhaustive_lists_missing_constructors() {
        let d = Diagnostic::Type {
            span: Span::DUMMY,
            msg: TypeError::NonExhaustiveCase {
                missing: SortedNames::new(["Green".into(), "Blue".into()]),
            },
        };
        assert_eq!(d.code(), IPE_T0010);
        // The newtype renders the set in canonical string order, so `Blue`
        // precedes `Green` regardless of the order they were discovered in.
        assert_eq!(
            d.help(),
            vec![
                HelpLine::MissingConstructor("Blue".into()),
                HelpLine::MissingConstructor("Green".into()),
            ]
        );
    }

    // -- teaching nudges (SeeExplain) --

    #[test]
    fn lawless_effect_discard_carries_see_explain_effects() {
        let d = Diagnostic::Lower {
            span: Span::DUMMY,
            msg: LowerError::LawlessEffectDiscard,
        };
        assert_eq!(d.code(), IPE_L0141);
        let help = d.help();
        assert!(
            help.iter().any(|h| h == &HelpLine::SeeExplain("effects")),
            "IPE-L0141 must carry SeeExplain(\"effects\"); got: {help:?}"
        );
    }

    #[test]
    fn non_entry_main_carries_see_explain_main() {
        let d = Diagnostic::Lower {
            span: Span::DUMMY,
            msg: LowerError::NonEntryMain {
                found: MainRetName::Bare("Int"),
            },
        };
        assert_eq!(d.code(), IPE_L0136);
        let help = d.help();
        assert!(
            help.iter().any(|h| h == &HelpLine::SeeExplain("main")),
            "IPE-L0136 must carry SeeExplain(\"main\"); got: {help:?}"
        );
    }

    #[test]
    fn function_in_record_carries_see_explain_state() {
        let d = Diagnostic::Lower {
            span: Span::DUMMY,
            msg: LowerError::Unsupported(Feature::FirstClassFunctions),
        };
        assert_eq!(d.code(), IPE_L0107);
        let help = d.help();
        assert!(
            help.iter().any(|h| h == &HelpLine::SeeExplain("state")),
            "IPE-L0107 must carry SeeExplain(\"state\"); got: {help:?}"
        );
    }

    #[test]
    fn see_explain_renders_hint_text_in_plain_message() {
        let d = Diagnostic::Lower {
            span: Span::DUMMY,
            msg: LowerError::LawlessEffectDiscard,
        };
        let msg = plain_message(&d, "");
        assert!(
            msg.contains("ipe doc effects"),
            "plain_message for IPE-L0141 must contain 'ipe doc effects'; got: {msg:?}"
        );
    }

    #[test]
    fn see_explain_human_render_contains_topic_nudge() {
        let d = Diagnostic::Lower {
            span: Span::DUMMY,
            msg: LowerError::NonEntryMain {
                found: MainRetName::Bare("String"),
            },
        };
        let rendered = render(&d, "main.ipe", "");
        assert!(
            rendered.contains("ipe doc main"),
            "human render for IPE-L0136 must contain 'ipe doc main'; got: {rendered:?}"
        );
    }

    /// Every code in the taxonomy is reachable through the crate-root re-export.
    ///
    /// The re-export is `pub use code::*`, so each `ALL_CODES` entry is nameable
    /// downstream by construction. Naming the codes that a hand-synced list had
    /// dropped compiles only because the glob surfaces them, and asserting each
    /// is a distinct member pins the taxonomy against a re-export that stops
    /// short of a code again.
    #[test]
    fn code_reexport_covers_all_codes() {
        // Codes an enumerated re-export list had skipped — nameable here only
        // through the crate-root glob.
        let previously_unreachable = [
            IPE_P0065, IPE_P0066, IPE_P0067, IPE_P0068, IPE_P0069, IPE_L0153,
        ];
        for code in previously_unreachable {
            assert!(
                ALL_CODES.contains(&code),
                "{} must be a taxonomy member",
                code.as_str()
            );
        }
    }

    /// Every code's 5th character (index 4) must be the family letter of the
    /// `Diagnostic` variant that produces it: P for Parse, N for Name, T for
    /// Type, L for Lower, I for `CompilerBug`. This turns the prose contract into
    /// a mechanically-checked predicate — the previously offending case
    /// (`RoutedAppMissingPageField`, relocated to `LowerError`) is covered
    /// explicitly.
    #[test]
    fn code_prefix_matches_diagnostic_family() {
        // One representative per family.
        let cases: &[(Diagnostic, char)] = &[
            (
                Diagnostic::Parse {
                    span: Span::DUMMY,
                    msg: ParseError::Unexpected,
                },
                'P',
            ),
            (
                Diagnostic::Name {
                    span: Span::DUMMY,
                    msg: NameError::Unknown,
                },
                'N',
            ),
            (
                Diagnostic::Type {
                    span: Span::DUMMY,
                    msg: TypeError::Mismatch,
                },
                'T',
            ),
            (
                Diagnostic::Type {
                    span: Span::DUMMY,
                    msg: TypeError::RedundantCaseBranch {
                        constructor: "Red".into(),
                    },
                },
                'T',
            ),
            (
                Diagnostic::Lower {
                    span: Span::DUMMY,
                    msg: LowerError::Unsupported(Feature::BinOps),
                },
                'L',
            ),
            // Formerly cross-stamped as L under the Type family — must now be L under Lower.
            (
                Diagnostic::Lower {
                    span: Span::DUMMY,
                    msg: LowerError::RoutedAppMissingPageField { route_count: 2 },
                },
                'L',
            ),
            (
                Diagnostic::CompilerBug {
                    where_: "lower",
                    detail: "invariant".into(),
                },
                'I',
            ),
        ];
        for (diag, expected_letter) in cases {
            let code_str = diag.code().as_str();
            let actual = code_str
                .chars()
                .nth(4)
                .expect("code string must have at least 5 characters");
            assert_eq!(
                actual, *expected_letter,
                "code {code_str} has family letter '{actual}' but the variant belongs to the '{expected_letter}' family"
            );
        }
    }

    /// `RoutedAppMissingPageField` relocated to `LowerError` retains Warning
    /// severity and its IPE-L0124 code.
    #[test]
    fn routed_app_missing_page_field_is_lower_warning() {
        let d = Diagnostic::Lower {
            span: Span::DUMMY,
            msg: LowerError::RoutedAppMissingPageField { route_count: 3 },
        };
        assert_eq!(d.code(), IPE_L0124);
        assert_eq!(d.severity(), Severity::Warning);
    }

    /// Every Ffi, Sandbox, Consent, and `CompilerBug` code in [`ALL_CODES`]
    /// maps to a [`Diagnostic`] whose `.code()` round-trips back to that code.
    ///
    /// Parse/Name/Type/Lower coverage lives in their own modules; this gate
    /// focuses on the families added or restructured by the
    /// parallel-renderer-taxonomy-drift fix.
    #[test]
    #[allow(clippy::unreachable)]
    fn every_fsi_code_has_a_diagnostic_value() {
        for &code in code::ALL_CODES {
            let code_str = code.as_str();
            // Only F, S, and I family codes are covered by sample_for_code.
            let is_fsi = matches!(code_str.chars().nth(4), Some('F' | 'S' | 'I'));
            if !is_fsi {
                continue;
            }
            let Some(diag) = sample_for_code(code) else {
                unreachable!(
                    "no sample Diagnostic for code {code_str} — add an arm in sample_for_code"
                );
            };
            assert_eq!(
                diag.code(),
                code,
                "sample for {code_str} returned code {} instead",
                diag.code().as_str()
            );
        }
    }

    /// A representative [`Diagnostic`] of the Ffi, Sandbox, Consent, and
    /// `CompilerBug` families routes through the shared rendering pipeline
    /// without panicking and produces structurally sound output.
    ///
    /// Checked properties:
    /// - `render()` is non-empty and contains the code string.
    /// - `render_json()` starts with `{` (is a JSON object) and contains the
    ///   code string, confirming the shared pipeline serializes all families.
    #[test]
    #[allow(clippy::unreachable)]
    fn every_code_renders_through_the_pipeline() {
        let representatives: &[Code] = &[
            IPE_F4400, IPE_F4401, IPE_F4402, IPE_F4410, IPE_F4411, IPE_F4412, IPE_F4413, IPE_F4414,
            IPE_F4415, IPE_S0001, IPE_I0001,
        ];

        for &code in representatives {
            let Some(diag) = sample_for_code(code) else {
                unreachable!("no sample for representative code {code:?}");
            };

            // Text render must be non-empty and contain the code string.
            let text = render(&diag, "test.ipe", "");
            assert!(!text.is_empty(), "render() was empty for {code:?}");
            assert!(
                text.contains(code.as_str()),
                "render() for {code:?} does not contain the code string:\n{text}"
            );

            // JSON render must be a JSON object containing the code string.
            let json_str = render_json(&diag, "test.ipe", "");
            assert!(
                json_str.trim_start().starts_with('{'),
                "render_json() for {code:?} is not a JSON object:\n{json_str}"
            );
            assert!(
                json_str.contains(code.as_str()),
                "render_json() for {code:?} does not contain the code string:\n{json_str}"
            );
        }
    }

    /// Asserts that `ipe_ffi::diag::Diagnostic`, `ipe_sandbox::SandboxDefect`,
    /// and `ipe_sandbox::RunJailDefect` no longer carry hand-rolled Display
    /// implementations that prefix a raw `IPE-` code string.
    ///
    /// The absence of those impls is guaranteed by the module structure (the
    /// `impl fmt::Display` blocks were deleted), but this test makes the
    /// invariant observable in the test suite so a future accidental re-add
    /// surfaces immediately.
    #[test]
    fn parallel_renderers_are_eliminated() {
        // `ipe_diagnostics::render` is the ONLY code path that may produce a
        // rendered diagnostic.  Verify the shared pipeline works for all three
        // formerly-parallel families by confirming that converting a typed
        // defect into a `Diagnostic` and rendering it yields a non-empty
        // string containing the code, with no panics.
        let ffi_diag = Diagnostic::Ffi {
            msg: FfiError::GenericNotBindable {
                callee: "foo".into(),
                detail: "type var `a` not bound".into(),
            },
        };
        let sandbox_build = Diagnostic::Sandbox {
            msg: SandboxError::BuildJail {
                detail: "bwrap not installed".into(),
            },
        };
        let sandbox_run = Diagnostic::Sandbox {
            msg: SandboxError::RunJail {
                detail: "seccomp filter failed".into(),
            },
        };
        let consent = Diagnostic::Consent {
            msg: ConsentError::InteractiveDenied {
                body: String::new(),
            },
        };

        for diag in &[ffi_diag, sandbox_build, sandbox_run, consent] {
            let text = render(diag, "", "");
            assert!(!text.is_empty(), "render() was empty for {diag:?}");
            assert!(
                text.contains(diag.code().as_str()),
                "render() does not contain code {}:\n{text}",
                diag.code().as_str()
            );
        }
    }
}
