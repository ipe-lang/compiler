//! The capability notice of a program that lists trusted frame origins.
//!
//! A trusted frame reaches whatever its `allow` list delegates, and an
//! `allow` value can be computed at runtime, so the inferred capability list
//! cannot show which `Undisclosed` features a frame is given. The notice keys
//! on the one fact a build knows: the manifest lists at least one frame
//! origin.

use ipe_runtime_rust::encoding::{FrameOriginEntries, FrameOriginEntry};
use ipe_runtime_rust::frames::{DELEGATION_FEATURES, DelegationFeature, FeatureClass};

/// The notice's opening words, before the listed origins.
const NOTICE_LEAD: &str = "This app lists trusted frame origins";

/// The notice's words before the delegable features.
const NOTICE_FEATURES: &str = "A page can give a trusted frame access to";

/// The notice's closing sentence.
const NOTICE_TAIL: &str =
    "The capability list cannot show whether this program reaches them through a frame.";

/// The text `docs/guide/package.md` writes where the notice names the
/// listed origins.
pub const ORIGINS_PLACEHOLDER: &str = "<origins>";

/// The reach a program's trusted frame origins give a page: present only for
/// a non-empty `delivery.frameOrigins`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameReach {
    /// The written origins, in the list's order; never empty.
    origins: Vec<String>,
}

impl FrameReach {
    /// The reach of `entries`, or `None` when the list is empty.
    #[must_use]
    pub fn of(entries: &FrameOriginEntries) -> Option<Self> {
        let origins: Vec<String> = entries.entries().map(written).collect();
        (!origins.is_empty()).then_some(Self { origins })
    }

    /// The written origins, in the list's order.
    #[must_use]
    pub fn origins(&self) -> &[String] {
        &self.origins
    }

    /// The `Undisclosed` delegation features, in table order.
    pub fn undisclosed() -> impl Iterator<Item = &'static DelegationFeature> {
        DELEGATION_FEATURES
            .iter()
            .filter(|row| matches!(row.class, FeatureClass::Undisclosed))
    }

    /// The notice naming this reach's origins.
    #[must_use]
    pub fn notice(&self) -> String {
        notice_naming(&self.origins.join(", "))
    }
}

/// One program of a project as a frame report names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameProgram {
    /// The program's name, as `package.ipe` writes it.
    name: String,
    /// The entry file, `src/<Module/Path>.ipe`; its segments are module
    /// segments, so it holds no line break or control character.
    file: String,
}

impl FrameProgram {
    /// The program `name` whose entry module is `module`.
    #[must_use]
    pub fn new(name: &str, module: &[String]) -> Self {
        Self {
            name: name.to_owned(),
            file: format!("src/{}.ipe", module.join("/")),
        }
    }

    /// The program's name, as `package.ipe` writes it.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The entry file, `src/<Module/Path>.ipe`.
    #[must_use]
    pub fn file(&self) -> &str {
        &self.file
    }
}

/// What a capability report says of the project's frame list, which applies
/// to the one program a build compiles and to no other.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameReport {
    /// The built program is among the analysed ones: the list gives its
    /// pages `reach`, and applies to none of `not_applicable`.
    Applies {
        /// The reach the list gives the built program's pages.
        reach: FrameReach,
        /// The program a build compiles.
        built: FrameProgram,
        /// Every other analysed program, in declared order.
        not_applicable: Vec<FrameProgram>,
    },
    /// No analysed program is the built one, so the list applies to none.
    NotApplicable {
        /// The program a build compiles.
        built: FrameProgram,
        /// The analysed programs, in declared order.
        analysed: crate::project_root::NonEmpty<FrameProgram>,
    },
}

impl FrameReport {
    /// The report of `reach` over the `analysed` programs when a build
    /// compiles `built`; `None` when nothing is analysed.
    #[must_use]
    pub fn of(reach: FrameReach, built: FrameProgram, analysed: Vec<FrameProgram>) -> Option<Self> {
        if analysed.contains(&built) {
            let not_applicable = analysed
                .into_iter()
                .filter(|program| *program != built)
                .collect();
            return Some(Self::Applies {
                reach,
                built,
                not_applicable,
            });
        }
        crate::project_root::NonEmpty::from_vec(analysed)
            .map(|analysed| Self::NotApplicable { built, analysed })
    }

    /// The reach the list gives an analysed program; `None` when it applies
    /// to none of them.
    #[must_use]
    pub const fn reach(&self) -> Option<&FrameReach> {
        match self {
            Self::Applies { reach, .. } => Some(reach),
            Self::NotApplicable { .. } => None,
        }
    }

    /// The program a build compiles, the one the list applies to.
    #[must_use]
    pub const fn built(&self) -> &FrameProgram {
        match self {
            Self::Applies { built, .. } | Self::NotApplicable { built, .. } => built,
        }
    }

    /// The analysed programs the list does not apply to, in declared order.
    #[must_use]
    pub fn not_applicable(&self) -> Vec<&FrameProgram> {
        match self {
            Self::Applies { not_applicable, .. } => not_applicable.iter().collect(),
            Self::NotApplicable { analysed, .. } => analysed.iter().collect(),
        }
    }
}

/// The written form of `entry`.
fn written(entry: &FrameOriginEntry) -> String {
    let mut out = String::with_capacity(entry.written_len());
    entry.write(&mut out);
    out
}

/// A feature's display name as a sentence names it: the first letter is
/// lowered unless the name opens with an acronym.
fn in_sentence(display: &str) -> String {
    let mut chars = display.chars();
    match (chars.next(), chars.next()) {
        (Some(first), Some(second)) if second.is_lowercase() || second == ' ' => {
            let mut out = first.to_lowercase().collect::<String>();
            out.push(second);
            out.push_str(chars.as_str());
            out
        }
        _ => display.to_owned(),
    }
}

/// The notice text with `origins` where the listed origins are named.
#[must_use]
pub fn notice_naming(origins: &str) -> String {
    let features: Vec<String> = FrameReach::undisclosed()
        .map(|row| in_sentence(row.display))
        .collect();
    let phrase = match features.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{}, and {last}", rest.join(", ")),
        Some((last, _)) => last.clone(),
        None => String::new(),
    };
    format!("{NOTICE_LEAD} (`{origins}`). {NOTICE_FEATURES} {phrase}. {NOTICE_TAIL}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The entries of `texts`, each a well-formed frame origin.
    #[allow(clippy::expect_used)] // every vector is a well-formed origin
    fn entries(texts: &[&str]) -> FrameOriginEntries {
        FrameOriginEntries::new(
            texts
                .iter()
                .map(|text| FrameOriginEntry::parse(text).expect("a frame origin")),
        )
        .expect("a frame list")
    }

    /// R29: the reach exists only for a listed origin; its features are the
    /// `Undisclosed` rows in table order; the notice names every origin and
    /// every row's display name.
    #[test]
    fn frame_reach_exists_only_for_a_listed_origin() {
        assert_eq!(FrameReach::of(&FrameOriginEntries::none()), None);
        assert_eq!(FrameReach::of(&entries(&[])), None);
        let one = FrameReach::of(&entries(&["https://player.example"]));
        assert!(one.is_some(), "one listed origin has a reach");
        let Some(one) = one else { return };
        assert_eq!(one.origins(), ["https://player.example"]);
        let names: Vec<&str> = FrameReach::undisclosed().map(|row| row.name).collect();
        let table: Vec<&str> = DELEGATION_FEATURES
            .iter()
            .filter(|row| matches!(row.class, FeatureClass::Undisclosed))
            .map(|row| row.name)
            .collect();
        assert_eq!(names, table);
        assert!(!names.is_empty());
        let two = FrameReach::of(&entries(&["https://b.example", "http://localhost:3000"]));
        assert!(two.is_some(), "two listed origins have a reach");
        let Some(two) = two else { return };
        let notice = two.notice();
        for origin in two.origins() {
            assert!(notice.contains(origin.as_str()), "{origin}: {notice}");
        }
        assert_eq!(two.origins().len(), 2);
        let lowered = notice.to_lowercase();
        for row in FrameReach::undisclosed() {
            assert!(
                lowered.contains(&row.display.to_lowercase()),
                "{}: {notice}",
                row.display
            );
        }
        assert!(!notice.contains("pure"), "{notice}");
    }

    /// DP-12: the list applies to the built program only. An analysed set
    /// holding it carries the reach and marks every other program not
    /// applicable; a set without it carries no reach at all; an empty set
    /// has no report.
    #[test]
    fn frame_report_applies_to_the_built_program_only() {
        let reach = FrameReach::of(&entries(&["https://player.example"]));
        assert!(reach.is_some());
        let Some(reach) = reach else { return };
        let module = |path: &[&str]| path.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let web = FrameProgram::new("web", &module(&["Web", "Main"]));
        let cli = FrameProgram::new("cli", &module(&["Cli"]));
        assert_eq!(web.file(), "src/Web/Main.ipe");
        let both = FrameReport::of(reach.clone(), web.clone(), vec![web.clone(), cli.clone()]);
        assert!(both.is_some());
        let Some(both) = both else { return };
        assert_eq!(both.reach(), Some(&reach));
        assert_eq!(both.built(), &web);
        assert_eq!(both.not_applicable(), vec![&cli]);
        let only_cli = FrameReport::of(reach.clone(), web.clone(), vec![cli.clone()]);
        assert!(only_cli.is_some());
        let Some(only_cli) = only_cli else { return };
        assert_eq!(only_cli.reach(), None);
        assert_eq!(only_cli.built(), &web);
        assert_eq!(only_cli.not_applicable(), vec![&cli]);
        assert_eq!(FrameReport::of(reach, web, Vec::new()), None);
    }

    /// The repository root this crate was built from.
    fn repo_root() -> Option<&'static std::path::Path> {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
    }

    /// R32: the `frame-reach-notice` block of `docs/guide/package.md` is the
    /// notice with the origins placeholder, between exactly one marker pair.
    #[test]
    fn package_guide_carries_the_frame_reach_notice() {
        const BEGIN: &str = "<!-- frame-reach-notice:begin -->";
        const END: &str = "<!-- frame-reach-notice:end -->";
        let root = repo_root();
        assert!(root.is_some(), "src/ipe-cli has a repo root two levels up");
        let Some(root) = root else { return };
        let path = root.join("docs/guide/package.md");
        let doc = std::fs::read_to_string(&path);
        assert!(doc.is_ok(), "{} reads", path.display());
        let Ok(doc) = doc else { return };
        assert_eq!(doc.matches(BEGIN).count(), 1, "one opening marker");
        assert_eq!(doc.matches(END).count(), 1, "one closing marker");
        let block = doc
            .split_once(BEGIN)
            .and_then(|(_, rest)| rest.split_once(END))
            .map(|(block, _)| block.split_whitespace().collect::<Vec<_>>().join(" "));
        assert_eq!(
            block,
            Some(notice_naming(ORIGINS_PLACEHOLDER)),
            "docs/guide/package.md's frame-reach-notice block drifted from the notice"
        );
    }
}
