//! Drift guard: the shell installer (`install.sh`) cannot import the
//! Rust `style` module, so it hand-mirrors the palette, the repository URL, and
//! the "report bugs" footer. This test reads the script and asserts those
//! mirrored values EQUAL the `style` SSOT constants — an unmirrored change to
//! either side fails CI. That enforced equality is how the shell "reuses" the
//! single source of truth: by test, not by trust.

use ipe::style::{self, Palette};

/// Read `install.sh` from the repository root (two levels up from this crate's
/// manifest). A read failure surfaces as a plain assertion carrying the path and
/// error — the empty string it returns then fails every `contains` check with a
/// clear message, never a silent pass.
fn install_script() -> String {
    let path = e2e_support::manifest_dir!().join("../../install.sh");
    let read = std::fs::read_to_string(&path);
    assert!(read.is_ok(), "could not read {}: {read:?}", path.display());
    read.unwrap_or_default()
}

/// The installer assigns each colour with `printf '\033[…m'`, whereas the Rust
/// palette carries the same escape as a literal `\x1b[…m`. Reduce a palette
/// field to the numeric+letter tail (`38;5;222m`) that both spellings share, so
/// the assertion compares the code itself, not its escape spelling.
fn ansi_tail(escape: &str) -> &str {
    escape.trim_start_matches('\x1b').trim_start_matches('[')
}

#[test]
fn installer_palette_mirrors_the_style_ssot() {
    let script = install_script();
    let color = &Palette::COLOR;

    // Each coloured field must appear in the script as a `printf '\033[<tail>'`
    // assignment. Checking the `\033[<tail>` fragment matches the script's own
    // spelling exactly while staying independent of which shell var holds it.
    for (name, escape) in [
        ("yellow", color.yellow),
        ("bright_yellow", color.bright_yellow),
        ("dim", color.dim),
        ("green", color.green),
        ("red", color.red),
        ("bold", color.bold),
        ("reset", color.reset),
    ] {
        let needle = format!("\\033[{}", ansi_tail(escape));
        assert!(
            script.contains(&needle),
            "install.sh must mirror the style `{name}` colour as `printf '{needle}'`"
        );
    }
}

#[test]
fn installer_mirrors_the_repo_url_and_bug_footer() {
    let script = install_script();

    // The installer builds the URL from `REPO="owner/repo"`; assert the SSOT
    // URL is exactly that GitHub base so the two cannot drift.
    let expected_repo = style::REPO_URL
        .strip_prefix("https://github.com/")
        .unwrap_or(style::REPO_URL);
    assert!(
        script.contains(&format!("REPO=\"{expected_repo}\"")),
        "install.sh REPO must equal the style REPO_URL path segment `{expected_repo}`"
    );

    // The success footer's fixed phrase must match the SSOT footer verbatim,
    // and the URL it points at must be the SSOT URL.
    let footer = style::report_bugs_footer();
    let phrase = "If you find any bugs, please report them at ";
    assert!(
        footer.starts_with(phrase),
        "the style footer phrase changed — update this test and install.sh"
    );
    assert!(
        script.contains(phrase),
        "install.sh must mirror the style footer phrase `{phrase}`"
    );
    assert!(
        footer.ends_with("/issues."),
        "the style footer must end at `{}/issues.`",
        style::REPO_URL
    );
    // The installer renders `.../$REPO/issues.` — assert the literal tail.
    assert!(
        script.contains("/issues."),
        "install.sh footer must point at the `/issues.` page"
    );
}

#[test]
fn installer_mirrors_the_spinner_frames() {
    let script = install_script();
    for frame in style::SPINNER_FRAMES {
        assert!(
            script.contains(frame),
            "install.sh spinner must include the style frame `{frame}`"
        );
    }
}

#[test]
fn installer_mirrors_the_status_glyphs_it_uses() {
    // The stage renderer leads a success outcome with `✓`, a failure outcome
    // with `✗`, and a soft-skip settle with the `•` step glyph. All three come
    // from the style SSOT; assert each appears in the script.
    let script = install_script();
    for (name, glyph) in [
        ("step", style::glyph::STEP),
        ("ok", style::glyph::OK),
        ("fail", style::glyph::FAIL),
    ] {
        assert!(
            script.contains(glyph),
            "install.sh must use the style `{name}` glyph `{glyph}`"
        );
    }
}

/// The GUTTER (2 spaces) must lead every human stage/banner/footer line in the
/// installer. These are the lines the install experience presents to the user as
/// a "frame"; a 4-space regression here made them visually inconsistent with the
/// CLI's guttered output.
///
/// The assertions check the rendered indent prefix in the `printf` call, not a
/// parsed AST — a character-level match is enough to catch a width regression
/// (4 spaces vs 2 spaces) without reimplementing a shell parser.
#[test]
fn installer_banner_success_and_footer_use_the_two_space_gutter() {
    let script = install_script();
    let gutter = style::GUTTER;

    // The stage success (`stage_ok`) and failure (`stage_fail`) helpers each
    // rewrite the running line in place: a carriage return, then the GUTTER, then
    // the colour placeholder and glyph — `'\r  %s✓…'` and `'\r  %s✗…'`.
    let ok_prefix = format!("'\\r{gutter}%s{}", style::glyph::OK);
    assert!(
        script.contains(&ok_prefix),
        "install.sh stage_ok must rewrite with the {}-space GUTTER before the ✓ glyph; \
         expected prefix `{ok_prefix}` in script",
        gutter.len()
    );

    let fail_prefix = format!("'\\r{gutter}%s{}", style::glyph::FAIL);
    assert!(
        script.contains(&fail_prefix),
        "install.sh stage_fail must rewrite with the {}-space GUTTER before the ✗ glyph; \
         expected prefix `{fail_prefix}` in script",
        gutter.len()
    );

    // The success banner and the "report bugs" footer both start with `\n  …`
    // (a leading newline then the GUTTER). Check the exact prefix so a width
    // change (4 spaces instead of 2) fails this assertion.
    let banner_prefix = format!("\\n{gutter}Ipê");
    assert!(
        script.contains(&banner_prefix),
        "install.sh success banner must be indented by the {}-space GUTTER; \
         expected `{banner_prefix}` in script",
        gutter.len()
    );

    let footer_prefix = format!("\\n{gutter}If you find any bugs");
    assert!(
        script.contains(&footer_prefix),
        "install.sh report-bugs footer must be indented by the {}-space GUTTER; \
         expected `{footer_prefix}` in script",
        gutter.len()
    );
}

/// The two install entry points must stay consistent: the README `curl … | sh`
/// one-liner and the `ipe upgrade` self-updater (`INSTALL_SH_URL`) must reference
/// the SAME URL, and it must point at the installer that actually exists at the
/// repository root. When `install.sh` moved under `tools/scripts/`, the README and
/// the upgrade URL kept pointing at the old path and silently 404'd — this test
/// replicates both entry points and fails if they drift apart again.
#[test]
fn install_entrypoints_agree_on_the_root_installer() {
    // 1. The installer lives at the repository root (short, easy-to-locate path).
    let script_path = e2e_support::manifest_dir!().join("../../install.sh");
    assert!(
        script_path.is_file(),
        "install.sh must live at the repository root: {}",
        script_path.display()
    );

    // 2. `ipe upgrade` curls exactly this URL — the real constant the command runs.
    let upgrade_url = ipe::INSTALL_SH_URL;
    assert!(
        upgrade_url.ends_with("/main/install.sh"),
        "ipe upgrade INSTALL_SH_URL must point at `main/install.sh`, got `{upgrade_url}`"
    );

    // 3. The README `curl … | sh` one-liner must curl that same URL — one source
    //    of truth shared by the fresh-install and self-update paths.
    let readme = std::fs::read_to_string(e2e_support::manifest_dir!().join("../../README.md"))
        .expect("README.md is readable");
    let curl_line = readme
        .lines()
        .find(|l| l.contains("curl") && l.contains("install.sh"))
        .expect("README must document a `curl … install.sh | sh` install command");
    assert!(
        curl_line.contains(upgrade_url),
        "the README curl one-liner must use the same URL as `ipe upgrade` (`{upgrade_url}`); \
         README line: `{}`",
        curl_line.trim()
    );
    assert!(
        curl_line.contains("| sh"),
        "the README install command must pipe the script into `sh`; line: `{}`",
        curl_line.trim()
    );
}

/// `run_installer` sets `IPE_UPGRADE_WRAPPED=1` so `install.sh` knows it was
/// launched by `ipe upgrade` itself (never a direct `curl | sh`) and can hand the
/// resolved tag back through the file named by `IPE_UPGRADE_TAG_FILE` instead of
/// printing its own now-redundant "no prebuilt binary" banner. Both env var names
/// are hand-mirrored as shell literals in `install.sh` and as the Rust
/// `UPGRADE_WRAPPED_ENV` / `UPGRADE_TAG_FILE_ENV` constants — assert they agree
/// so a rename on either side fails CI instead of silently breaking the
/// wrapped-mode handshake.
#[test]
fn installer_mirrors_the_upgrade_wrapped_env_name() {
    let script = install_script();
    let env_name = ipe::UPGRADE_WRAPPED_ENV;

    assert!(
        script.contains(env_name),
        "install.sh must read the same wrapped-mode env var name as \
         ipe::UPGRADE_WRAPPED_ENV (`{env_name}`); it was not found in the script"
    );
    let tag_file_env = ipe::UPGRADE_TAG_FILE_ENV;
    assert!(
        script.contains(&format!("${{{tag_file_env}:-}}")),
        "install.sh must read the same tag-file env var name as \
         ipe::UPGRADE_TAG_FILE_ENV (`{tag_file_env}`); it was not found in the script"
    );
}
