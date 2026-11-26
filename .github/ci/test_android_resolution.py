#!/usr/bin/env python3
"""Refusal proofs for `android_resolution.py`, the Kotlin stdlib judge of the
`android-shell-build` job.

A skewed stdlib row, a row upgraded past the platform, an empty or unreadable
report, a report with no stdlib row, a failed resolution and a `build.gradle`
without exactly one platform line are each refused; a clean report is
accepted, so the refusals are not a judge that refuses everything. Pure
stdlib `unittest`.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))

_spec = importlib.util.spec_from_file_location("android_resolution", os.path.join(HERE, "android_resolution.py"))
assert _spec is not None and _spec.loader is not None
ar = importlib.util.module_from_spec(_spec)
sys.modules["android_resolution"] = ar
_spec.loader.exec_module(ar)

BOM = "1.8.22"
GRADLE = """dependencies {
    implementation platform('org.jetbrains.kotlin:kotlin-bom:1.8.22')
    implementation 'androidx.core:core:1.13.1'
}
"""
# The shape `./gradlew -q :app:dependencies --configuration debugRuntimeClasspath`
# prints for an aligned project.
CLEAN = """
------------------------------------------------------------
Project ':app'
------------------------------------------------------------

debugRuntimeClasspath - Runtime classpath of compilation 'debug' (target  (androidJvm)).
+--- org.jetbrains.kotlin:kotlin-bom:1.8.22
|    +--- org.jetbrains.kotlin:kotlin-stdlib:1.8.22 (c)
|    +--- org.jetbrains.kotlin:kotlin-stdlib-jdk7:1.8.22 (c)
|    \\--- org.jetbrains.kotlin:kotlin-stdlib-jdk8:1.8.22 (c)
+--- androidx.core:core:1.13.1
|    +--- org.jetbrains.kotlin:kotlin-stdlib:1.8.22 (*)
|    \\--- org.jetbrains.kotlinx:kotlinx-coroutines-android:1.6.4
|         \\--- org.jetbrains.kotlinx:kotlinx-coroutines-core-jvm:1.6.4
|              +--- org.jetbrains.kotlin:kotlin-stdlib-jdk8:1.6.21 -> 1.8.22
|              |    +--- org.jetbrains.kotlin:kotlin-stdlib:1.8.22 (*)
|              |    \\--- org.jetbrains.kotlin:kotlin-stdlib-jdk7:1.8.22
|              \\--- org.jetbrains.kotlin:kotlin-stdlib-common:1.6.21 -> 1.8.22
\\--- androidx.webkit:webkit:1.11.0
"""


class JudgeTest(unittest.TestCase):
    def test_clean_report_is_accepted(self) -> None:
        self.assertEqual(ar.judge(CLEAN, BOM), [])

    def test_skewed_stdlib_row_is_refused(self) -> None:
        skewed = CLEAN.replace("kotlin-stdlib-jdk8:1.6.21 -> 1.8.22", "kotlin-stdlib-jdk8:1.6.21")
        errors = ar.judge(skewed, BOM)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("kotlin-stdlib-jdk8 resolves to 1.6.21", errors[0])

    def test_upgrade_past_the_platform_is_refused(self) -> None:
        upgraded = CLEAN.replace("kotlin-stdlib:1.8.22 (*)\n|    \\---", "kotlin-stdlib:1.8.22 -> 1.9.0\n|    \\---")
        self.assertNotEqual(upgraded, CLEAN)
        errors = ar.judge(upgraded, BOM)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("resolves to 1.9.0", errors[0])

    def test_empty_report_is_refused(self) -> None:
        for empty in ("", "\n\n", "   \n"):
            with self.subTest(empty=empty):
                self.assertNotEqual(ar.judge(empty, BOM), [])

    def test_report_without_stdlib_rows_is_refused(self) -> None:
        bare = "debugRuntimeClasspath\n+--- org.jetbrains.kotlin:kotlin-bom:1.8.22\n\\--- androidx.webkit:webkit:1.11.0\n"
        errors = ar.judge(bare, BOM)
        self.assertTrue(any("no kotlin-stdlib row" in e for e in errors), errors)

    def test_report_without_the_platform_is_refused(self) -> None:
        unaligned = CLEAN.replace("+--- org.jetbrains.kotlin:kotlin-bom:1.8.22\n", "")
        errors = ar.judge(unaligned, BOM)
        self.assertTrue(any("does not resolve the kotlin-bom" in e for e in errors), errors)

    def test_failed_resolution_is_refused(self) -> None:
        failed = CLEAN + "+--- com.example:missing:1.0 FAILED\n"
        self.assertTrue(any("failed to resolve" in e for e in ar.judge(failed, BOM)))

    def test_unreadable_stdlib_row_is_refused(self) -> None:
        for row in (
            "+--- org.jetbrains.kotlin:kotlin-stdlib:{strictly 1.8.22} -> 1.8.22",
            "+--- org.jetbrains.kotlin:kotlin-stdlib:1.8.22 (n)",
            "+--- org.jetbrains.kotlin:kotlin-stdlib -> 1.8",
            "+--- org.jetbrains.kotlin:kotlin-stdlib",
        ):
            with self.subTest(row=row):
                self.assertNotEqual(ar.judge(CLEAN + row + "\n", BOM), [])


class BomVersionTest(unittest.TestCase):
    def test_one_platform_line_is_read(self) -> None:
        self.assertEqual(ar.bom_version(GRADLE), BOM)

    def test_missing_or_repeated_platform_is_refused(self) -> None:
        line = "    implementation platform('org.jetbrains.kotlin:kotlin-bom:1.8.22')\n"
        for gradle in (
            GRADLE.replace(line, ""),
            GRADLE.replace(line, line + line),
            GRADLE + "// kotlin-bom elsewhere\n",
            GRADLE.replace("1.8.22')", "1.8')"),
        ):
            with self.subTest(gradle=gradle):
                self.assertIsInstance(ar.bom_version(gradle), ar.Refused)


class MainTest(unittest.TestCase):
    def run_main(self, report: str, gradle: str) -> int:
        with tempfile.TemporaryDirectory() as tmp:
            report_path = os.path.join(tmp, "deps.txt")
            gradle_path = os.path.join(tmp, "build.gradle")
            with open(report_path, "w") as fh:
                fh.write(report)
            with open(gradle_path, "w") as fh:
                fh.write(gradle)
            return ar.main([report_path, gradle_path])

    def test_clean_project_passes(self) -> None:
        self.assertEqual(self.run_main(CLEAN, GRADLE), 0)

    def test_skewed_project_fails(self) -> None:
        self.assertEqual(self.run_main(CLEAN.replace(" -> 1.8.22", ""), GRADLE), 1)

    def test_platform_lowered_below_a_transitive_stdlib_fails(self) -> None:
        # androidx.core pulls kotlin-stdlib 1.8.22, so a 1.6.21 platform cannot
        # hold the stdlib down: Gradle resolves 1.8.22, past the written BOM.
        lowered = CLEAN.replace("kotlin-bom:1.8.22", "kotlin-bom:1.6.21")
        self.assertNotEqual(lowered, CLEAN)
        self.assertEqual(self.run_main(lowered, GRADLE.replace("1.8.22", "1.6.21")), 1)

    def test_platform_raised_with_every_row_following_passes(self) -> None:
        # The judge proves the project's own platform governs every stdlib row;
        # the generator's pin is proven by the `kotlin_bom_agrees` const assert.
        raised = CLEAN.replace("1.8.22", "1.9.0")
        self.assertEqual(self.run_main(raised, GRADLE.replace("1.8.22", "1.9.0")), 0)

    def test_missing_file_fails(self) -> None:
        self.assertEqual(ar.main(["/nonexistent/deps.txt", "/nonexistent/build.gradle"]), 1)

    def test_oversized_report_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "deps.txt")
            with open(path, "wb") as fh:
                fh.truncate(ar.MAX_BYTES + 1)
            self.assertIsInstance(ar.read_bounded(path), ar.Refused)

    def test_usage_error_exits_two(self) -> None:
        self.assertEqual(ar.main([]), 2)


if __name__ == "__main__":
    unittest.main()
