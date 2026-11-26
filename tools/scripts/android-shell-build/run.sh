#!/usr/bin/env bash
# Assemble the Android shells `ipe release build web client android` generates,
# following the build steps the packer writes into their README.txt, and judge
# the Kotlin stdlib each one resolves.
#
# Usage: run.sh <path to the ipe binary>
#
# Two variants: a wasm client without push (examples/shapes/web/wasm-client-clipboard)
# and one that accepts `JsPort Push` (push-fixture/), whose shell links Firebase.
# Needs JDK 17 (`JAVA_HOME_17_X64`, else `JAVA_HOME`), the Android SDK
# (`ANDROID_HOME`), the wasm32 toolchain and wasm-bindgen. Every absent
# prerequisite is a refusal, never a skip.
set -euo pipefail

die() {
  echo "android-shell-build: $*" >&2
  exit 1
}

[ "$#" -eq 1 ] || die "usage: run.sh <path to the ipe binary>"
ipe="$(realpath -e -- "$1")" || die "no ipe binary at '$1'"
[ -x "$ipe" ] || die "'$ipe' is not executable"

repo="$(git -C "$(dirname -- "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
here="$repo/tools/scripts/android-shell-build"
judge="$repo/.github/ci/android_resolution.py"

java_home="${JAVA_HOME_17_X64:-${JAVA_HOME:-}}"
if [ -z "$java_home" ] || [ ! -x "$java_home/bin/java" ]; then
  die "JDK 17 is required: set JAVA_HOME_17_X64 or JAVA_HOME"
fi
java_version="$(timeout 60 "$java_home/bin/java" -version 2>&1 | head -n1)"
[[ "$java_version" =~ \"17[.\"] ]] || die "JDK 17 is required; $java_home/bin/java is: $java_version"
export JAVA_HOME="$java_home"
export PATH="$JAVA_HOME/bin:$PATH"

if [ -z "${ANDROID_HOME:-}" ] || [ ! -d "$ANDROID_HOME" ]; then
  die "the Android SDK is required: set ANDROID_HOME"
fi
sdkmanager="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"
[ -x "$sdkmanager" ] || die "no sdkmanager at $sdkmanager"

work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/android-shell-build.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT

# The Gradle distribution step 1 names, fetched once and checked against the
# digest step 1 names: the step's own pin is what this build proves.
bootstrap_gradle() {
  local version="$1" sha="$2"
  local zip="$work/gradle-$version-bin.zip"
  timeout 600 curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --max-filesize 536870912 --output "$zip" \
    "https://services.gradle.org/distributions/gradle-$version-bin.zip"
  echo "$sha  $zip" | sha256sum --check --quiet - \
    || die "gradle-$version-bin.zip does not match the SHA-256 the build steps pin"
  timeout 300 unzip -q "$zip" -d "$work/gradle-dist"
  rm -f -- "$zip"
  gradle_bin="$work/gradle-dist/gradle-$version/bin/gradle"
  [ -x "$gradle_bin" ] || die "the Gradle $version distribution has no bin/gradle"
}

gradle_bin=""
shell=""

# build_shell <project dir> <package name>
build_shell() {
  local project="$1" name="$2"
  local copy="$work/$name"
  echo "::group::android shell: $name"
  cp -R -- "$project" "$copy"
  rm -rf -- "$copy/out"
  timeout 600 "$ipe" type-check "$copy"
  timeout 1800 "$ipe" release build "$copy" web client android
  shell="$copy/out/release/web-client-android/dist/android/$name-android"
  [ -f "$shell/README.txt" ] || die "$name: no Android shell at $shell"
  cd "$shell"

  # Step 1 of the README's build steps, read from the generator's own text.
  local step tick='`'
  step="$(sed -n "s/^[[:space:]]*1\\. ${tick}\(gradle wrapper [^${tick}]*\)${tick}.*\$/\1/p" README.txt)"
  [[ "$step" =~ ^gradle\ wrapper\ --gradle-version\ ([0-9]+\.[0-9]+(\.[0-9]+)?)\ --gradle-distribution-sha256-sum\ ([0-9a-f]{64})$ ]] \
    || die "$name: README.txt step 1 is not a pinned \`gradle wrapper\` command: '$step'"
  local version="${BASH_REMATCH[1]}" sha="${BASH_REMATCH[3]}"
  [ -n "$gradle_bin" ] || bootstrap_gradle "$version" "$sha"

  local api
  api="$(sed -n 's/^[[:space:]]*compileSdk \([0-9]\{1,3\}\)[[:space:]]*$/\1/p' app/build.gradle)"
  [[ "$api" =~ ^[0-9]+$ ]] || die "$name: app/build.gradle names no single compileSdk"
  { yes || :; } | timeout 600 "$sdkmanager" --licenses >/dev/null
  timeout 600 "$sdkmanager" "platforms;android-$api" >/dev/null
  [ -d "$ANDROID_HOME/platforms/android-$api" ] || die "$name: the SDK has no platforms/android-$api after sdkmanager"

  timeout 600 "$gradle_bin" --no-daemon wrapper --gradle-version "$version" --gradle-distribution-sha256-sum "$sha"
  timeout 1200 ./gradlew --no-daemon assembleDebug
  [ -s app/build/outputs/apk/debug/app-debug.apk ] || die "$name: assembleDebug wrote no app-debug.apk"

  timeout 600 ./gradlew --no-daemon -q :app:dependencies --configuration debugRuntimeClasspath >"$work/$name-deps.txt"
  python3 "$judge" "$work/$name-deps.txt" app/build.gradle
  cd "$repo"
  echo "::endgroup::"
}

build_shell "$repo/examples/shapes/web/wasm-client-clipboard" wasm-client-clipboard
build_shell "$here/push-fixture" android-push-shell
grep -q "firebase-messaging" "$shell/app/build.gradle" \
  || die "the push shell links no Firebase messaging: the push variant proves nothing"
echo "android-shell-build: both generated Android shells assemble and resolve one Kotlin stdlib."
