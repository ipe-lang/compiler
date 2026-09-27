# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

Entries below the header are maintained by
[release-please](https://github.com/googleapis/release-please): each release
section is generated from Conventional Commit messages and prepended when the
standing release pull request is merged.

## [0.3.0](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.2.6...ipe-v0.3.0) (2026-09-27)


### ⚠ BREAKING CHANGES

* **cli:** fold `ipe debugger` into `ipe run --record`
* **cli:** remove `ipe migrate`
* **cli:** `--out <dir>` for build/run/watch/release names the output root (crate at `<dir>/rust`, binary at `<dir>/bin`, release under `<dir>/release`); an existing unmarked `out/` must be removed once by hand.

### Features

* **cli:** `ipe run --replay` shows a trace-only session, sanitised ([1975b79](https://github.com/arthurmaciel/ipe-lang/commit/1975b79bf742f470317410b9cdf3b013799a51f6)), closes [#2847](https://github.com/arthurmaciel/ipe-lang/issues/2847)
* **cli:** deterministic `ipe run --replay` of recorded cli/worker sessions ([4b67789](https://github.com/arthurmaciel/ipe-lang/commit/4b67789e7f7a9a84e5e643303f3d824276e66682)), closes [#2848](https://github.com/arthurmaciel/ipe-lang/issues/2848)
* **db:** Db.upsertFields kernel — cross-backend ON CONFLICT DO UPDATE ([#2833](https://github.com/arthurmaciel/ipe-lang/issues/2833)) ([b991c63](https://github.com/arthurmaciel/ipe-lang/commit/b991c639e00459433f9a4609050a07a0a4245e58))
* **runtime/db:** typed engine version floors + fail-closed connect-time check ([f74166a](https://github.com/arthurmaciel/ipe-lang/commit/f74166aa52e74fa8d936b54050aac06e2649a4ea)), closes [#2789](https://github.com/arthurmaciel/ipe-lang/issues/2789)


### Bug Fixes

* **backend:** declare tokio net wherever the ssrf module is emitted ([c493302](https://github.com/arthurmaciel/ipe-lang/commit/c493302a0aff9418326b9f2ab698cc99a53e225d))
* **build:** store the build cache only after the emit claims the output dir ([6e38379](https://github.com/arthurmaciel/ipe-lang/commit/6e383792ecf333d41eb307058fffd102c2ddd264))
* capability-inference perf, fmt do-block re-parse, semver major line (batch) ([94c7732](https://github.com/arthurmaciel/ipe-lang/commit/94c77325313b601b1d3023e0396f3dd90e063336))
* **cli:** a handed-over eject tree can never sit inside an ipe-owned one ([e99617a](https://github.com/arthurmaciel/ipe-lang/commit/e99617ac34045bb053e6f85829ebabdd67d41ede))
* **cli:** classify emitted-build causes ([#2900](https://github.com/arthurmaciel/ipe-lang/issues/2900)) ([c117136](https://github.com/arthurmaciel/ipe-lang/commit/c117136602301ccb8ceda02a902e7e1d562a6e29))
* **cli:** never follow a symlink planted inside an owned output dir ([f4a11b0](https://github.com/arthurmaciel/ipe-lang/commit/f4a11b01c0a13a05c3623a81505a544374f274e0)), closes [#2827](https://github.com/arthurmaciel/ipe-lang/issues/2827)
* **cli:** never overwrite or delete user files; build output lives in ipe-owned out/ ([ce04a16](https://github.com/arthurmaciel/ipe-lang/commit/ce04a162f88dad13170d734c1d8c855b14e5d319)), closes [#2827](https://github.com/arthurmaciel/ipe-lang/issues/2827)
* **cli:** no output root may sit in any project's .ipe cache namespace ([230f0df](https://github.com/arthurmaciel/ipe-lang/commit/230f0df021b7601de62dabd5cecc9c9a6a6f67b4))
* **cli:** owned output dirs, single session gate, record/replay ([f841c22](https://github.com/arthurmaciel/ipe-lang/commit/f841c227c57bb8b57198f1d839691c9204278db4))
* **editors:** Emacs setup ships ipe-mode (font-lock + Eglot) and wires it into init.el or Doom's config.el, verified in batch ([99ae7bb](https://github.com/arthurmaciel/ipe-lang/commit/99ae7bb5cae467a92fa1236c1aaea611128682fc))
* **editors:** Helix setup builds the grammar locally, manages one languages.toml block, verifies before success ([eaf968a](https://github.com/arthurmaciel/ipe-lang/commit/eaf968abceb9a3b01ce5111a972599627ec55687))
* **editors:** Neovim setup installs parser, queries and a built-in-LSP plugin into the site dir, verified headlessly ([7929098](https://github.com/arthurmaciel/ipe-lang/commit/7929098910f756b448f817b89d2eca62153bc343))
* **editors:** Zed extension starts ipe lsp and builds under any cargo config; configure.sh never edits settings.json; shared tests ([efdd039](https://github.com/arthurmaciel/ipe-lang/commit/efdd0394069ef50e7e7fb67bf12624b1163061a9))
* **fmt:** re-sugar do blocks so formatted output always re-parses ([50e1af9](https://github.com/arthurmaciel/ipe-lang/commit/50e1af9c848c228ae848455b45919fb2e15b5008)), closes [#2843](https://github.com/arthurmaciel/ipe-lang/issues/2843)
* **ipe-index:** resolve wrapper binary out-of-tree, never in-tree target/ ([#2836](https://github.com/arthurmaciel/ipe-lang/issues/2836)) ([564bcdc](https://github.com/arthurmaciel/ipe-lang/commit/564bcdc754e27e43c3bf4820d003967582f78cbb))
* **pkg:** refuse a package with an uncompilable sibling, blamed on its own file ([61b9876](https://github.com/arthurmaciel/ipe-lang/commit/61b9876d6bb8ca54e7317a81b8df515222734054))
* **registry:** enforced-semver baseline is the last stable release; prerelease-aware floor ([83838ee](https://github.com/arthurmaciel/ipe-lang/commit/83838eefcf10f640fe24bef46ff7c26d8f4cbfbf)), closes [#2816](https://github.com/arthurmaciel/ipe-lang/issues/2816)
* **registry:** enforced-semver bump follows the predecessor's release line ([1113054](https://github.com/arthurmaciel/ipe-lang/commit/1113054e741b6d75cc72cd23023ee32570897c97)), closes [#2835](https://github.com/arthurmaciel/ipe-lang/issues/2835)
* **registry:** login-shaped publisher parse; diff report measures from the old version ([3a679d6](https://github.com/arthurmaciel/ipe-lang/commit/3a679d65eb0c34e73270a5bc40d1cb4da84396f4))
* **registry:** type publisher identity; blessed privileges need a proven identity ([d1f0515](https://github.com/arthurmaciel/ipe-lang/commit/d1f051519c43513ee4360dff34c9611680a0989c)), closes [#2802](https://github.com/arthurmaciel/ipe-lang/issues/2802)
* **run:** judge the session's native-bearing refusal over the consented capabilities ([b847520](https://github.com/arthurmaciel/ipe-lang/commit/b847520e96d8a749f40ef9ca36c010842bba95af))
* **runtime/db:** gate host-less and Unix-socket PostgreSQL targets; refuse startup on a policy-refused store ([#2830](https://github.com/arthurmaciel/ipe-lang/issues/2830)) ([23ebb73](https://github.com/arthurmaciel/ipe-lang/commit/23ebb737bf6a199f8638b7556c860178cf52396c))
* **runtime/db:** gate session-store pools on the engine floor; credential-free version-query errors ([691f83b](https://github.com/arthurmaciel/ipe-lang/commit/691f83b9dab0b5e2fc48d946874251d05d621cf7))
* **runtime/db:** one VettedPool constructor for every caller-URL pool; credential-free connect errors ([#2830](https://github.com/arthurmaciel/ipe-lang/issues/2830)) ([b207291](https://github.com/arthurmaciel/ipe-lang/commit/b20729132436a985020fb7a239d35160c7f96d37))
* **runtime/tests:** dial-scan strips only cfg(test) items, not whole file tail ([21511c3](https://github.com/arthurmaciel/ipe-lang/commit/21511c330d59bd6b1f11b4cc044d567b3b9558ce))
* **runtime/tests:** harden the dial-scan cfg(test) stripper against fooling ([817a707](https://github.com/arthurmaciel/ipe-lang/commit/817a707c944a6d37ff7268854a3388f067380f1e))
* **runtime:** carry the credential-free host proof in the type of every named SSRF dial ([1e25a07](https://github.com/arthurmaciel/ipe-lang/commit/1e25a0797807f0010beb83abe06a9819f6091411))
* **runtime:** classify store refusals exhaustively; dial scans read masked code structurally ([f6fac03](https://github.com/arthurmaciel/ipe-lang/commit/f6fac0397edd2c43a20d73a8dab2fbe49ef0e056))
* **runtime:** derive URL error text from the gate's parse, never echo a scheme ([a796975](https://github.com/arthurmaciel/ipe-lang/commit/a796975c1eb34923427ac34327782eb6cd4451ff))
* **runtime:** drop derived equality on DsnPart; test SQLite modes without to_url_lossy ([fd60bd3](https://github.com/arthurmaciel/ipe-lang/commit/fd60bd342bfe3b63b2804304486e069d2551ccc4)), closes [#2838](https://github.com/arthurmaciel/ipe-lang/issues/2838)
* **runtime:** gate server-only origin helpers on the server feature ([fb72643](https://github.com/arthurmaciel/ipe-lang/commit/fb72643465fb37966219d5f456dc42665b2b546d))
* **runtime:** hold a Dsn password only beside its user, and bound Dsn input ([5fe5767](https://github.com/arthurmaciel/ipe-lang/commit/5fe5767f6b802c5e6870852af4920007779baea6)), closes [#2838](https://github.com/arthurmaciel/ipe-lang/issues/2838)
* **runtime:** one typed SSRF gate for every dial; credential-free DB errors ([7c9b8b0](https://github.com/arthurmaciel/ipe-lang/commit/7c9b8b0c4a10424fc57da1d13d54f21e4e992ea8))
* **runtime:** open the cache root without following symlinks ([#2883](https://github.com/arthurmaciel/ipe-lang/issues/2883)) ([9ecd39e](https://github.com/arthurmaciel/ipe-lang/commit/9ecd39e9b0b1e7be565000c813fc9b4df7af47e7))
* **runtime:** parse a SQLite Dsn path once so it cannot change the open mode ([1137ca3](https://github.com/arthurmaciel/ipe-lang/commit/1137ca37842009845f6ee81ebf02c446264f9fc4)), closes [#2838](https://github.com/arthurmaciel/ipe-lang/issues/2838)
* **runtime:** parse the DB URL once into the engine it selects ([014c5b5](https://github.com/arthurmaciel/ipe-lang/commit/014c5b52b99fbdb8168d6c0282f4a380afaae3e7))
* **runtime:** percent-encode every Dsn part so a built name cannot downgrade TLS ([a522962](https://github.com/arthurmaciel/ipe-lang/commit/a522962d0177495c480e54bd095b415b20bd110a)), closes [#2838](https://github.com/arthurmaciel/ipe-lang/issues/2838)
* **runtime:** pin Postgres TLS to vetted address, fail closed on relay loss ([#2909](https://github.com/arthurmaciel/ipe-lang/issues/2909)) ([2a563b5](https://github.com/arthurmaciel/ipe-lang/commit/2a563b50ebe631f20b9c66b2bf93cb8e05f009a5))
* **runtime:** pin SSRF-vetted dials, resolve without blocking, type the refusal ([d0df83b](https://github.com/arthurmaciel/ipe-lang/commit/d0df83bb1dc3f7021e128a391616090f5f54a2e5))
* **runtime:** refuse ambiguous DB URLs and withhold hosts that may be credentials ([8d83b79](https://github.com/arthurmaciel/ipe-lang/commit/8d83b79857b9aa18c8c8101a635f0e50906fa6ad))
* **runtime:** route the HTTP resolver through the one SSRF gate ([785fcb1](https://github.com/arthurmaciel/ipe-lang/commit/785fcb19c7c175be100789789ba517d16d9c4fb7)), closes [#2854](https://github.com/arthurmaciel/ipe-lang/issues/2854)
* **runtime:** withhold credential-derived hosts, addresses and URL tails from every refusal ([488bbc2](https://github.com/arthurmaciel/ipe-lang/commit/488bbc20cb42719759c8339449c122cc674ee5de))
* typed db build errors, publisher login parse, editor setup ([a2e60db](https://github.com/arthurmaciel/ipe-lang/commit/a2e60db99961731ab4ee5861f88f575ff59f5901))


### Performance Improvements

* **cli:** resolve capabilities once per build/run/release invocation ([878da3a](https://github.com/arthurmaciel/ipe-lang/commit/878da3a3d022f89098b4a7129b98ea250ffb2072)), closes [#2822](https://github.com/arthurmaciel/ipe-lang/issues/2822)
* **pkg:** infer package capabilities over one shared source graph ([a88bcdd](https://github.com/arthurmaciel/ipe-lang/commit/a88bcddb45147be10136211a1c4c2f67cc53913f)), closes [#2826](https://github.com/arthurmaciel/ipe-lang/issues/2826)


### Code Refactoring

* **cli:** fold `ipe debugger` into `ipe run --record` ([7df345d](https://github.com/arthurmaciel/ipe-lang/commit/7df345d11a91435adfe248d893be7a12c79bd8c9)), closes [#2827](https://github.com/arthurmaciel/ipe-lang/issues/2827)
* **cli:** remove `ipe migrate` ([d646da9](https://github.com/arthurmaciel/ipe-lang/commit/d646da9107b3f1f629cbf8eecda88482d1c81d12)), closes [#2827](https://github.com/arthurmaciel/ipe-lang/issues/2827)

## [0.2.6](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.2.5...ipe-v0.2.6) (2026-09-26)


### Bug Fixes

* **ci:** sync Cargo.lock on the release branch, not the default branch ([#2820](https://github.com/arthurmaciel/ipe-lang/issues/2820)) ([a6d19d5](https://github.com/arthurmaciel/ipe-lang/commit/a6d19d55264b904db0651f7e79cc8e0594fbfc9f))
* **init:** equal-width counter buttons; refresh shapes + package.ipe docs from code ([#2818](https://github.com/arthurmaciel/ipe-lang/issues/2818)) ([9ec8b33](https://github.com/arthurmaciel/ipe-lang/commit/9ec8b33370fc6a239eac8f26ff671aa8f957df38))
* **ipe-index:** seed change_queue on initial index ([#2824](https://github.com/arthurmaciel/ipe-lang/issues/2824)) ([c14dfd6](https://github.com/arthurmaciel/ipe-lang/commit/c14dfd6c6400635e35c3ef9413faba39aff75e5f))

## [0.2.5](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.2.4...ipe-v0.2.5) (2026-09-25)


### Features

* **web:** routed Web.embed mountable via Server.mountApp; fail-closed endpoint-conflict gate ([#2812](https://github.com/arthurmaciel/ipe-lang/issues/2812)) ([3a9c825](https://github.com/arthurmaciel/ipe-lang/commit/3a9c82550af1d8ddb81b9012dbb90af04f26e7f2))


### Bug Fixes

* **registry:** exempt prereleases from the enforced-semver API bump ([#2817](https://github.com/arthurmaciel/ipe-lang/issues/2817)) ([da19ad8](https://github.com/arthurmaciel/ipe-lang/commit/da19ad8406c9cf67f12ce5b998a11d4eba96fad9))
* **registry:** fetch the exact pinned rev; keep smoke source revs immutable ([#2814](https://github.com/arthurmaciel/ipe-lang/issues/2814)) ([371930a](https://github.com/arthurmaciel/ipe-lang/commit/371930ad298e7c1fe8f2180bf204e4ba188f08f6))
* **registry:** negative-leg smoke proves admission verify-before-trust (source spoof) ([#2815](https://github.com/arthurmaciel/ipe-lang/issues/2815)) ([2c5bb87](https://github.com/arthurmaciel/ipe-lang/commit/2c5bb876e827549adbbb3d16d956338372dcda2b))

## [0.2.4](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.2.3...ipe-v0.2.4) (2026-09-24)


### Bug Fixes

* **publish:** audit reserved-namespace packages under the claimed publisher ([#2808](https://github.com/arthurmaciel/ipe-lang/issues/2808)) ([40e70de](https://github.com/arthurmaciel/ipe-lang/commit/40e70de7a19f6aecb1b394c9aa7093ee15637c03))

## [0.2.3](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.2.2...ipe-v0.2.3) (2026-09-24)


### Features

* **registry:** reset-per-run for the reserved smoke probe (append-only harden + --fresh) ([#2799](https://github.com/arthurmaciel/ipe-lang/issues/2799)) ([4946997](https://github.com/arthurmaciel/ipe-lang/commit/4946997ccdce6a9df26427e4e8f9b7308461f8d8))

## [0.2.2](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.2.1...ipe-v0.2.2) (2026-09-24)


### Features

* **registry:** reserve the ipe-registry-smoke-* package namespace to the blessed publisher ([#2795](https://github.com/arthurmaciel/ipe-lang/issues/2795)) ([c1d8193](https://github.com/arthurmaciel/ipe-lang/commit/c1d8193f564a37df2a6cb2385088d38a8055d6b8))


### Bug Fixes

* **deps:** bump salsa 0.27.2-&gt;0.28.5 to close RUSTSEC-2026-0308 (use-after-free) ([#2797](https://github.com/arthurmaciel/ipe-lang/issues/2797)) ([4062e87](https://github.com/arthurmaciel/ipe-lang/commit/4062e871c888a98a18d1b039615792825c728b4b))
* **doc:** embed the guide/topic/construct/idiom corpus so `ipe doc serve` renders everywhere ([#2796](https://github.com/arthurmaciel/ipe-lang/issues/2796)) ([412a573](https://github.com/arthurmaciel/ipe-lang/commit/412a57317768bf34a9a91d1f93a1e190b908b0a7))

## [0.2.1](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.2.0...ipe-v0.2.1) (2026-09-24)


### Features

* **auth:** add Ipe.Auth principal-claims read kernels (claim/hasRole/memberOf) ([3986d0f](https://github.com/arthurmaciel/ipe-lang/commit/3986d0fd26a6efa802246722bf43648e7727b8bd))
* **backend:** uniquify emitted crate identity per project ([#2752](https://github.com/arthurmaciel/ipe-lang/issues/2752)) ([1baba6d](https://github.com/arthurmaciel/ipe-lang/commit/1baba6d3fff2697db11982412c2eddef4ede47e0))
* **cli:** ipe add writes the dependency into package.ipe, not only ipe.lock ([f11da4e](https://github.com/arthurmaciel/ipe-lang/commit/f11da4e72b038387585ab6b58cb3a0e07c57521a))
* **cli:** verified publisher identity for signed publishes + `ipe add` writes package.ipe ([d764278](https://github.com/arthurmaciel/ipe-lang/commit/d76427849e3025d92f8fbd2f86297b42b265af8d))
* **control:** parent→child loopback control-channel transport + accept-loop server ([#2766](https://github.com/arthurmaciel/ipe-lang/issues/2766)) ([79731ac](https://github.com/arthurmaciel/ipe-lang/commit/79731accf5152695a460232adc512f3c15d6975c))
* **db-rls:** composable Pred/Policy row-security algebra (slice 1 of [#2767](https://github.com/arthurmaciel/ipe-lang/issues/2767)) ([a7c5c10](https://github.com/arthurmaciel/ipe-lang/commit/a7c5c10b5da2b79d3c6fcfa877188c640ee563e8))
* **db,emit:** RLS existsIn (slice 2) + tui appearance-hoist enablement ([971a7f6](https://github.com/arthurmaciel/ipe-lang/commit/971a7f6244925ece695139eddce349bcf8d0f2b6))
* **db/store:** column masking — CASE-WHEN projection that masks to NULL for unauthorized rows ([#2771](https://github.com/arthurmaciel/ipe-lang/issues/2771)) ([e3c182d](https://github.com/arthurmaciel/ipe-lang/commit/e3c182d66ec7119fbfa3311b38034590a1954817))
* **db:** existsIn correlated-subquery RLS predicate ([4fc1814](https://github.com/arthurmaciel/ipe-lang/commit/4fc18142dcf7ea55694117db5f6d29e81c2c571d))
* **db:** principal-side RLS predicate leaves (role/memberOf/claimEquals) ([5c06009](https://github.com/arthurmaciel/ipe-lang/commit/5c0600956191cfe5e952496be62e36a1461f23b0))
* **db:** wire Sql.exists + existsIn/correlate kernels across the pipeline ([58a8fb7](https://github.com/arthurmaciel/ipe-lang/commit/58a8fb70f9457bcad3f74ca6b5ecba82912e206e))
* **debugger:** cli/worker record/replay surface (C5/C6) ([196cbea](https://github.com/arthurmaciel/ipe-lang/commit/196cbea9b0b1d8991ff0e70ee92733fc9be10854))
* **debugger:** place the time-travel recorder above the cli and worker TEA loops ([#2765](https://github.com/arthurmaciel/ipe-lang/issues/2765)) ([2bc2092](https://github.com/arthurmaciel/ipe-lang/commit/2bc2092fdf26929f1ecb45868c335a2463accfd5))
* **dev-loop,db:** control-channel tui wiring + ipe debugger record/replay + RLS predicate algebra (slice 1) ([1eb21e8](https://github.com/arthurmaciel/ipe-lang/commit/1eb21e8f8dc7158464c934374d8f742bdb4e4624))
* **runtime/tui:** in-process apply seam for hot-swap + debugger scrub ([#2763](https://github.com/arthurmaciel/ipe-lang/issues/2763)) ([417e754](https://github.com/arthurmaciel/ipe-lang/commit/417e754f3cfb03a6aa590ea89e6457a49797998c))
* **runtime:** shape-agnostic dev-loop control channel — security spine (+ debugger/web compile fix) ([#2760](https://github.com/arthurmaciel/ipe-lang/issues/2760)) ([3c7cd46](https://github.com/arthurmaciel/ipe-lang/commit/3c7cd4679369e20669ad1d24a56dacbad10f8814))
* **tui:** mount the control apply-seam on a default `ipe watch` ([#2749](https://github.com/arthurmaciel/ipe-lang/issues/2749)) ([7546df6](https://github.com/arthurmaciel/ipe-lang/commit/7546df6593b132c19127d9def58205a94816ce90))
* **watch,auth:** mount tui apply-seam on default watch + Auth principal-claim read kernels ([e47f6fc](https://github.com/arthurmaciel/ipe-lang/commit/e47f6fcf4b056d7c8b49ac0e4e30a82441f0f1ec))
* **watch,tui:** wire the shape-agnostic control channel end-to-end for tui ([8658ca3](https://github.com/arthurmaciel/ipe-lang/commit/8658ca3a453cba4e53d4e75bf0ed5cf2c799fdf6))
* **watch:** tui appearance hot-swap over the loopback control channel ([eabc51e](https://github.com/arthurmaciel/ipe-lang/commit/eabc51ef1ea289b0e1e1eb58d45d7d060fa499ec))


### Bug Fixes

* **auth:** principal_claim returns IpeMaybe&lt;String&gt; to match the Maybe scheme (SEAL) ([4cbcb46](https://github.com/arthurmaciel/ipe-lang/commit/4cbcb46e45ab19290d8da8dfb7b0a117cefcde1c))
* **canon:** expose Auth.claim/hasRole/memberOf as Ipe.Auth module members ([6af5006](https://github.com/arthurmaciel/ipe-lang/commit/6af50060842daa356f3a8f44952acc93daca4af5))
* **canon:** resolve fully-qualified dotted user modules in type position ([#2777](https://github.com/arthurmaciel/ipe-lang/issues/2777)) ([22398e1](https://github.com/arthurmaciel/ipe-lang/commit/22398e17dcb6e80ab9fec2524859d223e2acbf3f))
* **ci:** resolve the static-build artifact by crate identity and deliver the Windows exe suffix ([#2764](https://github.com/arthurmaciel/ipe-lang/issues/2764)) ([4f7830d](https://github.com/arthurmaciel/ipe-lang/commit/4f7830d9c51646aac0fda248633ae656daa05993))
* **db/store:** build Policy as a full record literal, not a generic record update (unsupported at lowering) ([f1f38ee](https://github.com/arthurmaciel/ipe-lang/commit/f1f38eed14815c440f6ba2e329f0c5e33cbe0509))
* **db/store:** handle every Pred constructor explicitly in simplifyNot/predIsAlways/predIsNever (no closed-union catch-all) ([0d29e84](https://github.com/arthurmaciel/ipe-lang/commit/0d29e849267ddf6ed68820d4ed46675937f63b93))
* **db:** correlate takes column values, not accessors ([64aa101](https://github.com/arthurmaciel/ipe-lang/commit/64aa10178d813f603886953f8e2d23d3935895cc))
* **debugger:** hoist RECORD_ENV to the ungated runtime root so the featureless CLI can reference it ([a47ab6d](https://github.com/arthurmaciel/ipe-lang/commit/a47ab6d63c34575f45d01d4d813ef47aeb0af716))
* **debugger:** hoist replay use to fn top; classify the debugger subcommand as build-heavy in the transcript matrix ([8be6a21](https://github.com/arthurmaciel/ipe-lang/commit/8be6a21610c77e63acccc2f122b154bffb1d0b45))
* **emit:** declare literal_table in the emitted mod.rs for web/control-wire/debugger (module-set closure); drop unused re-export ([34020d8](https://github.com/arthurmaciel/ipe-lang/commit/34020d8284c4dff3862d9d93b3aaacc8637a1d15))
* **ipe-cli:** clear clippy nursery/restriction lints in the publish + manifest-writer paths ([0221829](https://github.com/arthurmaciel/ipe-lang/commit/02218295368e7d8e6d202f9da3fb482bbb365fc0))
* **lower:** drop ExistsRef phantom row so PExists carries no live tyvar ([466571d](https://github.com/arthurmaciel/ipe-lang/commit/466571d7dc0988cf8207d1ace4aa03e5ce834802))
* **publish:** author the index-PR commit under the account's verified GitHub identity ([328afce](https://github.com/arthurmaciel/ipe-lang/commit/328afcecf6e6fa3f26472d348ce4e327ee41107d))
* **rls-example:** type classifyMarker store param as Draft, not Store ([cd2c8e4](https://github.com/arthurmaciel/ipe-lang/commit/cd2c8e4e6eb60977f3e789b348095de1a3aad767))
* **runtime:** compile ipe-runtime-rust under debugger+tui (CellsView vs Element) ([#2762](https://github.com/arthurmaciel/ipe-lang/issues/2762)) ([83d5139](https://github.com/arthurmaciel/ipe-lang/commit/83d5139a511b3bcb8778ed2c6abe52e4a1f6e7a8))
* **runtime:** sound tui watch hot-swap over the control channel + prove the full loopback path ([#2772](https://github.com/arthurmaciel/ipe-lang/issues/2772)) ([bb2d0f2](https://github.com/arthurmaciel/ipe-lang/commit/bb2d0f261b0dd2017c47e25f302108a1b742d035))
* **watch/runtime:** server IPE_SERVER_PORT + proxy HTTP-detection + artifact→out/ + listening gutter + script template ([#2753](https://github.com/arthurmaciel/ipe-lang/issues/2753)) ([6bbd867](https://github.com/arthurmaciel/ipe-lang/commit/6bbd86787d260c41908abbd6fdcf02e43a385513))
* **watch:** detect web/tui/http shape across the whole emitted crate, not just src/main.rs ([c7c8383](https://github.com/arthurmaciel/ipe-lang/commit/c7c8383a595bde9b394067aa3641dbc13a9b56cf))
* **watch:** empty appearance patch is a no-op success before the port check ([aced28a](https://github.com/arthurmaciel/ipe-lang/commit/aced28a4d7991f99aeedd39c9282e21b4291e668))
* **watch:** route cli/worker appearance edits to rebuild, never a silent skip ([a7a8b1b](https://github.com/arthurmaciel/ipe-lang/commit/a7a8b1b8d91158d3dd16d9d880e14871ae3551a5))
* **watch:** tui hoists only tui-appearance kernels; narrow control-wire to tui ([f32de10](https://github.com/arthurmaciel/ipe-lang/commit/f32de10541c6face2bfadf0c96d6e7b808637c06))

## [0.2.0](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.86...ipe-v0.2.0) (2026-09-22)


### ⚠ BREAKING CHANGES

* **cli:** version/capabilities/type-check --json now emit the shared envelope. Scripts that read the bare top-level field must read it under .payload (e.g. `jq -r '.payload.version'`, `jq '.payload.capabilities'`); type-check success is now the envelope, not {"status":"ok"}.

### Features

* **cli:** emit shared JSON envelope from version/capabilities/type-check --json ([1a003bc](https://github.com/arthurmaciel/ipe-lang/commit/1a003bc7be1cab9b8eccf2e7e517b5bf620e9e69))
* **lsp:** typeDefinition, local let inlay hints, doc-backed enrichment, unused-import code action ([36fb533](https://github.com/arthurmaciel/ipe-lang/commit/36fb5337bb7d19c2d4bd6f2ff7c639c110dc7e7b))


### Bug Fixes

* **backend/emit:** route emit_ui_call/decoder/db over their full class domains ([d381cb0](https://github.com/arthurmaciel/ipe-lang/commit/d381cb01f4317424a92852e12dc9126484df65bd))
* **backend:** backtick ipe_kernels in doc comment (clippy doc_markdown) ([5066057](https://github.com/arthurmaciel/ipe-lang/commit/506605779bae5662a8f4419ab5ef63542b5fa332))
* **backend:** self-seal RuntimeFeature::ALL against the index() domain ([0b2aa13](https://github.com/arthurmaciel/ipe-lang/commit/0b2aa13184d5731b65ee0e452c7597796e18471d))
* **backend:** slice-pattern str_eq to clear const-fn indexing_slicing ([c32726f](https://github.com/arthurmaciel/ipe-lang/commit/c32726f9b63406d0c1afd5eb8cfa3a26cce5ea8b))
* **cli:** repair the ipe init server scaffold to the current server API ([2f62027](https://github.com/arthurmaciel/ipe-lang/commit/2f6202719d1e2af240039c06b3edf1b557b971ee))
* **init:** correct the script scaffold error type to Task Error () ([d39c1c3](https://github.com/arthurmaciel/ipe-lang/commit/d39c1c3d8387948409a1f2b72f572c2c8e5a4cd7))
* **init:** make the tui scaffold type-check against Tui.tea ([53b6e8b](https://github.com/arthurmaciel/ipe-lang/commit/53b6e8b12731d12a02b819583ecc9ad9bc28b2dd))
* **kernels:** const-safe str_eq for is_ui TermColor check (E0658) ([a1368bf](https://github.com/arthurmaciel/ipe-lang/commit/a1368bf0000e995f715d320269eded2ee2ffc0ae))
* **lower:** import enum_home_is_ffi_foreign from clone_class in the test ([0ff2a2a](https://github.com/arthurmaciel/ipe-lang/commit/0ff2a2a2e6d7ebaff2a8f322ba9b859c5a0dc7fe))
* **lower:** restore force_shared_capture_clones import used by lower.rs ([10a3e26](https://github.com/arthurmaciel/ipe-lang/commit/10a3e2609fba5a7683d2cd7e0ed763745bfc7928))
* **lower:** use pub(super) and a direct sibling import for clone_class ([93cacf8](https://github.com/arthurmaciel/ipe-lang/commit/93cacf8a5d09a8b757e6ab4a2968f1acd901d06f))
* **lower:** widen force_shared_capture_clones to pub(crate); re-home moved doc ([0122187](https://github.com/arthurmaciel/ipe-lang/commit/012218788defb7e87e63818112933e40a730b316))
* **lsp:** const fn for State::docs (clippy) ([cd84d0f](https://github.com/arthurmaciel/ipe-lang/commit/cd84d0fc866a7165bbb507f94641b5d7d2eb1264))
* **lsp:** delete the whole import in the unused-import quick-fix ([fca05b7](https://github.com/arthurmaciel/ipe-lang/commit/fca05b75b9f5a886d7e4fa4c05f3b5a34a322b5c))
* **lsp:** satisfy clippy nits + test imports; sync Cargo.lock for ipe_docs deps ([a93c8a1](https://github.com/arthurmaciel/ipe-lang/commit/a93c8a1c7c057a36e2eecb07c29de46286ac46a8))
* **lsp:** use slice contains in inlay-hint test (clippy manual_contains) ([5ca57d8](https://github.com/arthurmaciel/ipe-lang/commit/5ca57d8b5db610e68902d257c90f21f2f291cff8))

## [0.1.86](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.85...ipe-v0.1.86) (2026-09-21)


### Features

* **lsp:** editor-completeness — new LSP methods, richer completion/signature/hover/folding, fail-closed rangeFormatting ([#2729](https://github.com/arthurmaciel/ipe-lang/issues/2729)) ([1e62f7c](https://github.com/arthurmaciel/ipe-lang/commit/1e62f7c4c095aa696d18efbb40e61feaa925e460))

## [0.1.85](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.84...ipe-v0.1.85) (2026-09-21)


### Features

* **a11y:** default visible focus ring in Ipe.Ui + lint against silent outline removal ([#2720](https://github.com/arthurmaciel/ipe-lang/issues/2720)) ([129441a](https://github.com/arthurmaciel/ipe-lang/commit/129441aa33ecbd409f1a17c4defd982d3af6cd23))
* **a11y:** typed ARIA/role vocabulary + accessible-by-default Ipe.Ui ([#2716](https://github.com/arthurmaciel/ipe-lang/issues/2716)) ([58a7715](https://github.com/arthurmaciel/ipe-lang/commit/58a771570b4526cd6b2b964fd869c48be54ffe31))
* **cli:** four-quadrant output SSOT — semantic outcome layer + conformance table ([#2582](https://github.com/arthurmaciel/ipe-lang/issues/2582)) ([3e54918](https://github.com/arthurmaciel/ipe-lang/commit/3e54918ca66822607aced1da2722d54bd40f82ba)), closes [#2559](https://github.com/arthurmaciel/ipe-lang/issues/2559)
* **cli:** machine-output SSOT envelope + unified machine-error routing ([#2589](https://github.com/arthurmaciel/ipe-lang/issues/2589)) ([391c510](https://github.com/arthurmaciel/ipe-lang/commit/391c510f442d910ab2493fc9c81e423a4b9755c8)), closes [#2559](https://github.com/arthurmaciel/ipe-lang/issues/2559)
* **diagnostics:** bind each diagnostic code to its family at build time ([#2629](https://github.com/arthurmaciel/ipe-lang/issues/2629)) ([2438b14](https://github.com/arthurmaciel/ipe-lang/commit/2438b14da17280070be3dd1a1b4c16cd2072a83d))
* **editors:** one-shot 'curl … | sh' configure scripts per editor ([#2723](https://github.com/arthurmaciel/ipe-lang/issues/2723)) ([6d9efad](https://github.com/arthurmaciel/ipe-lang/commit/6d9efad9c65c215d3cf9d70d0a072dba990167fd))
* **lint:** flag empty Ui.iconButton label (nameless-to-AT a11y hole) ([#2725](https://github.com/arthurmaciel/ipe-lang/issues/2725)) ([b4ffda9](https://github.com/arthurmaciel/ipe-lang/commit/b4ffda9bbdb0065f1b5bcedaee61470bb09eaafe)), closes [#2717](https://github.com/arthurmaciel/ipe-lang/issues/2717)
* **lsp:** fill code-action, rename, and protocol feature gaps ([#2713](https://github.com/arthurmaciel/ipe-lang/issues/2713)) ([9d16467](https://github.com/arthurmaciel/ipe-lang/commit/9d16467585a1df14418b48893165dfc4a98d39e2))
* **shapes:** promote `worker` to a first-class TEA shape ([#2576](https://github.com/arthurmaciel/ipe-lang/issues/2576)) ([8239bd6](https://github.com/arthurmaciel/ipe-lang/commit/8239bd674db1efd2754291036cec7f871ee8adb3))
* **tree-sitter:** add textobjects and indents query files ([#2722](https://github.com/arthurmaciel/ipe-lang/issues/2722)) ([e7ff85a](https://github.com/arthurmaciel/ipe-lang/commit/e7ff85a969e481cc46563733dbb501f97a75bff7))


### Bug Fixes

* **annotate:** emit the exact operator glyph span, not the operand gap ([c9ce008](https://github.com/arthurmaciel/ipe-lang/commit/c9ce008fad500c3d0a3be20fbe34942da282c234))
* **backend:** close the first-line-only-fit SEAL-break class (StructLit/CallArgs/Chain/Assign) ([#2580](https://github.com/arthurmaciel/ipe-lang/issues/2580)) ([f6fccd5](https://github.com/arthurmaciel/ipe-lang/commit/f6fccd58ed45ce3d2b99ea66218455616d6ffcc4))
* **backend:** enforce hydration serde-safety gate on both emit paths ([#2605](https://github.com/arthurmaciel/ipe-lang/issues/2605)) ([80c41a7](https://github.com/arthurmaciel/ipe-lang/commit/80c41a76e40a3f569cbf836d6a22bff523db4597)), closes [#2603](https://github.com/arthurmaciel/ipe-lang/issues/2603) [#2604](https://github.com/arthurmaciel/ipe-lang/issues/2604)
* **canon:** resolve bare interpolation refs through the canonical name path ([d0b0820](https://github.com/arthurmaciel/ipe-lang/commit/d0b0820a5497cfd0d0b57c7473a394c6579ca631))
* **canon:** thread first-seen span through inject_dep_type for DuplicateType diagnostic ([40cdeaa](https://github.com/arthurmaciel/ipe-lang/commit/40cdeaadb1625f0491b18979f4edd3f13fb18fdd))
* **cli:** combine identical machine_kind arms (Usage|UsageOwned) for clippy::match_same_arms ([7fab1ff](https://github.com/arthurmaciel/ipe-lang/commit/7fab1ffda3d21e95856f4602c5042b8561885915))
* **cli:** fail publicEnv denylist closed on bare secret words ([b14ab55](https://github.com/arthurmaciel/ipe-lang/commit/b14ab555dfd11e4d6d22f69f69d5a76d4483e1a1))
* **cli:** gate the mimalloc note out of machine output ([#2594](https://github.com/arthurmaciel/ipe-lang/issues/2594)) ([0e03b23](https://github.com/arthurmaciel/ipe-lang/commit/0e03b230eae431734f2d1a59c0ecc1182ace96b5))
* **cli:** migrate the legacy ipe.toml [wasm] table instead of dropping it ([cdbcc90](https://github.com/arthurmaciel/ipe-lang/commit/cdbcc90ee05c77a9530ebecd4125b7b018cbd493))
* **cli:** parse lockfile dep names at the advisory-check boundary ([7807b1e](https://github.com/arthurmaciel/ipe-lang/commit/7807b1ef63e26260f03cd5a5c1d0cd16290065ee))
* **cli:** reject unknown [wasm] mode words on migration (mirror read_wasm) ([e170def](https://github.com/arthurmaciel/ipe-lang/commit/e170def8bc61c130ff6b65c8308bcb89c8227d0c))
* **cli:** remove dead target sub-grammar; reject repeated delivery tokens ([#2609](https://github.com/arthurmaciel/ipe-lang/issues/2609)) ([3e5b5c7](https://github.com/arthurmaciel/ipe-lang/commit/3e5b5c78656e2ae57e674572a6157d7609a96e92))
* **cli:** render every CliError variant to the documented --json/--plain schema ([65b847a](https://github.com/arthurmaciel/ipe-lang/commit/65b847ab6b7b264d3cbe2d93047d7db4125b7a7a))
* **cli:** resolve output format before parsing so parse errors honor machine mode ([#2595](https://github.com/arthurmaciel/ipe-lang/issues/2595)) ([194fafb](https://github.com/arthurmaciel/ipe-lang/commit/194fafb63a0757c106de09a7b0e3cb3482a899c5))
* **cli:** route ipe doc --json through the canonical JSON string escaper ([ec336f4](https://github.com/arthurmaciel/ipe-lang/commit/ec336f4cc1b349556149f75deb09513ceca837e2))
* **db-store:** reject unsafe DEFAULT text bytes before DDL (backend-independent literal) ([dcd9b44](https://github.com/arthurmaciel/ipe-lang/commit/dcd9b44179758d4c68ce4536e246993202d12911))
* **db:** cycle-check orphan modules in topo order, not just entry-reachable ([db92668](https://github.com/arthurmaciel/ipe-lang/commit/db92668409826448636caec3683be9d3e59f0fe2))
* **diagnostics:** correct render_json schema doc and add role drift-guard test ([1a93665](https://github.com/arthurmaciel/ipe-lang/commit/1a93665e9c18ca27d4f7508d73494ddf7fc6dcaf))
* **diagnostics:** mark compile-time family-pin const asserts for panic-scan ([9692055](https://github.com/arthurmaciel/ipe-lang/commit/969205599f745bf7b73cfaf61b3864657b632ee3))
* **encoding:** urlDecode fails closed on malformed percent-escape ([5e660bd](https://github.com/arthurmaciel/ipe-lang/commit/5e660bd8b1fda12c8d830b79eceb56c9192f3d18))
* **ffi:** derive Cargo dependency key from charset-gated PackageName ([#2663](https://github.com/arthurmaciel/ipe-lang/issues/2663)) ([1d45c5f](https://github.com/arthurmaciel/ipe-lang/commit/1d45c5ffae6ccbac676bbf6cce90fa9d9e243efc))
* **fmt:** preserve comments between record-type fields (unbreak file-browser example) ([#2726](https://github.com/arthurmaciel/ipe-lang/issues/2726)) ([3b57a7e](https://github.com/arthurmaciel/ipe-lang/commit/3b57a7ec9b18e5c24e31a625691c1c4bf6665b25))
* **fmt:** preserve comments in annotation, case-arm, let, and alias gaps ([#2719](https://github.com/arthurmaciel/ipe-lang/issues/2719)) ([e69a600](https://github.com/arthurmaciel/ipe-lang/commit/e69a60064ef063cfd3447c7996082e02643447bc))
* **ir:** single-source the runtime-shape field-name tables with a build-time assert ([#2680](https://github.com/arthurmaciel/ipe-lang/issues/2680)) ([b3cbb19](https://github.com/arthurmaciel/ipe-lang/commit/b3cbb19156db2939b40a0cd2bdfd8eb7d9a85cd4))
* **lint:** count CRLF bytes when mapping suppression markers to source spans ([578fbd2](https://github.com/arthurmaciel/ipe-lang/commit/578fbd2c814b567e47cfbf6d9eabb3a697b0b382))
* **lint:** drive inline suppression off real literal spans, not substring ([59cecaf](https://github.com/arthurmaciel/ipe-lang/commit/59cecaf524057cfb1dc946aee9cefa5f6ab8115c))
* **lint:** fail-closed suppression handling; add unused/wrapper/prim-param rules ([#2715](https://github.com/arthurmaciel/ipe-lang/issues/2715)) ([fdbe891](https://github.com/arthurmaciel/ipe-lang/commit/fdbe8914bbe8b99220a42e21a54244ac2a123820))
* **lint:** match prim-param name hints on token boundaries ([#2724](https://github.com/arthurmaciel/ipe-lang/issues/2724)) ([f86d390](https://github.com/arthurmaciel/ipe-lang/commit/f86d3909bac535c8e7d8052e30694e97478c5ab2)), closes [#2714](https://github.com/arthurmaciel/ipe-lang/issues/2714)
* **lower:** make default_generics_to_unit total over IrType (SEAL) ([4b19664](https://github.com/arthurmaciel/ipe-lang/commit/4b19664c8e4b389b689bf34e33842f10fced83b9))
* **lsp:** reach the rename engine for constructor/type renames ([faf21b1](https://github.com/arthurmaciel/ipe-lang/commit/faf21b11cad7f8a780759b8af9a2077be4cc8a53)), closes [#2654](https://github.com/arthurmaciel/ipe-lang/issues/2654)
* **lsp:** resolve constructor uses in find-references and goto-definition ([#2661](https://github.com/arthurmaciel/ipe-lang/issues/2661)) ([5e3fe36](https://github.com/arthurmaciel/ipe-lang/commit/5e3fe360ab8951057c4f6899a8f7e1d14af6db59))
* **lsp:** resolve the definition name token for goto/references ([fb62b15](https://github.com/arthurmaciel/ipe-lang/commit/fb62b15061c45e487a4721bec3c39037903cb89d))
* **lsp:** tighten interner lock scope in def_name_at (clippy::significant_drop_tightening) ([218f11c](https://github.com/arthurmaciel/ipe-lang/commit/218f11c0299e7093deec6b2e674fd6e47ce87b7d))
* **pack:** route XML/plist escaping through one shared SSOT helper ([#2606](https://github.com/arthurmaciel/ipe-lang/issues/2606)) ([569fa4b](https://github.com/arthurmaciel/ipe-lang/commit/569fa4b4dc5e73801f6dc57a48e12bc76ec45d79)), closes [#2599](https://github.com/arthurmaciel/ipe-lang/issues/2599)
* **panic-scan:** scope audit marker to its own construct's annotation ([5a44531](https://github.com/arthurmaciel/ipe-lang/commit/5a44531eebb844d96e45393f38716b84061cb5e7))
* **regex:** bound Ipe.Regex subject length, fail-closed past a shared ceiling ([c4f0c35](https://github.com/arthurmaciel/ipe-lang/commit/c4f0c35d7e531f1b8036ef2b1d9a3f189cccd4ed))
* **runtime:** bound + reclaim the cache registry, add Cache.destroy ([#2672](https://github.com/arthurmaciel/ipe-lang/issues/2672)) ([359141a](https://github.com/arthurmaciel/ipe-lang/commit/359141a09134fa56c441bfa869494d9399123b83))
* **runtime:** bound HTTP/WS server front door against DoS ([#2666](https://github.com/arthurmaciel/ipe-lang/issues/2666)) ([c9aa9ee](https://github.com/arthurmaciel/ipe-lang/commit/c9aa9ee8e1f8fe5b332a329a702e2f6100d23a64))
* **runtime:** bound String.pad width to match padLeft/padRight ([#2631](https://github.com/arthurmaciel/ipe-lang/issues/2631)) ([#2659](https://github.com/arthurmaciel/ipe-lang/issues/2659)) ([73b402b](https://github.com/arthurmaciel/ipe-lang/commit/73b402bf5e83a9559fc979502eb0a36641b34586))
* **runtime:** enforce RFC 5321 dot-atom mailbox in String.isEmail ([af09be5](https://github.com/arthurmaciel/ipe-lang/commit/af09be5e6bc120cc20ff431b5d3414b9c7f3b3e5)), closes [#2646](https://github.com/arthurmaciel/ipe-lang/issues/2646)
* **runtime:** floor Time.timeString sub-second split for pre-epoch timestamps ([3e8b946](https://github.com/arthurmaciel/ipe-lang/commit/3e8b94666d9b8d0dd990204c26a62b3aa3f3c033)), closes [#2645](https://github.com/arthurmaciel/ipe-lang/issues/2645)
* **runtime:** List.sum/product fold with wrapping arithmetic, not Iterator::sum ([#2667](https://github.com/arthurmaciel/ipe-lang/issues/2667)) ([86852b8](https://github.com/arthurmaciel/ipe-lang/commit/86852b8d9ce45e530cc4a16a0afaa5e835a08a2b))
* **runtime:** make String.repeat over-cap refusal observable via clamp ([1b989e2](https://github.com/arthurmaciel/ipe-lang/commit/1b989e23a11d5077ee81bffd1b567edda686238b))
* **runtime:** sever window.opener on target=_blank Ui.link (reverse tabnabbing) ([b711dbb](https://github.com/arthurmaciel/ipe-lang/commit/b711dbb670cd6930294bb54b92f78bc817e59e2e)), closes [#2634](https://github.com/arthurmaciel/ipe-lang/issues/2634)
* **runtime:** String.repeat emits &gt;=1 copy when a single copy exceeds the cap ([ff96552](https://github.com/arthurmaciel/ipe-lang/commit/ff9655263e8fb20a6574f373bfab1cdf059c51ee))
* **runtime:** uniform, unbiased random ints; guard weighted-sum overflow ([d5c6328](https://github.com/arthurmaciel/ipe-lang/commit/d5c632879271d67d49a26e20d90a4d47d17c25c9))
* **stdlib:** DeviceOrientation axes decode fail-closed on wrong-type ([3cc0371](https://github.com/arthurmaciel/ipe-lang/commit/3cc037104516a17f962fe63f3bd2257b6deef99c))
* **stdlib:** fail closed when a notification display ack reaches the permission fold ([fe730ec](https://github.com/arthurmaciel/ipe-lang/commit/fe730eca71acf089e0fc1c44c269267e21912a34)), closes [#2635](https://github.com/arthurmaciel/ipe-lang/issues/2635)
* **stdlib:** fail-closed ScreenOrientation lock/unlock fold ([#2651](https://github.com/arthurmaciel/ipe-lang/issues/2651)) ([f323c4c](https://github.com/arthurmaciel/ipe-lang/commit/f323c4c84939d6ea47296cf4bb4fbbeb78cb9e35))
* **stdlib:** filter Permission.changes to its name argument ([76ce383](https://github.com/arthurmaciel/ipe-lang/commit/76ce3839645c4d3ae17dd700eb8da9473cc93a8a))
* **stdlib:** map Fullscreen denial to permissionDenied, not unavailable ([905f294](https://github.com/arthurmaciel/ipe-lang/commit/905f294de2d342c3a9882ec4cc2db542d88a9906)), closes [#2649](https://github.com/arthurmaciel/ipe-lang/issues/2649)
* **stdlib:** Motion per-axis decode fails the frame closed on a wrong-type field ([d53b12e](https://github.com/arthurmaciel/ipe-lang/commit/d53b12e614005bcc26082dd6e7dad9971f91c69d))
* **stdlib:** percent-decode Url.Parser path segments and query values ([1147840](https://github.com/arthurmaciel/ipe-lang/commit/1147840be2519b1486b6453553909a930bbef032)), closes [#2643](https://github.com/arthurmaciel/ipe-lang/issues/2643)
* **stdlib:** quantize Money.convert to target currency minor units ([c377bca](https://github.com/arthurmaciel/ipe-lang/commit/c377bcae7128263cce7756049f9dd3327ac48fa6))
* **tools:** panic-scan detects UFCS / fully-qualified panicking calls ([#2665](https://github.com/arthurmaciel/ipe-lang/issues/2665)) ([036468e](https://github.com/arthurmaciel/ipe-lang/commit/036468eede1c91fd5bf8a81213489c085b4d0ba1)), closes [#2656](https://github.com/arthurmaciel/ipe-lang/issues/2656)
* **tools:** panic-scan fails closed on an un-lexable file ([#2660](https://github.com/arthurmaciel/ipe-lang/issues/2660)) ([33dfa63](https://github.com/arthurmaciel/ipe-lang/commit/33dfa630f9bd74da1cfe88d05463a9caaf657ff2)), closes [#2636](https://github.com/arthurmaciel/ipe-lang/issues/2636)
* **tree-sitter:** pin grammar to ABI 14 so editor hosts load it ([#2703](https://github.com/arthurmaciel/ipe-lang/issues/2703)) ([e5f1c4b](https://github.com/arthurmaciel/ipe-lang/commit/e5f1c4ba2cde7f556549b00ad844638f951ef724))
* **types:** enforce the Show use-site bound (SEAL) via a single-source bound predicate ([#2695](https://github.com/arthurmaciel/ipe-lang/issues/2695)) ([54da6f7](https://github.com/arthurmaciel/ipe-lang/commit/54da6f7e5ec1857df3a053514f26e6a8b3384f54))
* **types:** key stdlib record-alias expansion on resolved identity ([#2607](https://github.com/arthurmaciel/ipe-lang/issues/2607)) ([fa3132f](https://github.com/arthurmaciel/ipe-lang/commit/fa3132fcf404e6ac68d0000ddad991159c7a54b2)), closes [#2602](https://github.com/arthurmaciel/ipe-lang/issues/2602)
* **types:** pin kernel obligation slots to their scheme shapes ([#2681](https://github.com/arthurmaciel/ipe-lang/issues/2681)) ([a05205e](https://github.com/arthurmaciel/ipe-lang/commit/a05205ed25e28248486a6448cdc29eb7135ceabb))
* **watch:** harden watch subsystem against three audit findings ([#2608](https://github.com/arthurmaciel/ipe-lang/issues/2608)) ([8480b41](https://github.com/arthurmaciel/ipe-lang/commit/8480b41f78f06ee6f06fe70e852e0659f1575d37)), closes [#2596](https://github.com/arthurmaciel/ipe-lang/issues/2596) [#2597](https://github.com/arthurmaciel/ipe-lang/issues/2597) [#2598](https://github.com/arthurmaciel/ipe-lang/issues/2598)

## [0.1.84](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.83...ipe-v0.1.84) (2026-09-17)


### Bug Fixes

* **cli:** route the sandbox-override warning through the style palette ([#2557](https://github.com/arthurmaciel/ipe-lang/issues/2557)) ([f016e2d](https://github.com/arthurmaciel/ipe-lang/commit/f016e2d5e839a99043957221eba0896b7967ed67))

## [0.1.83](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.82...ipe-v0.1.83) (2026-09-17)


### Bug Fixes

* **cli:** parse the release-please `ipe-v` tag prefix in the upgrade check ([#2555](https://github.com/arthurmaciel/ipe-lang/issues/2555)) ([848daa5](https://github.com/arthurmaciel/ipe-lang/commit/848daa585a36aa6de4dde6d9ee021d4f1677c4e4))

## [0.1.82](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.81...ipe-v0.1.82) (2026-09-17)


### Bug Fixes

* **backend:** hydration-serde gate recurses into nested user ADT variant fields ([#2553](https://github.com/arthurmaciel/ipe-lang/issues/2553)) ([78ca083](https://github.com/arthurmaciel/ipe-lang/commit/78ca083e41a30ef036548ffae792813a05c3162c)), closes [#2550](https://github.com/arthurmaciel/ipe-lang/issues/2550)

## [0.1.81](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.80...ipe-v0.1.81) (2026-09-17)


### Bug Fixes

* **compiler:** int-overflow SSOT in transition classifier, hydration-gate target, App.fromEnv capability ([#2549](https://github.com/arthurmaciel/ipe-lang/issues/2549)) ([da3f6ea](https://github.com/arthurmaciel/ipe-lang/commit/da3f6ea284cc7235b5ddc036ca61c17b66872fcf))
* **lint:** prefer-pipeline --fix dropped operator precedence when the ([595e196](https://github.com/arthurmaciel/ipe-lang/commit/595e1969e4f56f9f86561c5d092ebc6cb48333e9))
* **lsp,lint:** parenthesise PCons/PAlias/POr ctor args and guard pipeline fix precedence ([#2545](https://github.com/arthurmaciel/ipe-lang/issues/2545)) ([595e196](https://github.com/arthurmaciel/ipe-lang/commit/595e1969e4f56f9f86561c5d092ebc6cb48333e9))
* **lsp:** push_pattern omitted parens for PCons/PAlias/POr in atom position ([595e196](https://github.com/arthurmaciel/ipe-lang/commit/595e1969e4f56f9f86561c5d092ebc6cb48333e9))
* **runtime,security:** bound CSS-value recursion, CSV bytes, and cache entry cap ([#2546](https://github.com/arthurmaciel/ipe-lang/issues/2546)) ([bd03b22](https://github.com/arthurmaciel/ipe-lang/commit/bd03b226b3ec9ad3c4add99a125d2a2216394a54))
* **security:** close IPv6-literal SSRF bypass + harden outbound HTTP ([#2538](https://github.com/arthurmaciel/ipe-lang/issues/2538)) ([2fc30bc](https://github.com/arthurmaciel/ipe-lang/commit/2fc30bccc8ce8748de41479bcf1fa2edf46acdee))
* **security:** pin redirect policy on credential-bearing web clients ([#2539](https://github.com/arthurmaciel/ipe-lang/issues/2539)) ([4615997](https://github.com/arthurmaciel/ipe-lang/commit/4615997253df874cd9b913e4f47cf2cb3c5cdd73)), closes [#2535](https://github.com/arthurmaciel/ipe-lang/issues/2535)
* **security:** Windows run-jail ceilings, ipe release consent gates, macOS bundle-name traversal ([#2552](https://github.com/arthurmaciel/ipe-lang/issues/2552)) ([2187683](https://github.com/arthurmaciel/ipe-lang/commit/21876832cc8b355350f8ef19bf4203e3c94d87d9))

## [0.1.80](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.79...ipe-v0.1.80) (2026-09-17)


### Features

* **audit:** control-model consumer consent + fail-closed drift gate (IPE-S0004) ([#2490](https://github.com/arthurmaciel/ipe-lang/issues/2490)) ([dc8d2f1](https://github.com/arthurmaciel/ipe-lang/commit/dc8d2f15278d4ccdbfb1a03457b44b8f9df4d2c5))
* **audit:** disclose compiler-derived control model + capability set, fail-closed ([#2484](https://github.com/arthurmaciel/ipe-lang/issues/2484)) ([785a3a5](https://github.com/arthurmaciel/ipe-lang/commit/785a3a5d7b3a0daa1b96970b637089600ac49bd2))
* **backend,types:** add unified colour BuiltinTag carriers + curate color runtime module ([#2477](https://github.com/arthurmaciel/ipe-lang/issues/2477)) ([20f1013](https://github.com/arthurmaciel/ipe-lang/commit/20f1013769397d4033669160c2df6d34ff1a939c))
* **canon:** reserve Ipe.Color companion opaque type names (S1) ([#2489](https://github.com/arthurmaciel/ipe-lang/issues/2489)) ([aa34205](https://github.com/arthurmaciel/ipe-lang/commit/aa34205e4015e7c33e2c3666ba8b1e3497cef072))
* **cli:** ipe run --target wasi executes the wasm32-wasip1 module in embedded wasmtime ([#2523](https://github.com/arthurmaciel/ipe-lang/issues/2523)) ([4b4fbdd](https://github.com/arthurmaciel/ipe-lang/commit/4b4fbddbc8b1fdf3199328bc4eabae80d506b645))
* **cli:** user-facing --target wasi selector; retire reconcile_wasm_target ([#2461](https://github.com/arthurmaciel/ipe-lang/issues/2461) incr 3) ([#2515](https://github.com/arthurmaciel/ipe-lang/issues/2515)) ([2bcec04](https://github.com/arthurmaciel/ipe-lang/commit/2bcec04a93729446edcd4d55553229af57bfe65b))
* **codec:** CDecimal/CMoney ColTypes → SqlDecimal/SqlMoney ([#2483](https://github.com/arthurmaciel/ipe-lang/issues/2483)) ([a181f62](https://github.com/arthurmaciel/ipe-lang/commit/a181f626cdc12c486dde67a353865f307b214607))
* **codec:** route Ipe.Time.Timestamp through CTime to SqlTime ([#2476](https://github.com/arthurmaciel/ipe-lang/issues/2476)) ([3d927ca](https://github.com/arthurmaciel/ipe-lang/commit/3d927caf0a7a7e04119eeac5b8341c73c14dac53))
* **color:** register the Ipe.Color a11y / profile / parse kernels ([#2329](https://github.com/arthurmaciel/ipe-lang/issues/2329) S3) ([#2518](https://github.com/arthurmaciel/ipe-lang/issues/2518)) ([b67cce1](https://github.com/arthurmaciel/ipe-lang/commit/b67cce17a29e7806bcede4792251803faaddd0d3))
* **color:** register the Ipe.Color kernels + bind them via a stdlib veneer ([#2329](https://github.com/arthurmaciel/ipe-lang/issues/2329) S2+S6) ([#2513](https://github.com/arthurmaciel/ipe-lang/issues/2513)) ([5d201cd](https://github.com/arthurmaciel/ipe-lang/commit/5d201cd0cab834e7455360fb699851ffb24eef88))
* **compiler:** kernel type-bridge for recursive payload-carrying stdlib ADTs ([#2519](https://github.com/arthurmaciel/ipe-lang/issues/2519)) ([60a6925](https://github.com/arthurmaciel/ipe-lang/commit/60a6925639614704d3458d199547899e2eb38e98))
* **delivery:** typed engine×host×triple validity matrix, fail-closed ([#2461](https://github.com/arthurmaciel/ipe-lang/issues/2461)) ([#2488](https://github.com/arthurmaciel/ipe-lang/issues/2488)) ([f56038f](https://github.com/arthurmaciel/ipe-lang/commit/f56038f3d01c2892efc5edd224435d207093707f))
* **disclose:** surface control model + capabilities in LSP hover and ipe doc ([#2460](https://github.com/arthurmaciel/ipe-lang/issues/2460)) ([#2498](https://github.com/arthurmaciel/ipe-lang/issues/2498)) ([e29ca5d](https://github.com/arthurmaciel/ipe-lang/commit/e29ca5dee7b67e61ef70fa36da1061739bd0fc48))
* **docs:** drop comrak, unify doc Markdown onto the Ipe.Markdown port ([#2235](https://github.com/arthurmaciel/ipe-lang/issues/2235)) ([#2499](https://github.com/arthurmaciel/ipe-lang/issues/2499)) ([4cacf0a](https://github.com/arthurmaciel/ipe-lang/commit/4cacf0a2834aeeba43cf07a7fafbb6a17f69e901))
* **docs:** Ipe.Markdown SSOT — hand-ported std-only parser + escape-by-default HTML walker (Stages 0–3) ([#2487](https://github.com/arthurmaciel/ipe-lang/issues/2487)) ([1e3d523](https://github.com/arthurmaciel/ipe-lang/commit/1e3d52303a25ee98d36fdcbf2a25fb3993ab6394))
* **editors:** tree-sitter-ipe grammar + queries + all-editor highlighting config ([#2522](https://github.com/arthurmaciel/ipe-lang/issues/2522)) ([242c40a](https://github.com/arthurmaciel/ipe-lang/commit/242c40a49e548aead5633483b33cceb17ea01042))
* **platform:** open the WASI accept-path for the sealed co-located floor ([#2461](https://github.com/arthurmaciel/ipe-lang/issues/2461) incr 2) ([#2507](https://github.com/arthurmaciel/ipe-lang/issues/2507)) ([b2c8804](https://github.com/arthurmaciel/ipe-lang/commit/b2c88049f4a8f6f6c6f61f217b3e78d15a499356))
* **shapes:** Direct = Task; drop generic TeaApp and Script.program ([#2455](https://github.com/arthurmaciel/ipe-lang/issues/2455)) ([#2470](https://github.com/arthurmaciel/ipe-lang/issues/2470)) ([2d570ef](https://github.com/arthurmaciel/ipe-lang/commit/2d570ef91dd7817d7b99950c498d7a0de42fc81f))
* **stdlib:** Ipe.Length language-level SSOT for shared CSS length units ([#2497](https://github.com/arthurmaciel/ipe-lang/issues/2497)) ([180f6dc](https://github.com/arthurmaciel/ipe-lang/commit/180f6dce7836f46726af6ead8e0dfcf07a9dbc4d))
* **tea:** add Ipe.Tea.worker — view-less, co-located, capability-gated program ([#2457](https://github.com/arthurmaciel/ipe-lang/issues/2457)) ([4e992e9](https://github.com/arthurmaciel/ipe-lang/commit/4e992e944ebf28bbfcf06e1edfcbe99a77f9796e))
* **tea:** retype Element/Screen/Lines to the real View &lt;engine&gt; type; generic Ipe.Tea.app ([#2459](https://github.com/arthurmaciel/ipe-lang/issues/2459)) ([3a6840a](https://github.com/arthurmaciel/ipe-lang/commit/3a6840ad88025ba1a4629c3c82ec060e0cebcb0f))
* **tea:** View e msg carrier + generic Ipe.Tea.app (engine=Web), additive ([#2458](https://github.com/arthurmaciel/ipe-lang/issues/2458)) ([48ba3d1](https://github.com/arthurmaciel/ipe-lang/commit/48ba3d15f8837af33747364f61c5d82a454a8285))
* **types:** forbid bare `_` over closed unions; add dev-only `Debug._` ([#2478](https://github.com/arthurmaciel/ipe-lang/issues/2478)) ([0918874](https://github.com/arthurmaciel/ipe-lang/commit/0918874aa7e43c51dca29ce41e50a420803b6475))
* **url,html,ui:** typed LinkTarget/MediaTarget SSOT over Url + Relative ([#2335](https://github.com/arthurmaciel/ipe-lang/issues/2335)) ([570c5d5](https://github.com/arthurmaciel/ipe-lang/commit/570c5d588987023936d5e6a4e6f447d7db2489d1))


### Bug Fixes

* **browser-e2e:** deterministic app-readiness gate ([#2407](https://github.com/arthurmaciel/ipe-lang/issues/2407)) ([#2418](https://github.com/arthurmaciel/ipe-lang/issues/2418)) ([cc9f4d5](https://github.com/arthurmaciel/ipe-lang/commit/cc9f4d5c48f9fed85d1c452d35fce4196a774feb))
* **canon:** home compiled-source Html-family ADTs at their real module ([#2437](https://github.com/arthurmaciel/ipe-lang/issues/2437)) ([f148b0f](https://github.com/arthurmaciel/ipe-lang/commit/f148b0f65864fd3ec6e3eca7645974e5a3f8b8e2)), closes [#2328](https://github.com/arthurmaciel/ipe-lang/issues/2328)
* **canon:** scope IPE-N0050 so static-site scripts are not warned ([#2485](https://github.com/arthurmaciel/ipe-lang/issues/2485)) ([5fd0d61](https://github.com/arthurmaciel/ipe-lang/commit/5fd0d61985b9e0ad02d56fc74b97863fabb12d43))
* **cli:** pin the wasi web-live fail-closed refusal + correct the bundle size probe ([#2461](https://github.com/arthurmaciel/ipe-lang/issues/2461) follow-ups) ([#2525](https://github.com/arthurmaciel/ipe-lang/issues/2525)) ([e1670c1](https://github.com/arthurmaciel/ipe-lang/commit/e1670c1339a027945f7dad26bf79161fa6716684))
* **cli:** version-adaptive cargo-deny --config placement in package audit ([#2426](https://github.com/arthurmaciel/ipe-lang/issues/2426)) ([59ac2a9](https://github.com/arthurmaciel/ipe-lang/commit/59ac2a9fd275a440857ba8b278cd24e683e61cc8))
* couple spa delivery to wasm target, fail closed on disagreement ([#2451](https://github.com/arthurmaciel/ipe-lang/issues/2451)) ([f72ac2b](https://github.com/arthurmaciel/ipe-lang/commit/f72ac2bbe2aa9e089158df29dc0678b7d06c84e9))
* **coverage:** make symbol_scratch_key injective ([#2322](https://github.com/arthurmaciel/ipe-lang/issues/2322)) ([#2438](https://github.com/arthurmaciel/ipe-lang/issues/2438)) ([fa26354](https://github.com/arthurmaciel/ipe-lang/commit/fa263548f78679bf9203e056a603134f691069e9))
* **db:** SqlValue.SqlDecimal takes a native Decimal (role-in-type) ([#2479](https://github.com/arthurmaciel/ipe-lang/issues/2479)) ([93eeb69](https://github.com/arthurmaciel/ipe-lang/commit/93eeb692ad0fed05e48e381f2de43f5a069e3319))
* **deps:** bump rustls to &gt;=0.23.45 (RUSTSEC-2026-0285) ([#2537](https://github.com/arthurmaciel/ipe-lang/issues/2537)) ([5f17d57](https://github.com/arthurmaciel/ipe-lang/commit/5f17d57c71d3c31dbe521824900b96d5433a9eae)), closes [#2533](https://github.com/arthurmaciel/ipe-lang/issues/2533)
* **deps:** bump rustls to 0.23.45 (RUSTSEC-2026-0285) ([#2469](https://github.com/arthurmaciel/ipe-lang/issues/2469)) ([6132db0](https://github.com/arthurmaciel/ipe-lang/commit/6132db0e87c887488f8c20bce0d554de7f598471))
* **fixture:** spike-webview-threejs view returns Element Msg ([#2253](https://github.com/arthurmaciel/ipe-lang/issues/2253)) ([#2434](https://github.com/arthurmaciel/ipe-lang/issues/2434)) ([23687fa](https://github.com/arthurmaciel/ipe-lang/commit/23687fa2106b8349ef10cfae905a38cb4251190b))
* **publish:** sign the package-publish commit, fail closed without a key ([#2428](https://github.com/arthurmaciel/ipe-lang/issues/2428)) ([#2444](https://github.com/arthurmaciel/ipe-lang/issues/2444)) ([6238008](https://github.com/arthurmaciel/ipe-lang/commit/6238008d3d489a4e0295cb4e5a95315656e3fbe5))
* **release:** copy native binary into out dir; fail-closed if missing ([#2433](https://github.com/arthurmaciel/ipe-lang/issues/2433)) ([f63b3b8](https://github.com/arthurmaciel/ipe-lang/commit/f63b3b8bbda4dfb3ada354618adf0e0d56e9aba9))
* **runtime:** bound recursive-tree teardown and keep the red-zone probe sound under ASAN ([#2413](https://github.com/arthurmaciel/ipe-lang/issues/2413)) ([29e3526](https://github.com/arthurmaciel/ipe-lang/commit/29e35269762f2dcb0b594b6de0473974274706f9))
* **runtime:** derive Permissions-Policy from granted Ipe.Browser capabilities ([#2422](https://github.com/arthurmaciel/ipe-lang/issues/2422), [#2407](https://github.com/arthurmaciel/ipe-lang/issues/2407)) ([#2424](https://github.com/arthurmaciel/ipe-lang/issues/2424)) ([90d82c4](https://github.com/arthurmaciel/ipe-lang/commit/90d82c470be2a1a20d56b32ed5ae47f47e6ce656))
* **sandbox:** create FreeBSD jail rw nullfs mountpoints before mount ([#2446](https://github.com/arthurmaciel/ipe-lang/issues/2446)) ([f75545b](https://github.com/arthurmaciel/ipe-lang/commit/f75545b42c807117385c33827dd316820b46eaad))
* **sandbox:** re-permit macOS child bring-up services under the run-jail SBPL ([#2247](https://github.com/arthurmaciel/ipe-lang/issues/2247)) ([#2445](https://github.com/arthurmaciel/ipe-lang/issues/2445)) ([60a061c](https://github.com/arthurmaciel/ipe-lang/commit/60a061cd01abbe6cc51f0d09eddb3decbb22f7ff))
* **seal:** exact-pin chrono=0.4.45 to make the emitted-crate dep resolve deterministic (Part of [#2278](https://github.com/arthurmaciel/ipe-lang/issues/2278)) ([#2440](https://github.com/arthurmaciel/ipe-lang/issues/2440)) ([31897b8](https://github.com/arthurmaciel/ipe-lang/commit/31897b8511512e458859f695d4624bca448cf5f3))
* **seal:** per-emit Cargo.lock + --locked hermetic emitted build ([#2467](https://github.com/arthurmaciel/ipe-lang/issues/2467)) ([2f51463](https://github.com/arthurmaciel/ipe-lang/commit/2f5146349fde168a26f8b9cdc54fade0c8f55fef))
* **test:** isolate the run-and-assert SEAL e2e binary from the shared warm target ([#2517](https://github.com/arthurmaciel/ipe-lang/issues/2517)) ([a76d6d8](https://github.com/arthurmaciel/ipe-lang/commit/a76d6d8881d65d1cfa023586d0cee361e08d73c9))
* **types:** thread home onto obligation constraints + deterministic diagnostic fallback ([#2412](https://github.com/arthurmaciel/ipe-lang/issues/2412)) ([#2442](https://github.com/arthurmaciel/ipe-lang/issues/2442)) ([2da10f2](https://github.com/arthurmaciel/ipe-lang/commit/2da10f27ec1d135c4678954face63e0a9941b4e4))
* unnecessary workflows prunning ([#2401](https://github.com/arthurmaciel/ipe-lang/issues/2401)) ([107223a](https://github.com/arthurmaciel/ipe-lang/commit/107223a4ce0b8d0bb50a88baafbe23a6cba33099))

## [0.1.79](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.78...ipe-v0.1.79) (2026-09-08)


### Features

* **browser:** Ipe.Browser.Recorder — audio + video recording (MediaRecorder + getUserMedia) ([#1819](https://github.com/arthurmaciel/ipe-lang/issues/1819)) ([9a0cdff](https://github.com/arthurmaciel/ipe-lang/commit/9a0cdffcb7096261394dd7bf4847d0e76f67a435))
* **browser:** Web API batch 2 — Orientation, Motion, Channel, Fullscreen, ScreenOrientation, WakeLock ([#1813](https://github.com/arthurmaciel/ipe-lang/issues/1813)) ([a00a54c](https://github.com/arthurmaciel/ipe-lang/commit/a00a54c8662811e1bf975ead2b1bdfd109405a5c))
* **browser:** WebAuthn capability (Payment Request deferred as non-Baseline) ([#1826](https://github.com/arthurmaciel/ipe-lang/issues/1826)) ([d1f0786](https://github.com/arthurmaciel/ipe-lang/commit/d1f0786a0432abd8854f0f94162dc985596667b4))
* **build:** model the delivery set and release every declared delivery ([#1996](https://github.com/arthurmaciel/ipe-lang/issues/1996)) ([a6891c6](https://github.com/arthurmaciel/ipe-lang/commit/a6891c6dec67097c8813016eafe9a544c1f70508))
* **canon:** library-SSOT shape×runtime allow-gate (IPE-N0047) ([#1822](https://github.com/arthurmaciel/ipe-lang/issues/1822)) ([ccfd682](https://github.com/arthurmaciel/ipe-lang/commit/ccfd68228d6761f35f6fdb8436ea3f61bb187c68))
* **cli:** delivery grammar (shape/runtime/host) + webview-native host wiring ([#1811](https://github.com/arthurmaciel/ipe-lang/issues/1811)) ([e2579c4](https://github.com/arthurmaciel/ipe-lang/commit/e2579c4ac4099104300a4622501a9861f979fb04))
* **cli:** group dev verbs under `ipe dev`, `ipe release` as the shipping posture ([#2169](https://github.com/arthurmaciel/ipe-lang/issues/2169)) ([0e937e4](https://github.com/arthurmaciel/ipe-lang/commit/0e937e41d49375521d462cf8116a1e860688238d))
* **cli:** ipe init wizard + doc/project/watch perf ([#2090](https://github.com/arthurmaciel/ipe-lang/issues/2090)) ([c777f0d](https://github.com/arthurmaciel/ipe-lang/commit/c777f0dc35b1dff7eb9c0dce69a698e3274c35e6)), closes [#2025](https://github.com/arthurmaciel/ipe-lang/issues/2025)
* **cli:** ipe init wizard + package.ipe delivery (build=default/release=all) ([#1827](https://github.com/arthurmaciel/ipe-lang/issues/1827)) ([e2c8ff2](https://github.com/arthurmaciel/ipe-lang/commit/e2c8ff2e9a1a32333ffc48ce22aca817c28c8a7e))
* **cli:** print version banner at the start of ipe init ([#2149](https://github.com/arthurmaciel/ipe-lang/issues/2149)) ([1b49d9e](https://github.com/arthurmaciel/ipe-lang/commit/1b49d9e89b25869955454728e7ac71d8b3cf46ee))
* **cli:** uniform --json/--plain machine output + ipe --help --json discovery ([#2153](https://github.com/arthurmaciel/ipe-lang/issues/2153)) ([52578ec](https://github.com/arthurmaciel/ipe-lang/commit/52578ecde974e803a68632807bb55878f73f5859))
* fail-closed gates, injective name fold, and trust-set hardening ([4ccbbb8](https://github.com/arthurmaciel/ipe-lang/commit/4ccbbb82db0104814a984922958e3c7457f6e517))
* **registry:** publish + admission E2E gate (accept valid, deny malicious) ([#2097](https://github.com/arthurmaciel/ipe-lang/issues/2097)) ([ad9ab90](https://github.com/arthurmaciel/ipe-lang/commit/ad9ab9076de6b57856e54a44c2dda90f0c3dec89))
* **runtime:** Ipe.Color SSOT foundation — opaque sRGB colour + toAnsi single degradation point (part of [#2140](https://github.com/arthurmaciel/ipe-lang/issues/2140)) ([#2150](https://github.com/arthurmaciel/ipe-lang/issues/2150)) ([6fcfc08](https://github.com/arthurmaciel/ipe-lang/commit/6fcfc082708cef798832767e9fd38f198a0eea85))
* **runtime:** render a Cli Lines view to styled terminal output ([#1915](https://github.com/arthurmaciel/ipe-lang/issues/1915)) ([16cd5bc](https://github.com/arthurmaciel/ipe-lang/commit/16cd5bcedad1f024a5cc88647f6ef7da8acbda47))
* **shape:** fold WebViewApp leaf into web shape + webview host ([#1823](https://github.com/arthurmaciel/ipe-lang/issues/1823)) ([bf7ebeb](https://github.com/arthurmaciel/ipe-lang/commit/bf7ebebe2ae98824a5f711a8895da8c57edadecf))
* **shape:** Ipe.Tea.Tui.Ui Screen view with cell-native attributes (kill the silent attribute drop) ([#1812](https://github.com/arthurmaciel/ipe-lang/issues/1812)) ([a15a080](https://github.com/arthurmaciel/ipe-lang/commit/a15a0803c760dd2f15f50a5e1c62cc5a5fee6b5d))
* **stdlib:** Cli.app view model -&gt; Lines msg (typed Cli view) ([#2173](https://github.com/arthurmaciel/ipe-lang/issues/2173)) ([b9b1a9a](https://github.com/arthurmaciel/ipe-lang/commit/b9b1a9a907dc75a1cec93aab61bdea3b8efc0edf))
* **stdlib:** Ipe.Ffi.Kernel + Ipe.Ffi.Rust doc veneers ([#1913](https://github.com/arthurmaciel/ipe-lang/issues/1913)) ([7b89636](https://github.com/arthurmaciel/ipe-lang/commit/7b89636a2a4afddc01d47c40b0f1f5556c01aec8))
* **stdlib:** opaque PDV SSOT for Duration at the Http timeout boundary ([#2141](https://github.com/arthurmaciel/ipe-lang/issues/2141)) ([#2160](https://github.com/arthurmaciel/ipe-lang/issues/2160)) ([21a300f](https://github.com/arthurmaciel/ipe-lang/commit/21a300f8ab7f9c2c66b281f336a31939a42aac3e))
* **tui:** dim/reverse text styles + user-facing terminal-attribute diagnostic ([#1824](https://github.com/arthurmaciel/ipe-lang/issues/1824)) ([b54b592](https://github.com/arthurmaciel/ipe-lang/commit/b54b592947202004c47f69676397c65be2f2d447))
* **types,lower:** Program shape-carrier + phantom shape tags (P1+P2-core) ([#2179](https://github.com/arthurmaciel/ipe-lang/issues/2179)) ([8c0ac71](https://github.com/arthurmaciel/ipe-lang/commit/8c0ac71505149d37dde652b6912fb0d34c684238))
* **watch:** dev-loop UX — output gutter, prominent URL, soft-yellow error banner, in-app status, floating debugger ([#1870](https://github.com/arthurmaciel/ipe-lang/issues/1870)) ([5c170a9](https://github.com/arthurmaciel/ipe-lang/commit/5c170a93edee0cda27dd7e611d899a03e78a64da))
* **web:** compose Cmd-wiring at update-arm Cmd position ([#2121](https://github.com/arthurmaciel/ipe-lang/issues/2121)) ([7ebe2cb](https://github.com/arthurmaciel/ipe-lang/commit/7ebe2cb59fba2b7d9a36b4a08772b32422a8cca7))


### Bug Fixes

* **annotate:** derive keyword spans from lexer tokens, not source scans ([3ed00e4](https://github.com/arthurmaciel/ipe-lang/commit/3ed00e46a06284f0c5fb1a45ca1760084615f133))
* **annotate:** drop stale source arg from in-module annotate test callers ([b7df2d5](https://github.com/arthurmaciel/ipe-lang/commit/b7df2d5ea57db46d6f7c6a5b51a6b1c7c35bc720))
* **annotate:** match canon defs to syntax values by name, not positional zip ([060ac2f](https://github.com/arthurmaciel/ipe-lang/commit/060ac2fb1d69d1312078a880d86b0180036d2635)), closes [#1837](https://github.com/arthurmaciel/ipe-lang/issues/1837)
* **annotate:** reject orphaned and duplicate type annotations instead of dropping them ([33599d6](https://github.com/arthurmaciel/ipe-lang/commit/33599d6f11d1e44aa98b9864ea3d082ce3acc0de))
* **backend:** backend-classify — peel-guard, exhaustive discriminant, SSOT escaper ([#2051](https://github.com/arthurmaciel/ipe-lang/issues/2051)) ([16c6130](https://github.com/arthurmaciel/ipe-lang/commit/16c6130f5d053c5014faaba00c3e2ae329af6c0f)), closes [#1941](https://github.com/arthurmaciel/ipe-lang/issues/1941) [#1943](https://github.com/arthurmaciel/ipe-lang/issues/1943) [#1944](https://github.com/arthurmaciel/ipe-lang/issues/1944)
* **backend:** injective rust-name fold + keyed collision detection ([251f5c1](https://github.com/arthurmaciel/ipe-lang/commit/251f5c1c652198af527892d309b2f68f6f0d386a)), closes [#1843](https://github.com/arthurmaciel/ipe-lang/issues/1843) [#1835](https://github.com/arthurmaciel/ipe-lang/issues/1835)
* **backend:** make the wasm kernel-wrapper prelude filter an allowlist ([c9b81c3](https://github.com/arthurmaciel/ipe-lang/commit/c9b81c356bbd9e1f1b28654771e8a1dccb1b1d1e)), closes [#1984](https://github.com/arthurmaciel/ipe-lang/issues/1984)
* **backend:** reject non-finite float literals + drop uncallable kernel polyfill ([#2060](https://github.com/arthurmaciel/ipe-lang/issues/2060)) ([c9b81c3](https://github.com/arthurmaciel/ipe-lang/commit/c9b81c356bbd9e1f1b28654771e8a1dccb1b1d1e)), closes [#1983](https://github.com/arthurmaciel/ipe-lang/issues/1983)
* **canon+ci:** fail-closed bare-import capability smuggle + g_http_live heavy timeout ([#2106](https://github.com/arthurmaciel/ipe-lang/issues/2106)) ([b27b41e](https://github.com/arthurmaciel/ipe-lang/commit/b27b41ee7ad88cfe044caf3edefab1e9cae280a6))
* **canon:** classify an unqualified shape-entry head through its exposing import ([#2118](https://github.com/arthurmaciel/ipe-lang/issues/2118)) ([792f0a8](https://github.com/arthurmaciel/ipe-lang/commit/792f0a853500358fc271acb0020bc1e59418b43e))
* **canon:** classify shape by resolved module of main's head, not the written token ([#2142](https://github.com/arthurmaciel/ipe-lang/issues/2142)) ([#2148](https://github.com/arthurmaciel/ipe-lang/issues/2148)) ([61de327](https://github.com/arthurmaciel/ipe-lang/commit/61de3277779113acf54944a082c598797d1d2e62))
* **canon:** drop unused mut in wildcard pattern-binder test ([fdfca7e](https://github.com/arthurmaciel/ipe-lang/commit/fdfca7e3c49066dffb127a7cc62a9ae6ce2ae558))
* **canon:** fail-closed asserted-path keywords and duplicate-def link gate ([#2055](https://github.com/arthurmaciel/ipe-lang/issues/2055)) ([a170d08](https://github.com/arthurmaciel/ipe-lang/commit/a170d08112b2909e318cec05c59aa99f1748acf2)), closes [#1929](https://github.com/arthurmaciel/ipe-lang/issues/1929) [#1931](https://github.com/arthurmaciel/ipe-lang/issues/1931)
* **canon:** sanction the const-eval drift-gate assert! for the panic scanner ([#2114](https://github.com/arthurmaciel/ipe-lang/issues/2114)) ([0417751](https://github.com/arthurmaciel/ipe-lang/commit/04177515e59d52f5a73687a8481c297a0d71d7e3))
* **ci:** classify guardian-sound as gate-external, keep in required set ([#2158](https://github.com/arthurmaciel/ipe-lang/issues/2158)) ([2ea67d3](https://github.com/arthurmaciel/ipe-lang/commit/2ea67d31e41ca7606ff79f964a5bd014a9a100a1))
* **ci:** count gate-external in the manifest-guard required-set sync check ([#2165](https://github.com/arthurmaciel/ipe-lang/issues/2165)) ([276fc67](https://github.com/arthurmaciel/ipe-lang/commit/276fc67a4b4239f012b5f41e208cfd91b4b8fdce))
* **ci:** document new e2e env vars + classify registry-smoke check disposition ([#2163](https://github.com/arthurmaciel/ipe-lang/issues/2163)) ([df41803](https://github.com/arthurmaciel/ipe-lang/commit/df4180306ac35f227f3ad7cef01eae809910f102))
* **cli:** auth/token, arg-parsing, help-parity, doc/project, and path-containment hardening ([a2a6258](https://github.com/arthurmaciel/ipe-lang/commit/a2a6258421a5b55160c9d3cd2aac78e61490723c))
* **cli:** security train — CSS allowlist, path containment, credential typing, ffi override, hash bounds, package-name ([#1911](https://github.com/arthurmaciel/ipe-lang/issues/1911)) ([e06d940](https://github.com/arthurmaciel/ipe-lang/commit/e06d940bd6839a6510d6fe963ffb98e08c04a01b))
* **cli:** text-boundary hygiene for watch/doc/runtime SSE ([6a584b4](https://github.com/arthurmaciel/ipe-lang/commit/6a584b4a358175a395be2c643d645213835a7aa4))
* **compiler:** fail-closed sandbox/lexer/doc-serve gates, shared stdlib-inject SSOT, duplicate-pattern-binder rejection ([c21c981](https://github.com/arthurmaciel/ipe-lang/commit/c21c9814ce36d7e1e2c8ef8c1a98005375a18b33))
* **compiler:** front-end train — parse/annotate/canon/types/diagnostics ([#1910](https://github.com/arthurmaciel/ipe-lang/issues/1910)) ([ca6d385](https://github.com/arthurmaciel/ipe-lang/commit/ca6d38515e680cf8f8e5cdc6395c1e3444371be7))
* **coverage:** probe build+run drives the real ipe binary + warm shared dep target ([#2145](https://github.com/arthurmaciel/ipe-lang/issues/2145)) ([6a832be](https://github.com/arthurmaciel/ipe-lang/commit/6a832be316954b37c75c2a8f345b3f43e995974e))
* Decode.nullable + accept () pattern ([#1820](https://github.com/arthurmaciel/ipe-lang/issues/1820)) ([3250c57](https://github.com/arthurmaciel/ipe-lang/commit/3250c57377b721f7c7653462e5aa2d1156b52caa))
* **diagnostics:** ipe-doc rename, SeeExplain drift-guard, code-tag + re-export fixes ([#2047](https://github.com/arthurmaciel/ipe-lang/issues/2047)) ([96bef9f](https://github.com/arthurmaciel/ipe-lang/commit/96bef9ff662b2a4955aff3087f849c3f337ff859)), closes [#1954](https://github.com/arthurmaciel/ipe-lang/issues/1954)
* **diagnostics:** report source spans and Ipê names in duplicate-Rust-name diagnostics ([8438f4a](https://github.com/arthurmaciel/ipe-lang/commit/8438f4adb3ff6130f81c4bb8776767284279a709))
* **diagnostics:** satisfy clippy on the IPE-N0048 name-fold sites ([f60859e](https://github.com/arthurmaciel/ipe-lang/commit/f60859e1666d41ecd7b0f98c1a613acb7abc9440))
* **doc:** HTML site — CLI-help SSOT, drop Terminal shape residual, parse Markdown, Ipê highlight ([#2130](https://github.com/arthurmaciel/ipe-lang/issues/2130)) ([ec2dee8](https://github.com/arthurmaciel/ipe-lang/commit/ec2dee8be19f42457af233d57cfeea33697d671e))
* **doc:** manual let-else in doc-serve conn handler (clippy pedantic) ([caffd10](https://github.com/arthurmaciel/ipe-lang/commit/caffd10f3d1858ed24c18750df78c97ba0cb6b0f))
* **docs:** register IPE_EMIT_PACKAGE_NAME in the env-var SSOT + regenerate env.md ([#2152](https://github.com/arthurmaciel/ipe-lang/issues/2152)) ([a8d1fbc](https://github.com/arthurmaciel/ipe-lang/commit/a8d1fbcb1a0af46714f7f73ed0ef2b9be12ca720))
* **docs:** strip exposing-list comments + reconcile ipe-docs source count ([03356dc](https://github.com/arthurmaciel/ipe-lang/commit/03356dcab5051dc866e57c97878a8cf9b5cf62d5))
* **docs:** strip interleaved comments from multi-line exposing lists ([84fbf4e](https://github.com/arthurmaciel/ipe-lang/commit/84fbf4ea8c48613668b9d8b8293c89a4b6919c3e)), closes [#1976](https://github.com/arthurmaciel/ipe-lang/issues/1976)
* **ffi:** refuse crate-root aliasing of std/core in the capability scan ([#2048](https://github.com/arthurmaciel/ipe-lang/issues/2048)) ([f7e46be](https://github.com/arthurmaciel/ipe-lang/commit/f7e46be809987a16c4c6458b9e058e589ad04bf4))
* **init:** escape template name holes through a typed IpeStringLiteral ([#1864](https://github.com/arthurmaciel/ipe-lang/issues/1864)) ([0a4af61](https://github.com/arthurmaciel/ipe-lang/commit/0a4af6150679f390bba19d40dceef5c82bf5d60e))
* **kernels,lower:** capability + SSOT + fail-closed train ([#1909](https://github.com/arthurmaciel/ipe-lang/issues/1909)) ([c5242c0](https://github.com/arthurmaciel/ipe-lang/commit/c5242c028c50fb69db00aee78723d4f137cf9f5d))
* **kernels:** accept insignificant trailing whitespace after the CSS !important flag ([09d3d61](https://github.com/arthurmaciel/ipe-lang/commit/09d3d619cb757d422af84b38f85175fdeb372ed3)), closes [#1948](https://github.com/arthurmaciel/ipe-lang/issues/1948)
* **kernels:** add an exhaustive drift guard for for_browser_module ([fe5fcd8](https://github.com/arthurmaciel/ipe-lang/commit/fe5fcd8a6ee390d6e6bef0d03895b1766f56f556)), closes [#1946](https://github.com/arthurmaciel/ipe-lang/issues/1946)
* **kernels:** disclose the capabilities auth/JWT kernels actually use ([bee64c8](https://github.com/arthurmaciel/ipe-lang/commit/bee64c82f24cb68dcfff2f527b88dbb0ade58cba)), closes [#1945](https://github.com/arthurmaciel/ipe-lang/issues/1945)
* **kernels:** make the kernel-table drift tripwire actually fail the build ([#2112](https://github.com/arthurmaciel/ipe-lang/issues/2112)) ([99b1bc8](https://github.com/arthurmaciel/ipe-lang/commit/99b1bc8c4a4359930b1ec7bfe05d24a70c57d83d))
* **lsp:** gate rename and completion keywords on the lexer's own table ([d294ba2](https://github.com/arthurmaciel/ipe-lang/commit/d294ba2485184fa0b63899ab735552d71fba9d94)), closes [#1971](https://github.com/arthurmaciel/ipe-lang/issues/1971)
* **lsp:** re-map quick-fix codes to the real diagnostic taxonomy ([f9b5741](https://github.com/arthurmaciel/ipe-lang/commit/f9b5741a3b21788b11c6f0e30b2d28af42de31b8)), closes [#1969](https://github.com/arthurmaciel/ipe-lang/issues/1969)
* **lsp:** recurse into ForeignCall args in the navigation walkers ([64f3057](https://github.com/arthurmaciel/ipe-lang/commit/64f3057b4d47a6d761d0938353ba51fc53b50f43)), closes [#1972](https://github.com/arthurmaciel/ipe-lang/issues/1972)
* **lsp:** stop Format Document from corrupting files ([0053b02](https://github.com/arthurmaciel/ipe-lang/commit/0053b02440e31c8762812724c2554626f1ab1dad)), closes [#1970](https://github.com/arthurmaciel/ipe-lang/issues/1970)
* **merge:** clippy let-else + unused-mut on merged fold sites ([e54b538](https://github.com/arthurmaciel/ipe-lang/commit/e54b53897d77a3797fa4958ecf6aaa513ef597a6))
* **parse:** desugar unary minus hygienically via qualified Basics.negate ([c11e010](https://github.com/arthurmaciel/ipe-lang/commit/c11e010c5b49c5366ca1a248d25f9246809bbae6))
* **parse:** parser front-end correctness + perf ([#2053](https://github.com/arthurmaciel/ipe-lang/issues/2053)) ([e3235cb](https://github.com/arthurmaciel/ipe-lang/commit/e3235cb6541c35244e7920b29f8197861aab23cb)), closes [#1829](https://github.com/arthurmaciel/ipe-lang/issues/1829) [#1919](https://github.com/arthurmaciel/ipe-lang/issues/1919) [#1920](https://github.com/arthurmaciel/ipe-lang/issues/1920) [#1921](https://github.com/arthurmaciel/ipe-lang/issues/1921) [#1922](https://github.com/arthurmaciel/ipe-lang/issues/1922) [#1924](https://github.com/arthurmaciel/ipe-lang/issues/1924) [#1926](https://github.com/arthurmaciel/ipe-lang/issues/1926) [#2008](https://github.com/arthurmaciel/ipe-lang/issues/2008)
* **runtime:** add encoding to http_client feature so form_url_decode resolves ([#2162](https://github.com/arthurmaciel/ipe-lang/issues/2162)) ([c52fa39](https://github.com/arthurmaciel/ipe-lang/commit/c52fa39bfa584f19c2811d878215f67778994287))
* **runtime:** eliminate environ mutation UB via a process-local env overlay ([#1873](https://github.com/arthurmaciel/ipe-lang/issues/1873)) ([566a75d](https://github.com/arthurmaciel/ipe-lang/commit/566a75d306bb9b3147b0f547b03b0bd6eb3ec249))
* **runtime:** email feature must enable secret ([#2052](https://github.com/arthurmaciel/ipe-lang/issues/2052)) ([edf78d7](https://github.com/arthurmaciel/ipe-lang/commit/edf78d7c276c520d5a1a5ff51a581035185ec148)), closes [#2001](https://github.com/arthurmaciel/ipe-lang/issues/2001)
* **sandbox:** deny-by-default macOS jail, scoped run-jail bind, non-destructive FreeBSD jail ([#2083](https://github.com/arthurmaciel/ipe-lang/issues/2083)) ([e9ccfb6](https://github.com/arthurmaciel/ipe-lang/commit/e9ccfb6e7f387f2d01b7f3ad0d9236da9f0913d5)), closes [#1959](https://github.com/arthurmaciel/ipe-lang/issues/1959)
* **sandbox:** kill the jailed child immediately on output-cap breach ([#1872](https://github.com/arthurmaciel/ipe-lang/issues/1872)) ([4a3a078](https://github.com/arthurmaciel/ipe-lang/commit/4a3a0788f6566a2d0f52c5acb3ce89de22a9fd7f))
* **sandbox:** kill x32-tagged syscall numbers in the x86_64 seccomp filter ([#1863](https://github.com/arthurmaciel/ipe-lang/issues/1863)) ([7a724a6](https://github.com/arthurmaciel/ipe-lang/commit/7a724a6421ea768b83c1b32a07244ccbd88cb9de))
* **security:** parse CSS raw-body and media-query gates against an allowlist instead of a denylist ([#1918](https://github.com/arthurmaciel/ipe-lang/issues/1918)) ([8ad7ed1](https://github.com/arthurmaciel/ipe-lang/commit/8ad7ed16c9c3a99044bdfbe0997473a352f9a29b))
* **soundness:** route unresolvable-symbol handling to CompilerBug in canon/types ([7048374](https://github.com/arthurmaciel/ipe-lang/commit/70483741ee3ccb631da6c5e62b46c8f59ec269f4)), closes [#1898](https://github.com/arthurmaciel/ipe-lang/issues/1898)
* **stdlib:** dedupe the Store SQL-identifier gate + restore ToString.fromTime ([#2068](https://github.com/arthurmaciel/ipe-lang/issues/2068)) ([d33b90d](https://github.com/arthurmaciel/ipe-lang/commit/d33b90d99601d6eebc575b046f33da74a3eab0c0))
* **stdlib:** register System.getcwd and gate the kernel-veneer export surface ([0a802b3](https://github.com/arthurmaciel/ipe-lang/commit/0a802b368aff9e6367f2767276b4a36a97a8f1c3))
* **stdlib:** registry-derived kernel-availability + Postgres rewriter regression tests ([#2093](https://github.com/arthurmaciel/ipe-lang/issues/2093)) ([c584137](https://github.com/arthurmaciel/ipe-lang/commit/c5841377ecd7953b0d73edd28608112b6f4c8bd2))
* **stdlib:** shorten first doc paragraph on inject SSOT (clippy nursery) ([6ec8643](https://github.com/arthurmaciel/ipe-lang/commit/6ec86437c4d74c77cddda93e98d391296176755c))
* **syntax,parse:** line-start-only doc fences + dedup identifier-word scan ([#2065](https://github.com/arthurmaciel/ipe-lang/issues/2065)) ([7aa4a91](https://github.com/arthurmaciel/ipe-lang/commit/7aa4a91babe29baba8baeedf3df44f05d3752584))
* **types:** bound list-pattern spine depth and drop per-lookup home clones in exhaustiveness ([4b1ca5b](https://github.com/arthurmaciel/ipe-lang/commit/4b1ca5b5955d4f437a0570e1992c4d5f4e9c8b90)), closes [#1934](https://github.com/arthurmaciel/ipe-lang/issues/1934) [#2015](https://github.com/arthurmaciel/ipe-lang/issues/2015)
* **types:** bound the exhaustiveness pass with a per-case work budget ([a6dead2](https://github.com/arthurmaciel/ipe-lang/commit/a6dead2c829b4624897cb412f9f758c0099a0f2a))
* **types:** make unification iterative so deep type spines can't overflow the native stack ([#1868](https://github.com/arthurmaciel/ipe-lang/issues/1868)) ([6cddfb2](https://github.com/arthurmaciel/ipe-lang/commit/6cddfb2575582f239d7308442af0c5adf9023f85)), closes [#1840](https://github.com/arthurmaciel/ipe-lang/issues/1840)
* **types:** reject conflated skolems and structure-vs-structure cycles; trim unify clones ([4886ba5](https://github.com/arthurmaciel/ipe-lang/commit/4886ba5b4c7c92f46c86fe497bd3c2af39e0d0eb)), closes [#1932](https://github.com/arthurmaciel/ipe-lang/issues/1932) [#1933](https://github.com/arthurmaciel/ipe-lang/issues/1933) [#2011](https://github.com/arthurmaciel/ipe-lang/issues/2011)
* **types:** tighten empty-module wildcard in nominal Con unification ([fd17788](https://github.com/arthurmaciel/ipe-lang/commit/fd17788478a1c1f9a57bf604b7c2901297a49e56))
* **types:** unify/exhaust soundness + perf (Group 1) ([7fee3c4](https://github.com/arthurmaciel/ipe-lang/commit/7fee3c4b79798a5cfffe650ec3500b88235de283))
* **types:** zonk memoizes shared solver DAGs instead of re-expanding them as trees ([#2100](https://github.com/arthurmaciel/ipe-lang/issues/2100)) ([d8dfbfe](https://github.com/arthurmaciel/ipe-lang/commit/d8dfbfecdc651e401a9e033671941bd11a6f8eff))
* Update merge queue configuration ([#2074](https://github.com/arthurmaciel/ipe-lang/issues/2074)) ([663bfb7](https://github.com/arthurmaciel/ipe-lang/commit/663bfb7810d65e1ea9f0f4eb93c0921f97a04a20))
* **wasm:** rename seen-&gt;observed to clear similar_names (clippy pedantic) ([c84be0a](https://github.com/arthurmaciel/ipe-lang/commit/c84be0a01366353119984d5fc62fc0b2d6682a9d))


### Performance Improvements

* **backend/rust:** skip no-op Task capture-clone walks and pre-size emit buffers ([#2105](https://github.com/arthurmaciel/ipe-lang/issues/2105)) ([f3db86a](https://github.com/arthurmaciel/ipe-lang/commit/f3db86a7c4a24bde909d8c54e0c3a53970a07439))
* **canon:** hoist stdlib-index copy-on-write out of the per-kernel loop ([#2056](https://github.com/arthurmaciel/ipe-lang/issues/2056)) ([6848e0d](https://github.com/arthurmaciel/ipe-lang/commit/6848e0dc398b78296f1aa3c931d99d5c8723520f)), closes [#2012](https://github.com/arthurmaciel/ipe-lang/issues/2012)
* **ci:** parallelize the doc gate + debug-build the shapes gate ([#2081](https://github.com/arthurmaciel/ipe-lang/issues/2081)) ([aa5db01](https://github.com/arthurmaciel/ipe-lang/commit/aa5db01d48a2e372962bf8234cb06b04b52438d7))
* **ci:** split the PR SEAL slice into three parallel sub-shards ([#2085](https://github.com/arthurmaciel/ipe-lang/issues/2085)) ([4780f34](https://github.com/arthurmaciel/ipe-lang/commit/4780f34933bfd51f3c3692e0ec834ca41b1c12b3))
* **cli,intern:** stream exe hash + memoize epoch; hoist tree buffer; borrow in Symbol serde ([#2069](https://github.com/arthurmaciel/ipe-lang/issues/2069)) ([f2d3f84](https://github.com/arthurmaciel/ipe-lang/commit/f2d3f8446eb4bc31342c794532aedaf18d0bfee9))
* **cli:** hoist embedded-runtime manifest to LazyLock + length pre-check in write_if_changed ([#2119](https://github.com/arthurmaciel/ipe-lang/issues/2119)) ([896d754](https://github.com/arthurmaciel/ipe-lang/commit/896d754d13677b6c13c28d515e2258f9033cad5b))
* **compiler:** constrain/resolve/lower efficiency improvements ([#2117](https://github.com/arthurmaciel/ipe-lang/issues/2117)) ([142fc8e](https://github.com/arthurmaciel/ipe-lang/commit/142fc8e5785d759af614c0a26a50a16927780e4f))
* **db:** range-scan per-module type projection and halve topo-sort path clones ([#2046](https://github.com/arthurmaciel/ipe-lang/issues/2046)) ([5f68fad](https://github.com/arthurmaciel/ipe-lang/commit/5f68fad7e83d13e5fcba762863afacea4061d42d)), closes [#2004](https://github.com/arthurmaciel/ipe-lang/issues/2004)
* **kernels:** skip the CSS escape-decoded reparse and binary-search the function allowlist ([#2075](https://github.com/arthurmaciel/ipe-lang/issues/2075)) ([9e490b9](https://github.com/arthurmaciel/ipe-lang/commit/9e490b9219af0b9e1a3b498c24be6ad917a0625d)), closes [#2013](https://github.com/arthurmaciel/ipe-lang/issues/2013)
* **lower:** fuse pre-lowering symbol-pool count walks into one pass ([#2120](https://github.com/arthurmaciel/ipe-lang/issues/2120)) ([ecceaae](https://github.com/arthurmaciel/ipe-lang/commit/ecceaae899a6fb6b9d9842be8a8f6a4470d4036a))
* **lsp:** add a reusable LineIndex for span&lt;-&gt;position conversion ([64a7e87](https://github.com/arthurmaciel/ipe-lang/commit/64a7e87fd1920de09c9c0c3047c1fedc72864b17)), closes [#2019](https://github.com/arthurmaciel/ipe-lang/issues/2019)
* **lsp:** main-loop clone/scan removal + semantic-tokens line index ([#2049](https://github.com/arthurmaciel/ipe-lang/issues/2049)) ([0b23ca6](https://github.com/arthurmaciel/ipe-lang/commit/0b23ca6b590e7e59fb3bcfe2070b1871a5d809ec)), closes [#1973](https://github.com/arthurmaciel/ipe-lang/issues/1973)
* **lsp:** share the salsa Arc and nest the solved-env map in completion ([0242ecc](https://github.com/arthurmaciel/ipe-lang/commit/0242ecc28286f028c93fd6bb1d8da33a40a44b20)), closes [#2018](https://github.com/arthurmaciel/ipe-lang/issues/2018)
* **parse:** eliminate per-token clone in bump and full char-pair Vec in lexer ([543496d](https://github.com/arthurmaciel/ipe-lang/commit/543496de1e880746272f883ca75b617c2fe7f834))

## [0.1.78](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.77...ipe-v0.1.78) (2026-09-04)


### Features

* **audit:** security-advisory database + fail-closed audit cross-check ([#1745](https://github.com/arthurmaciel/ipe-lang/issues/1745)) ([4920d22](https://github.com/arthurmaciel/ipe-lang/commit/4920d2244ff28d6cacf2f635f0e27ab7626aa794))
* **browser:** FilePicker + Camera device modules (Part of [#1519](https://github.com/arthurmaciel/ipe-lang/issues/1519)) ([#1780](https://github.com/arthurmaciel/ipe-lang/issues/1780)) ([31c9131](https://github.com/arthurmaciel/ipe-lang/commit/31c9131a42e4f3763c19acc497aec9cea4df1de3))
* **browser:** Geolocation + full Clipboard web-API modules over the port capability mechanism ([#1718](https://github.com/arthurmaciel/ipe-lang/issues/1718)) ([ea67cf8](https://github.com/arthurmaciel/ipe-lang/commit/ea67cf8f64a2379a912b1d6c923907f6228e177a))
* **browser:** Ipe.Browser.Microphone.captureAudio — one-shot audio clip (Part of [#1519](https://github.com/arthurmaciel/ipe-lang/issues/1519)) ([#1788](https://github.com/arthurmaciel/ipe-lang/issues/1788)) ([8c26f6e](https://github.com/arthurmaciel/ipe-lang/commit/8c26f6ebf4563e73bba535149368140fad4757e1))
* **browser:** remaining web-API modules — Notification/Storage/Vibration/Share/Battery/NetworkInfo (Closes [#1701](https://github.com/arthurmaciel/ipe-lang/issues/1701)) ([#1775](https://github.com/arthurmaciel/ipe-lang/issues/1775)) ([049ef53](https://github.com/arthurmaciel/ipe-lang/commit/049ef5384017cb29a3cfdfc66201b1b7a7f289a2))
* **browser:** Web API batch — Speech, Permission, Gamepad, Visibility, MediaQuery, Connectivity ([#1808](https://github.com/arthurmaciel/ipe-lang/issues/1808)) ([b1df9b3](https://github.com/arthurmaciel/ipe-lang/commit/b1df9b3539ab2714cb5203961355b00913f251fa))
* **canon,lsp:** cross-module rename operation over the reference index ([#1743](https://github.com/arthurmaciel/ipe-lang/issues/1743)) ([7f7bc45](https://github.com/arthurmaciel/ipe-lang/commit/7f7bc456005a25d2143b551b0e9bd2a76f4dba5c))
* **canon:** change-signature deltas — closed shape-delta set + call-site transformer ([#1752](https://github.com/arthurmaciel/ipe-lang/issues/1752)) ([e3f1f01](https://github.com/arthurmaciel/ipe-lang/commit/e3f1f0196b566cbc55fbaf56c9fbf8c818247ec1))
* **canon:** resolver-accurate reference index (Part of [#1685](https://github.com/arthurmaciel/ipe-lang/issues/1685)) ([#1732](https://github.com/arthurmaciel/ipe-lang/issues/1732)) ([9cd427e](https://github.com/arthurmaciel/ipe-lang/commit/9cd427ea9ce271eb67985aec88d3204233d4b80e))
* **cli:** package.ipe delivery record + ipe init shape/runtime/host wizard ([#1809](https://github.com/arthurmaciel/ipe-lang/issues/1809)) ([3504919](https://github.com/arthurmaciel/ipe-lang/commit/35049195dce1c9d2c8889b2199ba2a2eae047d18))
* **coverage:** add DiagnosticSurface — coverage matrix for IPE-XXXX codes ([#1734](https://github.com/arthurmaciel/ipe-lang/issues/1734)) ([fa0b62c](https://github.com/arthurmaciel/ipe-lang/commit/fa0b62c976cc9902b339a793960e13fb1995d4fc))
* **coverage:** combine CLI/compiler/foreign/package surface matrices (Closes [#1687](https://github.com/arthurmaciel/ipe-lang/issues/1687) [#1691](https://github.com/arthurmaciel/ipe-lang/issues/1691) [#1693](https://github.com/arthurmaciel/ipe-lang/issues/1693) [#1694](https://github.com/arthurmaciel/ipe-lang/issues/1694)) ([#1747](https://github.com/arthurmaciel/ipe-lang/issues/1747)) ([a48a2c6](https://github.com/arthurmaciel/ipe-lang/commit/a48a2c65177b6d764401a3494b662ecd513c6ebf))
* **coverage:** dynamic + doc columns — documented/doc-example/build-run/composes/runtime-fn/wasm ([#1673](https://github.com/arthurmaciel/ipe-lang/issues/1673), [#1674](https://github.com/arthurmaciel/ipe-lang/issues/1674)) ([#1711](https://github.com/arthurmaciel/ipe-lang/issues/1711)) ([2f08fbb](https://github.com/arthurmaciel/ipe-lang/commit/2f08fbb91772411b5afa1bc20fcc7b0134197091))
* **coverage:** EnvVarSurface + item-generic runner ([#1686](https://github.com/arthurmaciel/ipe-lang/issues/1686)) ([#1722](https://github.com/arthurmaciel/ipe-lang/issues/1722)) ([d6045ef](https://github.com/arthurmaciel/ipe-lang/commit/d6045ef93d060db2932dedcbdf3f2afb2d7c0d76))
* **coverage:** refusal-tested detector recognizes Code:: constant assertions ([#1748](https://github.com/arthurmaciel/ipe-lang/issues/1748)) ([500fd82](https://github.com/arthurmaciel/ipe-lang/commit/500fd825bca64e89a3af33853c6b90f5beb21b6d))
* **coverage:** stdlib coverage-matrix spine — StdlibSurface + runner + static columns ([#1671](https://github.com/arthurmaciel/ipe-lang/issues/1671), [#1672](https://github.com/arthurmaciel/ipe-lang/issues/1672)) ([#1698](https://github.com/arthurmaciel/ipe-lang/issues/1698)) ([d90e0b3](https://github.com/arthurmaciel/ipe-lang/commit/d90e0b3fcbfc560f5949588df2701e26aa0ebf55))
* **debugger:** import + reproduce determinism gate (Step 3) ([#1755](https://github.com/arthurmaciel/ipe-lang/issues/1755)) ([21dd037](https://github.com/arthurmaciel/ipe-lang/commit/21dd037f71f859e7875d0a61cfbe6512dc68e4e5))
* **debugger:** live inspection surface — GET /_ipe/debug/inspect (Step 4) ([#1758](https://github.com/arthurmaciel/ipe-lang/issues/1758)) ([08c5e07](https://github.com/arthurmaciel/ipe-lang/commit/08c5e07bfcad1fa806303df55851183b1b4d260d))
* **debugger:** message-recorder JSON export endpoint ([#1733](https://github.com/arthurmaciel/ipe-lang/issues/1733)) ([db358fd](https://github.com/arthurmaciel/ipe-lang/commit/db358fdca9e06e316b53e30571b0a7fb0fdfc3a0))
* **debugger:** stepTo / back / forward time-travel (Step 2) ([#1754](https://github.com/arthurmaciel/ipe-lang/issues/1754)) ([8da5113](https://github.com/arthurmaciel/ipe-lang/commit/8da51139e097b2fedd7a2c7e7d4f1b8002352606))
* **ffi:** capability-jail consent gate — refuse an un-granted native crossing (Part of [#396](https://github.com/arthurmaciel/ipe-lang/issues/396)) ([#1771](https://github.com/arthurmaciel/ipe-lang/issues/1771)) ([5c7678f](https://github.com/arthurmaciel/ipe-lang/commit/5c7678f3655f49fb6bc9e02f559ea0cebea0d478))
* **ffi:** correlated port→Task bridge — one-shot browser requests as Task ([#1730](https://github.com/arthurmaciel/ipe-lang/issues/1730)) ([cafa226](https://github.com/arthurmaciel/ipe-lang/commit/cafa2267df5e3b9fe99608488fc860d5e027941b))
* **ffi:** Ipe.Ffi.* taxonomy rename (Ipe.Js→Ipe.Ffi.Js, Ffi.kernel→Ipe.Ffi.Kernel, widget→Ipe.Ffi.Js.CustomElement) ([#1750](https://github.com/arthurmaciel/ipe-lang/issues/1750)) ([5576ac0](https://github.com/arthurmaciel/ipe-lang/commit/5576ac095506643ebfebec6c059396ab75323acb))
* **ffi:** Ipe.Ffi.Rust.fn native-binding surface (Part of [#396](https://github.com/arthurmaciel/ipe-lang/issues/396)) ([#1760](https://github.com/arthurmaciel/ipe-lang/issues/1760)) ([1d4e7dc](https://github.com/arthurmaciel/ipe-lang/commit/1d4e7dca3ac1dd734eeb206e3f8e43ed2a0b0af1))
* **ffi:** opaque-handle foreign declarations (Part of [#396](https://github.com/arthurmaciel/ipe-lang/issues/396) incr2) ([#1768](https://github.com/arthurmaciel/ipe-lang/issues/1768)) ([3c4bad0](https://github.com/arthurmaciel/ipe-lang/commit/3c4bad07c33c2bef8102e8dfde3a9797eac063d4))
* **ffi:** record-syntax foreign declarations, retire the Ffi.* pipe-builder (Closes [#1675](https://github.com/arthurmaciel/ipe-lang/issues/1675)) ([#1761](https://github.com/arthurmaciel/ipe-lang/issues/1761)) ([466847d](https://github.com/arthurmaciel/ipe-lang/commit/466847d09bf9d56c853ecec2f98182f630c33adc))
* **ffi:** Rust.const native-constant reads — infallible bare-scalar FFI (Closes [#396](https://github.com/arthurmaciel/ipe-lang/issues/396)) ([#1772](https://github.com/arthurmaciel/ipe-lang/issues/1772)) ([5c296a0](https://github.com/arthurmaciel/ipe-lang/commit/5c296a010cfd9eef25622226294348a27a4d9c38))
* **ffi:** session-stream port primitive — the correlated third port shape (Part of [#1519](https://github.com/arthurmaciel/ipe-lang/issues/1519)) ([#1785](https://github.com/arthurmaciel/ipe-lang/issues/1785)) ([4b20d55](https://github.com/arthurmaciel/ipe-lang/commit/4b20d5565be0c48548230b5258e44e2cbb0c0b22))
* **lint:** wire ipe lint --fix for prim-param and adjacent-bools sig-change rules ([#1757](https://github.com/arthurmaciel/ipe-lang/issues/1757)) ([1d1478d](https://github.com/arthurmaciel/ipe-lang/commit/1d1478de93035876379aba0780e5c5fb69a9d514))
* **lint:** wrapper-consistency rule emits SigFix + wired into --fix ([#1656](https://github.com/arthurmaciel/ipe-lang/issues/1656)) ([#1766](https://github.com/arthurmaciel/ipe-lang/issues/1766)) ([09cb794](https://github.com/arthurmaciel/ipe-lang/commit/09cb79493dbeb0404c5e894176021c75d76c6365))
* **pack:** capability→OS-permission derivation (Part of [#1519](https://github.com/arthurmaciel/ipe-lang/issues/1519)) ([#1782](https://github.com/arthurmaciel/ipe-lang/issues/1782)) ([4f2fb9e](https://github.com/arthurmaciel/ipe-lang/commit/4f2fb9e2929b76625ea5af31c92abb874a5c6f50))
* **pack:** ipe pack --target desktop[:os] — desktop bundle packager (Part of [#1519](https://github.com/arthurmaciel/ipe-lang/issues/1519)) ([#1789](https://github.com/arthurmaciel/ipe-lang/issues/1789)) ([f6b117d](https://github.com/arthurmaciel/ipe-lang/commit/f6b117dabd67de269213df5354d47fe023266cd0))
* **pack:** ipe pack --target mobile:ios|android — mobile webview packager (Part of [#1519](https://github.com/arthurmaciel/ipe-lang/issues/1519)) ([#1790](https://github.com/arthurmaciel/ipe-lang/issues/1790)) ([2c3c687](https://github.com/arthurmaciel/ipe-lang/commit/2c3c68756e02c8814617c9f1ff72d318f60616e4))
* **parse:** pipeline applicator operators |= and |. (parser sequencing sugar) ([#1744](https://github.com/arthurmaciel/ipe-lang/issues/1744)) ([23ca61a](https://github.com/arthurmaciel/ipe-lang/commit/23ca61acff312c7888d43292db82ed32f6d9b082))
* **registry:** client Pages read-path + ipe audit advisory fetch (Part of [#1696](https://github.com/arthurmaciel/ipe-lang/issues/1696)) ([#1776](https://github.com/arthurmaciel/ipe-lang/issues/1776)) ([10caec7](https://github.com/arthurmaciel/ipe-lang/commit/10caec7e5bc0849f96f3cc935ba1914598564110))
* **registry:** keyless publisher-signature trust subsystem (Part of [#1696](https://github.com/arthurmaciel/ipe-lang/issues/1696)) ([#1777](https://github.com/arthurmaciel/ipe-lang/issues/1777)) ([497a6cb](https://github.com/arthurmaciel/ipe-lang/commit/497a6cbad6e49595f7c69ebcd6d0e2710fe069ca))
* **security:** per-capability JS-port disclosure + fail-closed app-boundary consent gate ([#1703](https://github.com/arthurmaciel/ipe-lang/issues/1703)) ([#1710](https://github.com/arthurmaciel/ipe-lang/issues/1710)) ([5ac53b6](https://github.com/arthurmaciel/ipe-lang/commit/5ac53b647822b2677d8cc0668df18a6fc5ae803b))
* **security:** reserve the Ipe.* module namespace to the blessed first-party publisher ([#1708](https://github.com/arthurmaciel/ipe-lang/issues/1708)) ([6cf3d8b](https://github.com/arthurmaciel/ipe-lang/commit/6cf3d8b5615df44d1473ffb263ae47d1066e9f30))
* **shape:** Tui.app/Cli.app terminal entries + typed webview signal (retire manifest string-scan) ([#1802](https://github.com/arthurmaciel/ipe-lang/issues/1802)) ([98cbe7c](https://github.com/arthurmaciel/ipe-lang/commit/98cbe7cdefcd38888329cbc36b0ffc2ad83869f6))
* **ui:** control-flow hole for Ui templating (increment 1, [#1647](https://github.com/arthurmaciel/ipe-lang/issues/1647)) ([#1746](https://github.com/arthurmaciel/ipe-lang/issues/1746)) ([95897c5](https://github.com/arthurmaciel/ipe-lang/commit/95897c5caaf3525e20d904e29a175b2cd5bba6d2))
* **ui:** float-attr hole — typed numeric attr templating (Closes [#1647](https://github.com/arthurmaciel/ipe-lang/issues/1647)) ([#1764](https://github.com/arthurmaciel/ipe-lang/issues/1764)) ([3284774](https://github.com/arthurmaciel/ipe-lang/commit/32847743f0312dc75fc5ca97adda49536c7dded9))
* **ui:** list-hole for Ui templating (increment 2, [#1647](https://github.com/arthurmaciel/ipe-lang/issues/1647)) ([#1756](https://github.com/arthurmaciel/ipe-lang/issues/1756)) ([fc5969e](https://github.com/arthurmaciel/ipe-lang/commit/fc5969edc9f3339c1788d6e24b0568012924f920))
* **ui:** wrapper-hole for model-chosen wrapping element (Part of [#1647](https://github.com/arthurmaciel/ipe-lang/issues/1647)) ([#1759](https://github.com/arthurmaciel/ipe-lang/issues/1759)) ([e2ab87a](https://github.com/arthurmaciel/ipe-lang/commit/e2ab87a29144131cbebc424d579259352448bde4))
* **wasm:** enable typed Ipe.Js ports under --target wasm ([#1707](https://github.com/arthurmaciel/ipe-lang/issues/1707)) ([1cfe8ec](https://github.com/arthurmaciel/ipe-lang/commit/1cfe8ec3c5ada1d87cbe008c5fe0fbd3842a0be0))
* **web:** combined value-hole + handler-hole Ui template materializer ([#1729](https://github.com/arthurmaciel/ipe-lang/issues/1729)) ([eeb83e9](https://github.com/arthurmaciel/ipe-lang/commit/eeb83e9dda8bbab34b8549b6a5b864b85b064432))
* **web:** emit-wire model-dependent onClick to handler-id templates ([#1724](https://github.com/arthurmaciel/ipe-lang/issues/1724)) ([989f401](https://github.com/arthurmaciel/ipe-lang/commit/989f401919e7f839262ca58f477e414a7940ca85))
* **web:** program-as-data init→session-scoped ([#1665](https://github.com/arthurmaciel/ipe-lang/issues/1665)) + Cmd wiring→data ([#1666](https://github.com/arthurmaciel/ipe-lang/issues/1666)) ([#1690](https://github.com/arthurmaciel/ipe-lang/issues/1690)) ([6a97ee5](https://github.com/arthurmaciel/ipe-lang/commit/6a97ee553537067bccacdba40dcc7991c2af0476))


### Bug Fixes

* **browser:** track geolocation watch ids as a set so double-watch is fully clearable ([#1727](https://github.com/arthurmaciel/ipe-lang/issues/1727)) ([cf3af75](https://github.com/arthurmaciel/ipe-lang/commit/cf3af7511555e3e803583c700badf9a47a21452c))
* **constrain:** home the Db.Store/Codec ctor schemes so composed uses lower ([#1712](https://github.com/arthurmaciel/ipe-lang/issues/1712)) ([#1713](https://github.com/arthurmaciel/ipe-lang/issues/1713)) ([4c11da2](https://github.com/arthurmaciel/ipe-lang/commit/4c11da215de99ea640e5992874127152298b7466))
* **constrain:** home the Email.EmailProvider ctor scheme so point-free send lowers ([#1715](https://github.com/arthurmaciel/ipe-lang/issues/1715)) ([8c47aaf](https://github.com/arthurmaciel/ipe-lang/commit/8c47aafa55f52bf282cff7bdb00e6487a459f2f0))
* **coverage:** resolve 14 of 26 home holes via QUALIFIER_MODULE_OVERRIDES ([#1736](https://github.com/arthurmaciel/ipe-lang/issues/1736)) ([0c60c3c](https://github.com/arthurmaciel/ipe-lang/commit/0c60c3c606619ccb7349aa21ee51290f6f492715))
* **emit:** emit dom::req::WebReq (target-neutral) instead of web::WebReq ([#1787](https://github.com/arthurmaciel/ipe-lang/issues/1787)) ([e2c20bd](https://github.com/arthurmaciel/ipe-lang/commit/e2c20bd101e0b0bad11a902048960584a5f7e497))
* **ffi:** auto-inject Rust.Ffi qualifier when Ipe.Ffi.Rust is imported (Closes [#1762](https://github.com/arthurmaciel/ipe-lang/issues/1762)) ([#1769](https://github.com/arthurmaciel/ipe-lang/issues/1769)) ([8a053ae](https://github.com/arthurmaciel/ipe-lang/commit/8a053aefc0be76d8f7f4b16c6f3442a177526472))
* **lower:** enforce a concrete init request type on Ipe.Tea.Web apps (reject poly init, IPE-N0046) ([#1723](https://github.com/arthurmaciel/ipe-lang/issues/1723)) ([16194a4](https://github.com/arthurmaciel/ipe-lang/commit/16194a4b2e1be0aaad5bc5571835091f526935dd))
* **runtime:** dedup tinyvec to a single url-gated declaration ([#1803](https://github.com/arthurmaciel/ipe-lang/issues/1803)) ([020c664](https://github.com/arthurmaciel/ipe-lang/commit/020c66409e4c97ead77460afab48ce9587664d06))


### Performance Improvements

* **ci:** tier build_run coverage sweep off per-PR seal-slice to full-gate e2e ([#1731](https://github.com/arthurmaciel/ipe-lang/issues/1731)) ([f4a9e2d](https://github.com/arthurmaciel/ipe-lang/commit/f4a9e2d36b7d9afb74af9b08548e2dbb390d50f3))

## [0.1.77](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.76...ipe-v0.1.77) (2026-09-02)


### Features

* **backend:** Phase-2 partial evaluation — fold pure literal builder pipelines (animation/Css hot-swap) ([#1633](https://github.com/arthurmaciel/ipe-lang/issues/1633)) ([ef7ed0b](https://github.com/arthurmaciel/ipe-lang/commit/ef7ed0b510844e9d41d65a5b455feece6a367fe6))
* **cli:** ipe lint (+ --fix) — extensible static analysis with Ipê-native lint.ipe config ([#1659](https://github.com/arthurmaciel/ipe-lang/issues/1659)) ([7622343](https://github.com/arthurmaciel/ipe-lang/commit/762234367b433c6be7b93736076e411db4a9bb90))
* **cli:** record-syntax package.ipe manifest, retiring the pipe-builder (BREAKING) ([#1662](https://github.com/arthurmaciel/ipe-lang/issues/1662)) ([bb37a94](https://github.com/arthurmaciel/ipe-lang/commit/bb37a94b098c3117d4dda7332bc5aa5c22c46047))
* **ffi:** async-breadth — structural spawn choke-point (honest cancel + panic across all async-FFI shapes) ([#1658](https://github.com/arthurmaciel/ipe-lang/issues/1658)) ([b34cb02](https://github.com/arthurmaciel/ipe-lang/commit/b34cb029281c7b354712e071c4e5404a7c8799df))
* **padata:** handler-id holes — model-dependent Ui event handlers templatize ([#1668](https://github.com/arthurmaciel/ipe-lang/issues/1668)) ([#1680](https://github.com/arthurmaciel/ipe-lang/issues/1680)) ([78dff5d](https://github.com/arthurmaciel/ipe-lang/commit/78dff5de69b4c9002f3ea2d8e7ed2a8968d00b2c))
* **stdlib:** Ipe.Parser — native parser combinators (elm/parser parity) ([#397](https://github.com/arthurmaciel/ipe-lang/issues/397)) ([#1660](https://github.com/arthurmaciel/ipe-lang/issues/1660)) ([021d774](https://github.com/arthurmaciel/ipe-lang/commit/021d7746dc96756f33a012aba2b2e92e79b4c6ad))
* **ui:** elm-parity render fixes — default shrink, overlay anchor, alignment, describe, overflow, explain ([#1632](https://github.com/arthurmaciel/ipe-lang/issues/1632)) ([f233d73](https://github.com/arthurmaciel/ipe-lang/commit/f233d73f53f011bf431df8821156e65dc0f9334a))
* **watch:** dev-only build-status banner in the browser ([#1651](https://github.com/arthurmaciel/ipe-lang/issues/1651)) ([053904f](https://github.com/arthurmaciel/ipe-lang/commit/053904f7b3479229879cf0190365f699e80ff433))
* **watch:** Ipe.Ui view holes + float/color attr templating ([#1647](https://github.com/arthurmaciel/ipe-lang/issues/1647)) ([#1682](https://github.com/arthurmaciel/ipe-lang/issues/1682)) ([1999cd4](https://github.com/arthurmaciel/ipe-lang/commit/1999cd44dcc3cf3935006ea9220f6a22372cc8ec))
* **watch:** wrapper-transparent Ipe.Ui subtree hot-swap ([#1654](https://github.com/arthurmaciel/ipe-lang/issues/1654)) ([4f41bb6](https://github.com/arthurmaciel/ipe-lang/commit/4f41bb648f018f5bfde448255145ed83b93b9750))
* **watch:** zero-compile hot-swap of static Ipe.Html view subtrees (materializer) ([#1641](https://github.com/arthurmaciel/ipe-lang/issues/1641)) ([34f6618](https://github.com/arthurmaciel/ipe-lang/commit/34f6618605b623fcd194c49db51e0b12696caf96))
* **watch:** zero-compile hot-swap of static Ipe.Ui view subtrees (materializer) ([#1648](https://github.com/arthurmaciel/ipe-lang/issues/1648)) ([a39a5f3](https://github.com/arthurmaciel/ipe-lang/commit/a39a5f32161c642955099d06332ec744795bb46c))
* **web:** additive Msg-variant hot-swap — schema-tagged Msg-set codec + gate + /_ipe/hot-msg ([#1664](https://github.com/arthurmaciel/ipe-lang/issues/1664)) ([#1683](https://github.com/arthurmaciel/ipe-lang/issues/1683)) ([96abdfd](https://github.com/arthurmaciel/ipe-lang/commit/96abdfd0dcc3fcce416ef72355d750a786ac93b9))
* **web:** additive-Model-extension — preserve session state across an additive Model change ([#1640](https://github.com/arthurmaciel/ipe-lang/issues/1640)) ([4c3d37f](https://github.com/arthurmaciel/ipe-lang/commit/4c3d37f0749588c25d2132adbd507bb5a9c71fbd))
* **web:** subscriptions -&gt; sub descriptions (data-describable tick hot-swap) ([#1684](https://github.com/arthurmaciel/ipe-lang/issues/1684)) ([4d82e67](https://github.com/arthurmaciel/ipe-lang/commit/4d82e678efa1d26aec18b3d4a4951f3e9843c444))
* **web:** TEA update→transition-table foundation (inert datum + total apply_transition) ([#1646](https://github.com/arthurmaciel/ipe-lang/issues/1646)) ([b509f0b](https://github.com/arthurmaciel/ipe-lang/commit/b509f0b9625a00004bcc57c5893205b57033b1c5))
* **web:** wire update-arm transition hot-swap end-to-end (emit + watch + endpoint + SEAL) ([#1661](https://github.com/arthurmaciel/ipe-lang/issues/1661)) ([323212d](https://github.com/arthurmaciel/ipe-lang/commit/323212d50650211d3fa7476e56d93021fffd85cf))


### Bug Fixes

* **ci:** green the chronic SEAL/emit failures + add bounded seal-slice anti-rot gate ([#1650](https://github.com/arthurmaciel/ipe-lang/issues/1650)) ([09a4074](https://github.com/arthurmaciel/ipe-lang/commit/09a40743f4509cba2ec0cb4c231ad87695c9b875))
* **ci:** green the install-smoke badge (auth release lookup) + timestamp golden newline ([#1642](https://github.com/arthurmaciel/ipe-lang/issues/1642)) ([f08e0e8](https://github.com/arthurmaciel/ipe-lang/commit/f08e0e825dbcecfdf8aab28e4dd8f7d2a34f615f))
* **compiler:** lower composed higher-order combinators (eta-expansion + returned-fn application) ([#1669](https://github.com/arthurmaciel/ipe-lang/issues/1669)) ([4e7595b](https://github.com/arthurmaciel/ipe-lang/commit/4e7595ba5c864938ab28fe3f1b96b9dfc0a04f61))
* **sandbox:** netns-jail capability preflight — skip net tests when unprivileged userns can't configure loopback ([#1676](https://github.com/arthurmaciel/ipe-lang/issues/1676)) ([#1689](https://github.com/arthurmaciel/ipe-lang/issues/1689)) ([2b77ce5](https://github.com/arthurmaciel/ipe-lang/commit/2b77ce531aeca263b68245b36fd857737fd55b4c))
* **watch:** appearance hot-swap default-on for ipe watch (opt-out IPE_WATCH_NO_HOT_APPEARANCE); prod stays clean ([#1635](https://github.com/arthurmaciel/ipe-lang/issues/1635)) ([a931b1b](https://github.com/arthurmaciel/ipe-lang/commit/a931b1b89017cafe3d29507a931916cc0ac4a534))
* **watch:** dev blue-green default-on (opt-out IPE_WATCH_NO_BLUEGREEN) + swap toast replaces the rebuild reconnect banner ([#1636](https://github.com/arthurmaciel/ipe-lang/issues/1636)) ([708895d](https://github.com/arthurmaciel/ipe-lang/commit/708895db130e345f159b699d844452ec88dbf499))
* **watch:** model-state reset — test fixture, --reset-state flag, History::reset_to_init, debug overlay ([#1681](https://github.com/arthurmaciel/ipe-lang/issues/1681)) ([447966f](https://github.com/arthurmaciel/ipe-lang/commit/447966fe30a14f730611b2fe025aa0314aa1216f))

## [0.1.76](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.75...ipe-v0.1.76) (2026-08-31)


### Features

* **dev-loop:** hoist raw-CSS/URL string appearance values into hot-swap registry ([#1630](https://github.com/arthurmaciel/ipe-lang/issues/1630)) ([705cab6](https://github.com/arthurmaciel/ipe-lang/commit/705cab637ad730f59e3efad4bce70a2fdc190512))
* **dev-loop:** hoist typed numeric Font/Border/Background/Ui appearance scalars into hot-swap registry ([#1628](https://github.com/arthurmaciel/ipe-lang/issues/1628)) ([66ff383](https://github.com/arthurmaciel/ipe-lang/commit/66ff3835132a4f508a4bcfc9f97f853ced51ca36))
* **watch:** warmth-based build accel — sccache for a cold target's deps, incremental once warm ([#1629](https://github.com/arthurmaciel/ipe-lang/issues/1629)) ([3294e05](https://github.com/arthurmaciel/ipe-lang/commit/3294e058a570fc92ecbacc9cc41fd3c44acba8e1))

## [0.1.75](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.74...ipe-v0.1.75) (2026-08-31)


### Features

* **dev-loop:** appearance-literal registry + widen to Ui attr/text + Html (appearance Steps 5/5b) ([#1616](https://github.com/arthurmaciel/ipe-lang/issues/1616)) ([e2f3863](https://github.com/arthurmaciel/ipe-lang/commit/e2f3863337634446c14ff93147a410087227cf66))
* **dev-loop:** hoist Ui.image alt/src literals into appearance hot-swap ([#1624](https://github.com/arthurmaciel/ipe-lang/issues/1624)) ([ecedd32](https://github.com/arthurmaciel/ipe-lang/commit/ecedd32af398eaad912976ef85a01d1ab8119806))
* **dev-loop:** live literal-patch endpoint — apply + re-render, Model-preserving (appearance Step 2) ([#1610](https://github.com/arthurmaciel/ipe-lang/issues/1610)) ([816e5ff](https://github.com/arthurmaciel/ipe-lang/commit/816e5ff876a938879a4e85b181f599cc12ed7bdd))
* **dev-loop:** style-literal hoist into per-view LiteralTable (appearance hot-swap Step 1) ([#1604](https://github.com/arthurmaciel/ipe-lang/issues/1604)) ([11c3bd4](https://github.com/arthurmaciel/ipe-lang/commit/11c3bd4d3a3f6967c5531a402353eb2665b40356))
* **dev-loop:** typed style-value literal hoist (padding/spacing/size + rgb channels) ([#1608](https://github.com/arthurmaciel/ipe-lang/issues/1608)) ([e15e862](https://github.com/arthurmaciel/ipe-lang/commit/e15e8624eec17c20e02aac0b7970af6845df252c))
* **watch:** appearance hot-swap classifier — emit-diff picks style edits, pushes a live table patch, skips cargo ([#1615](https://github.com/arthurmaciel/ipe-lang/issues/1615)) ([9a2a6bd](https://github.com/arthurmaciel/ipe-lang/commit/9a2a6bde47044270bcfc7b1f37103c08cd33a801))
* **watch:** dev blue-green Model handoff across the swap + sqlx-free file store ([#1606](https://github.com/arthurmaciel/ipe-lang/issues/1606) Step 2) ([#1612](https://github.com/arthurmaciel/ipe-lang/issues/1612)) ([486f416](https://github.com/arthurmaciel/ipe-lang/commit/486f416b009e0765157634121bfb534693e2d467))
* **watch:** dev-only blue-green binary swap — zero socket-drop on rebuild ([#1606](https://github.com/arthurmaciel/ipe-lang/issues/1606) Step 1) ([#1609](https://github.com/arthurmaciel/ipe-lang/issues/1609)) ([1920fec](https://github.com/arthurmaciel/ipe-lang/commit/1920fecd48b5af8360f15b3e14b758b5966ed30e))
* **watch:** extend appearance hot-swap to Ipe.Css values through the sanitizer ([#1626](https://github.com/arthurmaciel/ipe-lang/issues/1626)) ([4942cd2](https://github.com/arthurmaciel/ipe-lang/commit/4942cd20c958c127cb3f7033803d95c2cfa4d048))


### Bug Fixes

* **backend:** distinct model schema-tag per IrType kind + pairwise-distinctness test ([#1623](https://github.com/arthurmaciel/ipe-lang/issues/1623)) ([7957ada](https://github.com/arthurmaciel/ipe-lang/commit/7957ada8cd94faa2ba4885a05d496e08835252f7))
* **clippy:** clear the db,web --all-targets leg — reword doc-list + allow unwrap/expect in test helpers ([#1622](https://github.com/arthurmaciel/ipe-lang/issues/1622)) ([0f58f6e](https://github.com/arthurmaciel/ipe-lang/commit/0f58f6e6a6d4d4538d976c2717f8f04579a27971))
* **web/store:** fail-closed store config + bounded checkpoint decode + 0600 session map ([#1625](https://github.com/arthurmaciel/ipe-lang/issues/1625)) ([ace40d3](https://github.com/arthurmaciel/ipe-lang/commit/ace40d325710bae27645977fcfdedff3dba2c2ce))


### Performance Improvements

* **watch:** incremental sccache-free emitted-app rebuild for the dev inner loop ([#1617](https://github.com/arthurmaciel/ipe-lang/issues/1617)) ([#1618](https://github.com/arthurmaciel/ipe-lang/issues/1618)) ([dd27f3f](https://github.com/arthurmaciel/ipe-lang/commit/dd27f3f45ecb4850fd14c6b138a1fba55fb69735))

## [0.1.74](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.73...ipe-v0.1.74) (2026-08-31)


### Features

* **cli:** idempotent ipe upgrade + health integration ([#1550](https://github.com/arthurmaciel/ipe-lang/issues/1550)) ([#1577](https://github.com/arthurmaciel/ipe-lang/issues/1577)) ([5b33f3f](https://github.com/arthurmaciel/ipe-lang/commit/5b33f3fe7275c506894ccc78bfda92587b0077ca))
* **docs:** ipe doc IPE_&lt;VAR&gt; resolves env vars from ENV_VARS ([#1593](https://github.com/arthurmaciel/ipe-lang/issues/1593)) ([#1601](https://github.com/arthurmaciel/ipe-lang/issues/1601)) ([850f3f1](https://github.com/arthurmaciel/ipe-lang/commit/850f3f145d57e81a8eb9cf319e2a3ce4b65f1eb7))
* **manifest:** package.ipe programs/exposedModules + ipe init --lib ([#1598](https://github.com/arthurmaciel/ipe-lang/issues/1598)) ([8a3bbd1](https://github.com/arthurmaciel/ipe-lang/commit/8a3bbd1515c23da3ff229bc8151221e9c9f34275))
* **playground:** one-command setup + CI gate (closes [#317](https://github.com/arthurmaciel/ipe-lang/issues/317)) ([#1596](https://github.com/arthurmaciel/ipe-lang/issues/1596)) ([aa734cc](https://github.com/arthurmaciel/ipe-lang/commit/aa734ccdc70596c93e1cc64ed3895cffed2ffd35))
* **process:** Process.runInPty — pty-backed child runner via rustix pty ([#1579](https://github.com/arthurmaciel/ipe-lang/issues/1579)) ([0f50e24](https://github.com/arthurmaciel/ipe-lang/commit/0f50e24541a9432a09495bc02a98c6044fed5e6b))
* **stdlib:** typed Http.StatusCode + Ui.ImageSrc ([#1522](https://github.com/arthurmaciel/ipe-lang/issues/1522), [#1530](https://github.com/arthurmaciel/ipe-lang/issues/1530)) ([#1564](https://github.com/arthurmaciel/ipe-lang/issues/1564)) ([badc28c](https://github.com/arthurmaciel/ipe-lang/commit/badc28cbb3b280b9faf8125560037d9eca270382))
* **time:** fromMillis/toMillis at Ipe.Time surface + Timestamp/Duration type-safety proof ([#1587](https://github.com/arthurmaciel/ipe-lang/issues/1587)) ([#1595](https://github.com/arthurmaciel/ipe-lang/issues/1595)) ([e672e2b](https://github.com/arthurmaciel/ipe-lang/commit/e672e2bba45f8336abae09a3af53b42249f83d88))
* **watch:** per-phase rebuild timing behind IPE_WATCH_TIMING ([#1590](https://github.com/arthurmaciel/ipe-lang/issues/1590)) ([f924b3e](https://github.com/arthurmaciel/ipe-lang/commit/f924b3ecc390b2a19b44b298170939b8895d904f))
* **web-runtime:** LiteralTable primitive + dev==prod conformance (perf Step 2 groundwork) ([#1600](https://github.com/arthurmaciel/ipe-lang/issues/1600)) ([9d0d84a](https://github.com/arthurmaciel/ipe-lang/commit/9d0d84a51b2f745713943516cd25712fd6f77efa))


### Bug Fixes

* **cache:** suffix every Ipe Int literal with i64 — fixes Cache.get miss on Int values ([#1551](https://github.com/arthurmaciel/ipe-lang/issues/1551)) ([ad47223](https://github.com/arthurmaciel/ipe-lang/commit/ad47223d7d57686a9eec6bc5ebb923ba721b88ac))
* **docs:** read -- | line doc-comments so all 77 stdlib modules get a reference page ([#1572](https://github.com/arthurmaciel/ipe-lang/issues/1572)) ([#1585](https://github.com/arthurmaciel/ipe-lang/issues/1585)) ([4361232](https://github.com/arthurmaciel/ipe-lang/commit/4361232b6d52671d4065426fc1f573dfc443a880))
* **docs:** regenerate stdlib reference for reworded boolAttribute doc-comment ([7b17c66](https://github.com/arthurmaciel/ipe-lang/commit/7b17c66ca787c0f1da671ab0fcb329ae9afcf9d9))
* **emit:** email-only programs no longer pull http_stream+tea into vendored crate ([#1545](https://github.com/arthurmaciel/ipe-lang/issues/1545)) ([#1576](https://github.com/arthurmaciel/ipe-lang/issues/1576)) ([7d8c143](https://github.com/arthurmaciel/ipe-lang/commit/7d8c1430883c5b19ae656353975bdc9ec8228bd0))
* **file:** readFileLimit takes ByteSize instead of bare Int (IPE-[#1422](https://github.com/arthurmaciel/ipe-lang/issues/1422)) ([#1574](https://github.com/arthurmaciel/ipe-lang/issues/1574)) ([46f4cdb](https://github.com/arthurmaciel/ipe-lang/commit/46f4cdb444b35b0c9cb5b9021ee328e2023f81e0))
* **html-attrs:** correct boolAttribute doc and scrub internal comment reference-impl names ([#1582](https://github.com/arthurmaciel/ipe-lang/issues/1582)) ([59d967b](https://github.com/arthurmaciel/ipe-lang/commit/59d967b8be2e8f042343603c0b917077036fc520))
* **modset:** append seal_codec for render-capable shapes (closes [#1581](https://github.com/arthurmaciel/ipe-lang/issues/1581)) ([#1597](https://github.com/arthurmaciel/ipe-lang/issues/1597)) ([fe68d3d](https://github.com/arthurmaciel/ipe-lang/commit/fe68d3d566cbf38dcfe054a20a9f7c79d253ec45))
* **regen-goldens:** drive build_project for multi-module package.ipe fixtures ([#1566](https://github.com/arthurmaciel/ipe-lang/issues/1566)) ([#1567](https://github.com/arthurmaciel/ipe-lang/issues/1567)) ([2e4442a](https://github.com/arthurmaciel/ipe-lang/commit/2e4442a9b0cb8072c958ddcd908f7587ea6cb3fc))
* **runtime:** drop crate:: qualifier on IpeTask in tea.rs app-handle fields ([#1549](https://github.com/arthurmaciel/ipe-lang/issues/1549)) ([#1580](https://github.com/arthurmaciel/ipe-lang/issues/1580)) ([f060c9d](https://github.com/arthurmaciel/ipe-lang/commit/f060c9dba0fdd1374431c918da667edce6d0bdf3))
* **upgrade:** return ExitCode not process::exit (unbreak main panic-scan) ([#1583](https://github.com/arthurmaciel/ipe-lang/issues/1583)) ([80f9a90](https://github.com/arthurmaciel/ipe-lang/commit/80f9a90c8594777b733e01dd85ac75d5deff3c29))
* **watch:** frame the build-failed diagnostic and soften red to light yellow ([#1571](https://github.com/arthurmaciel/ipe-lang/issues/1571)) ([2df51e3](https://github.com/arthurmaciel/ipe-lang/commit/2df51e315e79582b8fbd14c0d06a2d17ebbfd69a))

## [0.1.73](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.72...ipe-v0.1.73) (2026-08-31)


### Features

* **cli:** add a blocking HTTP client and the version_check unit ([#1547](https://github.com/arthurmaciel/ipe-lang/issues/1547)) ([ea3191d](https://github.com/arthurmaciel/ipe-lang/commit/ea3191d8b16c4dcb20eeb09b0a56087dc735556a))
* **init:** offer health check in interactive wizard mode ([#1553](https://github.com/arthurmaciel/ipe-lang/issues/1553)) ([06ff2c9](https://github.com/arthurmaciel/ipe-lang/commit/06ff2c99658660b331c5bedc0a024a407c1704d9)), closes [#1515](https://github.com/arthurmaciel/ipe-lang/issues/1515)
* **seal:** type-driven runtime-feature closure — a gated type is unemittable without its feature ([#1542](https://github.com/arthurmaciel/ipe-lang/issues/1542)) ([4a319b7](https://github.com/arthurmaciel/ipe-lang/commit/4a319b7ad20c2c5a301cdf70460c67b93227dae9))
* **web:** jittered fast-reconnect window so a restart reattaches promptly ([#1554](https://github.com/arthurmaciel/ipe-lang/issues/1554)) ([cb07a54](https://github.com/arthurmaciel/ipe-lang/commit/cb07a548826a75629a883712aed1d0b460cb2ed6))


### Bug Fixes

* **db:** enforce Store immutable policy in updateAs (row-level auth) ([#1556](https://github.com/arthurmaciel/ipe-lang/issues/1556)) ([a6134ee](https://github.com/arthurmaciel/ipe-lang/commit/a6134ee64a8c9fe968fd6ab0c42b80f268a1fdbc))
* **doc:** inject a module's own imports into its doc-example context ([#1525](https://github.com/arthurmaciel/ipe-lang/issues/1525)) ([#1544](https://github.com/arthurmaciel/ipe-lang/issues/1544)) ([7d6e87d](https://github.com/arthurmaciel/ipe-lang/commit/7d6e87d76990bbc9591761b1239e95f00c2c377a))
* **email+locale:** extend uses_email to all email kernels+types; add uses_locale end-to-end ([#1555](https://github.com/arthurmaciel/ipe-lang/issues/1555)) ([df8825b](https://github.com/arthurmaciel/ipe-lang/commit/df8825b9cb685387f3ac0ec0801e123b698fa197))
* **lower:** home-guard StreamWriter/WebSocketServer/WebSocketServerCfg opaque names ([#1464](https://github.com/arthurmaciel/ipe-lang/issues/1464)) ([#1543](https://github.com/arthurmaciel/ipe-lang/issues/1543)) ([88ef035](https://github.com/arthurmaciel/ipe-lang/commit/88ef035905c1a141c2e57001e1f0d919ccc3b3c7))
* **lower:** move-ownership discipline on destructure-parameter components (SEAL borrow track) ([#1560](https://github.com/arthurmaciel/ipe-lang/issues/1560)) ([361c43a](https://github.com/arthurmaciel/ipe-lang/commit/361c43ad705bcbaa6cb24108160681a1cab2f0c2))
* **lower:** support refutable tuple-pattern columns on a non-literal scrutinee ([#1532](https://github.com/arthurmaciel/ipe-lang/issues/1532)) ([#1558](https://github.com/arthurmaciel/ipe-lang/issues/1558)) ([9cd04c7](https://github.com/arthurmaciel/ipe-lang/commit/9cd04c70cb8074764de82390bc82c5717e0a32ea))
* **test:** set uses_console in the type-only feature-closure Module ([#1552](https://github.com/arthurmaciel/ipe-lang/issues/1552)) ([1fa7aee](https://github.com/arthurmaciel/ipe-lang/commit/1fa7aee63afbbb75208b6bd63f488fbd341bda62))

## [0.1.72](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.71...ipe-v0.1.72) (2026-08-30)


### Features

* **stdlib:** make-invalid-states-unrepresentable — HeadingLevel ADT + typed Head URLs (§D-10, §C-7) ([#1511](https://github.com/arthurmaciel/ipe-lang/issues/1511)) ([e40522d](https://github.com/arthurmaciel/ipe-lang/commit/e40522d57a41268e9da4d0bb02b1d70783ee147b))
* **stdlib:** typed-primitive newtypes Port/Duration/ByteSize + de-Bool cellCompare ([#1422](https://github.com/arthurmaciel/ipe-lang/issues/1422), [#1428](https://github.com/arthurmaciel/ipe-lang/issues/1428)) ([#1507](https://github.com/arthurmaciel/ipe-lang/issues/1507)) ([a8619d7](https://github.com/arthurmaciel/ipe-lang/commit/a8619d7d8406ea0730e3da4fe88d805790cb6ed5))


### Bug Fixes

* **io,secret:** Io.readSecret returns an opaque Secret, not plaintext String ([#1462](https://github.com/arthurmaciel/ipe-lang/issues/1462)) ([#1506](https://github.com/arthurmaciel/ipe-lang/issues/1506)) ([9a3c733](https://github.com/arthurmaciel/ipe-lang/commit/9a3c73336025fde0d6c7b53948dc60082dba6693))
* **lower:** home-guard kernel-implicit opaque type names against user shadows ([#1516](https://github.com/arthurmaciel/ipe-lang/issues/1516)) ([b6862cf](https://github.com/arthurmaciel/ipe-lang/commit/b6862cfcd50e5c0b81a9b91f6dd660ead71ae508))


### Performance Improvements

* **watch:** aggressive dev-watch stop — zero SIGTERM grace (instant SIGKILL) frees the port immediately on reload; tighter readiness poll ([#1513](https://github.com/arthurmaciel/ipe-lang/issues/1513)) ([8b0db66](https://github.com/arthurmaciel/ipe-lang/commit/8b0db66768f2f4dab7049865e957a9db4de8cb8a))

## [0.1.71](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.70...ipe-v0.1.71) (2026-08-30)


### Features

* **canon:** static-pin main's shape — reject a runtime-branched entry (IPE-N0045) ([#1502](https://github.com/arthurmaciel/ipe-lang/issues/1502)) ([85aa4a4](https://github.com/arthurmaciel/ipe-lang/commit/85aa4a4ab9d2c2c8bc3a7d45f3b4b5cf25203e5c))
* **canon:** terminal split — Ipe.Tea.Tui/Cli surface + Ipe.Server.* namespace (§14.3) ([#1505](https://github.com/arthurmaciel/ipe-lang/issues/1505)) ([190a883](https://github.com/arthurmaciel/ipe-lang/commit/190a883571c7cc665b74d093bac9569df95dbd77))
* **db:** arithmetic projection operators + rename CoalesceOperand-&gt;ProjectionOperand ([#1463](https://github.com/arthurmaciel/ipe-lang/issues/1463)) ([3dd35e6](https://github.com/arthurmaciel/ipe-lang/commit/3dd35e66faeac4e67fb123c0bcf13b986a6574d3)), closes [#1401](https://github.com/arthurmaciel/ipe-lang/issues/1401)
* **secret:** ban committed string literals in Secret.fromString (IPE-L0150) ([#1469](https://github.com/arthurmaciel/ipe-lang/issues/1469)) ([d19d40c](https://github.com/arthurmaciel/ipe-lang/commit/d19d40cd25a0f7e64600f4e0fbe3fa22729c6f7b))
* **shape:** Web.embed + Server.mountApp — mount a web app into a server on one port (§6/§9) ([#1503](https://github.com/arthurmaciel/ipe-lang/issues/1503)) ([f810bcd](https://github.com/arthurmaciel/ipe-lang/commit/f810bcdff0d67e848593dcd9f40f63fd5b7bc2a9))
* **stdlib:** migrate 6 tail modules to compiled-source (Maybe/Result/Basics/Log/Level/Error) ([#1500](https://github.com/arthurmaciel/ipe-lang/issues/1500)) ([5a458fa](https://github.com/arthurmaciel/ipe-lang/commit/5a458fa84d6b92713b35ce605f36ba5c05357ab1))
* **stdlib:** migrate 9 modules to compiled-source (String/Io/Dict/List/Task/Uuid/Decimal/Encoding/Math) ([#1493](https://github.com/arthurmaciel/ipe-lang/issues/1493)) ([23c4171](https://github.com/arthurmaciel/ipe-lang/commit/23c417112e6f4c265efc63ff5d8398b5c6434a15))
* **stdlib:** migrate Ipe.Bitwise from kernel-qualifier to compiled-source ([#1466](https://github.com/arthurmaciel/ipe-lang/issues/1466)) ([2028d11](https://github.com/arthurmaciel/ipe-lang/commit/2028d11f0e123d850aaa3ffdde17bc0167d430cc))
* **stdlib:** migrate Ipe.Bytes to compiled-source (Refs [#1447](https://github.com/arthurmaciel/ipe-lang/issues/1447)) ([#1480](https://github.com/arthurmaciel/ipe-lang/issues/1480)) ([28087e5](https://github.com/arthurmaciel/ipe-lang/commit/28087e5e22d6938590de2749ae5e1f9316c1d7a8))
* **stdlib:** migrate Ipe.Char to compiled-source (Refs [#1460](https://github.com/arthurmaciel/ipe-lang/issues/1460)) ([#1481](https://github.com/arthurmaciel/ipe-lang/issues/1481)) ([6a28959](https://github.com/arthurmaciel/ipe-lang/commit/6a28959ace9b206f6e39f5e01ea574e778ff6f6b))
* **stdlib:** migrate Ipe.Debug to compiled-source (Refs [#1458](https://github.com/arthurmaciel/ipe-lang/issues/1458)) ([#1473](https://github.com/arthurmaciel/ipe-lang/issues/1473)) ([0e268c4](https://github.com/arthurmaciel/ipe-lang/commit/0e268c4884f4408bea722aa73c549812d3709f8f))
* **stdlib:** migrate Ipe.Set to compiled-source (Refs [#1449](https://github.com/arthurmaciel/ipe-lang/issues/1449)) ([#1479](https://github.com/arthurmaciel/ipe-lang/issues/1479)) ([46c079c](https://github.com/arthurmaciel/ipe-lang/commit/46c079c3c0ba39e18f97644ce14e6dddd99f8261))
* **stdlib:** migrate Ipe.Time to compiled-source ([#1451](https://github.com/arthurmaciel/ipe-lang/issues/1451)) ([#1474](https://github.com/arthurmaciel/ipe-lang/issues/1474)) ([1ac154c](https://github.com/arthurmaciel/ipe-lang/commit/1ac154c72dabde6836c0078eafac8e8d5fa096f6))


### Bug Fixes

* **cli:** ipe watch resolves the runtime like build, not eject ([#1498](https://github.com/arthurmaciel/ipe-lang/issues/1498)) ([5688d3d](https://github.com/arthurmaciel/ipe-lang/commit/5688d3d5e2f46c86ae2d888203a48c804c72e8ea))
* **regen-goldens:** normalise runtime dep path to placeholder on write ([#1467](https://github.com/arthurmaciel/ipe-lang/issues/1467)) ([#1504](https://github.com/arthurmaciel/ipe-lang/issues/1504)) ([f46bba8](https://github.com/arthurmaciel/ipe-lang/commit/f46bba82a8b9e03d5c44e21108cfb6075154c2fc))

## [0.1.70](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.69...ipe-v0.1.70) (2026-08-28)


### Features

* **#1423:** add `ipe doc --type` type-signature search ([#1441](https://github.com/arthurmaciel/ipe-lang/issues/1441)) ([03c892f](https://github.com/arthurmaciel/ipe-lang/commit/03c892f7b899d0bfcde5e14a32697b04cc44f303))
* **chart:** nominal Point/Range/Pixel records to stop axis transposition ([#1439](https://github.com/arthurmaciel/ipe-lang/issues/1439)) ([9e7a56c](https://github.com/arthurmaciel/ipe-lang/commit/9e7a56ccb0f9832407b9a27751da667103f0f3fc)), closes [#1425](https://github.com/arthurmaciel/ipe-lang/issues/1425)
* **cli:** ipe release production command replacing deploy, gating Debug.* on the release verb ([8370ac6](https://github.com/arthurmaciel/ipe-lang/commit/8370ac6710133c2c080a763c2e6fbaa53a0ae16b))
* **db:** add Db.Decode.decimal combinator + Decimal/Money round-trip test coverage ([#1394](https://github.com/arthurmaciel/ipe-lang/issues/1394)) ([e062dda](https://github.com/arthurmaciel/ipe-lang/commit/e062dda6bc6973524bc751645d06bffec45de0bf))
* **db:** replace stringly-typed projection triple with ProjectionTerm/CoalesceOperand ([#1432](https://github.com/arthurmaciel/ipe-lang/issues/1432)) ([#1442](https://github.com/arthurmaciel/ipe-lang/issues/1442)) ([8b953c4](https://github.com/arthurmaciel/ipe-lang/commit/8b953c4ccd16712b67a1d73e5806d51f46f13925))
* **db:** typed join query for Ipe.Db.Store (single-statement joins, no N+1) ([#1391](https://github.com/arthurmaciel/ipe-lang/issues/1391)) ([b481499](https://github.com/arthurmaciel/ipe-lang/commit/b4814999c186cbca307b402dcc48e6516a92c7b3))
* **debugger:** client-WASM overlay UI — message list + scrubber panel ([#1372](https://github.com/arthurmaciel/ipe-lang/issues/1372)) ([df54cee](https://github.com/arthurmaciel/ipe-lang/commit/df54cee45cdb55277e07d8d51647ce4eb0b8b416))
* **debugger:** server-driven time-travel for server-rendered web apps ([#1373](https://github.com/arthurmaciel/ipe-lang/issues/1373)) ([bdbd00a](https://github.com/arthurmaciel/ipe-lang/commit/bdbd00a332634f65e204eb28620d4f3aed85fdbf))
* **debugger:** terminal time-travel for TUI apps ([#1376](https://github.com/arthurmaciel/ipe-lang/issues/1376)) ([f48f00b](https://github.com/arthurmaciel/ipe-lang/commit/f48f00beb058c53c79d7d18c53319c213ed13a7f))
* **debugger:** time-travel recorder core and --debugger build flag ([4127d43](https://github.com/arthurmaciel/ipe-lang/commit/4127d4301ad9ed23655effeb7e1ca2d0389c5156))
* **doc:** HTML site navigation — persistent header, teach-first landing, index pages, search ([#1414](https://github.com/arthurmaciel/ipe-lang/issues/1414)) ([fcaf4ea](https://github.com/arthurmaciel/ipe-lang/commit/fcaf4ea968691286dc00726163e8308f5d5c1d94))
* **doc:** unified DocBundle index, kind:key resolver, [[ref]] rewriter, fuzzy CLI search ([#1411](https://github.com/arthurmaciel/ipe-lang/issues/1411)) ([472ed15](https://github.com/arthurmaciel/ipe-lang/commit/472ed157619d0758beaf5979d83e240bae56554b))
* **file:** add Ipe.File.walk and Ipe.File.walkMatching ([#1419](https://github.com/arthurmaciel/ipe-lang/issues/1419)) ([5d48d4a](https://github.com/arthurmaciel/ipe-lang/commit/5d48d4ae17efec7ecefe5bde140455c9e7e01993))
* **http:** RedirectPolicy ADT replaces followRedirects:Bool + maxRedirects:Int ([#1426](https://github.com/arthurmaciel/ipe-lang/issues/1426)) ([#1443](https://github.com/arthurmaciel/ipe-lang/issues/1443)) ([63db3b8](https://github.com/arthurmaciel/ipe-lang/commit/63db3b86e2f437776482cc30acfa6202b65a8667))
* **js-interop:** live JS port transport — client-WASM wire + lowering flip ([#1382](https://github.com/arthurmaciel/ipe-lang/issues/1382)) ([af6af79](https://github.com/arthurmaciel/ipe-lang/commit/af6af795350037cb3796b9bcc784cd5b363cf91e))
* **js-interop:** server-driven JS port transport with per-session channels ([#1383](https://github.com/arthurmaciel/ipe-lang/issues/1383)) ([1da30de](https://github.com/arthurmaciel/ipe-lang/commit/1da30debb712ac89ade9e1a2667756a919fbbfca))
* **js-interop:** typed JS ports boundary (Js.send/subscribe/sync) with fail-closed gates ([4305f16](https://github.com/arthurmaciel/ipe-lang/commit/4305f169e96b2d34f98ce1293d451f530adb53c3))
* **js-interop:** wasm-client custom-element adapter (property down, CustomEvent up) ([db94075](https://github.com/arthurmaciel/ipe-lang/commit/db940755f056f72bc3a4682b0c93bfc7de50cd47))
* **shape:** opaque App IrType leaves + Shape surface Stage 1 ([#1444](https://github.com/arthurmaciel/ipe-lang/issues/1444)) ([aed588a](https://github.com/arthurmaciel/ipe-lang/commit/aed588aa737699d8db03c54e0ffb69e41aaa30bd))
* **stdlib:** Debug.todo typed hole and Debug.explain layout outline ([505c329](https://github.com/arthurmaciel/ipe-lang/commit/505c3295474c830e3ba080517d89ac4a1b2a8452)), closes [#910](https://github.com/arthurmaciel/ipe-lang/issues/910) [#912](https://github.com/arthurmaciel/ipe-lang/issues/912)
* **stdlib:** Opacity newtype for opacity/alpha — NaN-guard + clamp ([#1427](https://github.com/arthurmaciel/ipe-lang/issues/1427)) ([#1440](https://github.com/arthurmaciel/ipe-lang/issues/1440)) ([04fe209](https://github.com/arthurmaciel/ipe-lang/commit/04fe209b133cac8eb29d1b4b396426e91b927965))
* **stdlib:** typed named-field cubicBezier with X-clamp in Ui.Transition/Animation ([#1437](https://github.com/arthurmaciel/ipe-lang/issues/1437)) ([3b707bc](https://github.com/arthurmaciel/ipe-lang/commit/3b707bca9d578b06b66136f12bb9d194b6c2e236)), closes [#1424](https://github.com/arthurmaciel/ipe-lang/issues/1424)
* **store:** add Store.literal for SQL-parameter projection elements ([#1413](https://github.com/arthurmaciel/ipe-lang/issues/1413)) ([2705a78](https://github.com/arthurmaciel/ipe-lang/commit/2705a78d532648a0fea69e521cb7a11ebdb85b61))
* **store:** Store.coalesce projection operator + 3-tuple projection descriptor ABI ([#1429](https://github.com/arthurmaciel/ipe-lang/issues/1429)) ([171dad4](https://github.com/arthurmaciel/ipe-lang/commit/171dad40e82a9ab515d8401fb1fc1f8d7a3dd4ba))
* **store:** Store.upper / Store.lower projection operators + IPE-L0149 type label ([#1415](https://github.com/arthurmaciel/ipe-lang/issues/1415)) ([2d2a3d9](https://github.com/arthurmaciel/ipe-lang/commit/2d2a3d9a8e55f736b52e5916036a5fab96ea2b85))
* **task:** replace RetryPolicy kind+jitter fields with BackoffStrategy ADT ([#1421](https://github.com/arthurmaciel/ipe-lang/issues/1421)) ([#1438](https://github.com/arthurmaciel/ipe-lang/issues/1438)) ([fd873ad](https://github.com/arthurmaciel/ipe-lang/commit/fd873ad074c22b5d6cb927bcc36c9aac2ef321ca))


### Bug Fixes

* **debugger:** render server-driven overlay labels via IpeStringify::ipe_show ([#1397](https://github.com/arthurmaciel/ipe-lang/issues/1397)) ([5dae5e8](https://github.com/arthurmaciel/ipe-lang/commit/5dae5e8249fba35eda02d707e887440b62e695c7)), closes [#1375](https://github.com/arthurmaciel/ipe-lang/issues/1375)
* **doc:** render indented code blocks in HTML doc-comments as &lt;pre&gt; ([#1400](https://github.com/arthurmaciel/ipe-lang/issues/1400)) ([6d3ff00](https://github.com/arthurmaciel/ipe-lang/commit/6d3ff0017f34db151add9e91d71d8ad6de2d0cd7))

## [0.1.69](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.68...ipe-v0.1.69) (2026-08-26)


### Features

* **auth:** session revocation via Ipe.Auth.Revocation ([#1269](https://github.com/arthurmaciel/ipe-lang/issues/1269) P3) ([2c03489](https://github.com/arthurmaciel/ipe-lang/commit/2c03489d3a0f5ee658cf461a76431815bc2ee2a6))
* **capabilities:** infer and disclose the custom-element browser-JS capability with index-to-page hash pinning ([#1361](https://github.com/arthurmaciel/ipe-lang/issues/1361)) ([4e1ee0f](https://github.com/arthurmaciel/ipe-lang/commit/4e1ee0f7e7d99f75bb387d35cedeb0aa0d382304))
* **cli:** ContainedRelPath + read_to_string_capped + bounded module walk ([#1295](https://github.com/arthurmaciel/ipe-lang/issues/1295) [#1297](https://github.com/arthurmaciel/ipe-lang/issues/1297)) ([38ce6de](https://github.com/arthurmaciel/ipe-lang/commit/38ce6de82ad29ba1e8c5fe127d9cf1c307c57332))
* **config:** typed cross-cutting config gap-fill ([#1268](https://github.com/arthurmaciel/ipe-lang/issues/1268)) ([#1335](https://github.com/arthurmaciel/ipe-lang/issues/1335)) ([969c769](https://github.com/arthurmaciel/ipe-lang/commit/969c769500e883281f68b956bc73d84758af166f))
* **email:** type provider credentials as Secret, revealed only at the send boundary ([26bf00a](https://github.com/arthurmaciel/ipe-lang/commit/26bf00ad68171a388887c25d65ae8c9eac132885)), closes [#1336](https://github.com/arthurmaciel/ipe-lang/issues/1336)
* **ffi:** [#1289](https://github.com/arthurmaciel/ipe-lang/issues/1289) P2 — ipe migrate config, retire toml [[rust.define.*]], re-green iced-counter ([#1318](https://github.com/arthurmaciel/ipe-lang/issues/1318)) ([33dc3bd](https://github.com/arthurmaciel/ipe-lang/commit/33dc3bdd78c0cba4f44b2e52616d499999bca40c))
* **ffi:** add `foreign` declaration surface + `Ffi.*` blessed-call lift (Phase 1, [#1289](https://github.com/arthurmaciel/ipe-lang/issues/1289)) ([35d113f](https://github.com/arthurmaciel/ipe-lang/commit/35d113f7002b0c2522b0fbd1033b26e9bc72fa65))
* **js-interop:** client glue + SRI widget serving (WP5) ([398972a](https://github.com/arthurmaciel/ipe-lang/commit/398972ace1fdf6967d75b3ef8368c269b79c7de5))
* **js-interop:** custom-element emission + WebView-serde shape gate (WP4) ([b8e0299](https://github.com/arthurmaciel/ipe-lang/commit/b8e02994b97c29513df9bca504bd036899f7e06b))
* **js-interop:** WP1 — pin CustomElement seal exclusion of Secret + reserved sink types ([#1350](https://github.com/arthurmaciel/ipe-lang/issues/1350)) ([3aa7412](https://github.com/arthurmaciel/ipe-lang/commit/3aa74120f564da1fcdc267983fec8ac037e36145))
* **js-interop:** WP2 — customElement constructor + Ui.widget kernel sigs ([#333](https://github.com/arthurmaciel/ipe-lang/issues/333)) ([#1352](https://github.com/arthurmaciel/ipe-lang/issues/1352)) ([70b4cc2](https://github.com/arthurmaciel/ipe-lang/commit/70b4cc27f1bfe905044f0ac947659694c65b874f))
* **js-interop:** WP3 — Rust seal codec (total, fail-closed decode) ([#1356](https://github.com/arthurmaciel/ipe-lang/issues/1356)) ([d4c5f14](https://github.com/arthurmaciel/ipe-lang/commit/d4c5f1420c0637ec0bf1d0bb16371b6457a2fa7a))
* **lower/emit:** G1+G2+G6 row-poly record-update emission via IpeWithF setter witnesses ([8c41ac0](https://github.com/arthurmaciel/ipe-lang/commit/8c41ac0913787687494f11df16cb3e656082ba50))


### Bug Fixes

* **cli:** cap source-file reads via read_to_string_capped at all .ipe read sites ([bf75fb1](https://github.com/arthurmaciel/ipe-lang/commit/bf75fb1ca3986beb8ad7d3dac104cedddc4ac39d))
* **config,runtime:** reject shadowed config binding + drop redundant must_use ([#1339](https://github.com/arthurmaciel/ipe-lang/issues/1339), [#1340](https://github.com/arthurmaciel/ipe-lang/issues/1340)) ([#1341](https://github.com/arthurmaciel/ipe-lang/issues/1341)) ([7069176](https://github.com/arthurmaciel/ipe-lang/commit/70691768d9d0769998e416aa245d84217457b306))
* default un-annotated view msg tvar in argument position ([#1338](https://github.com/arthurmaciel/ipe-lang/issues/1338)) ([#1344](https://github.com/arthurmaciel/ipe-lang/issues/1344)) ([c0bd21f](https://github.com/arthurmaciel/ipe-lang/commit/c0bd21f795103d82bddde84d7a5feab6e16aaae6))
* **emit:** close three vendored-model SEAL gaps (jwt / auth / server in web) ([21bbb1e](https://github.com/arthurmaciel/ipe-lang/commit/21bbb1eacb8f1482f4190dd913ff0ec8a85d232f))
* **emit:** close vendored db-surface SEAL hole ([#1303](https://github.com/arthurmaciel/ipe-lang/issues/1303)) ([#1306](https://github.com/arthurmaciel/ipe-lang/issues/1306)) ([9e23976](https://github.com/arthurmaciel/ipe-lang/commit/9e23976973366a048768902525442fc2e67fe17f))
* **emit:** disambiguate distinct generic record shapes sharing a field-name set ([#1346](https://github.com/arthurmaciel/ipe-lang/issues/1346)) ([#1348](https://github.com/arthurmaciel/ipe-lang/issues/1348)) ([a902178](https://github.com/arthurmaciel/ipe-lang/commit/a902178c0b37d1aeb14128e449229adf2144db00))
* **emit:** emit pub mod server; for uses_web/uses_webview in vendored model ([3a99b8e](https://github.com/arthurmaciel/ipe-lang/commit/3a99b8ef3312503a1eae39266b1fbd93cd1e5d0f))
* **emit:** force uuid feature for jwt/auth programs ([#1307](https://github.com/arthurmaciel/ipe-lang/issues/1307)) ([#1308](https://github.com/arthurmaciel/ipe-lang/issues/1308)) ([8464275](https://github.com/arthurmaciel/ipe-lang/commit/8464275002b422368aa35192f242cc97fb485c84))
* **emit:** make record most-specific resolution order-independent (two-pass) ([#1358](https://github.com/arthurmaciel/ipe-lang/issues/1358)) ([3f2c136](https://github.com/arthurmaciel/ipe-lang/commit/3f2c136a2ab8985e67603dd8679fa7c1bee2d77b))
* **emit:** resolve concrete record straddling two generic templates to the most-specific ([#1349](https://github.com/arthurmaciel/ipe-lang/issues/1349)) ([#1355](https://github.com/arthurmaciel/ipe-lang/issues/1355)) ([4f59f82](https://github.com/arthurmaciel/ipe-lang/commit/4f59f8246991ef54f9e616425abdcad83c3dea23))
* **emit:** synthesise struct for single-field record shapes ([#1343](https://github.com/arthurmaciel/ipe-lang/issues/1343)) ([#1345](https://github.com/arthurmaciel/ipe-lang/issues/1345)) ([e649aaa](https://github.com/arthurmaciel/ipe-lang/commit/e649aaa49122a02cceda7536cbb9347d147523c3))
* **examples:** migrate 08-notes-app to current compiler APIs ([#1337](https://github.com/arthurmaciel/ipe-lang/issues/1337)) ([74dbe34](https://github.com/arthurmaciel/ipe-lang/commit/74dbe3484e0dfdf29bca69d5ac5822ed417c62de))
* **ffi:** harden opaqueTypeIds decode to fail-closed + strip ANSI from foreign rustc stderr ([19d4a6a](https://github.com/arthurmaciel/ipe-lang/commit/19d4a6ab643a4de5dae7f187c0c6e9c8579d9ee5))
* green main — combine revocation-symbol + FIRST_SCHEMED-burndown + migrate-sourceRoot fixes ([#1310](https://github.com/arthurmaciel/ipe-lang/issues/1310)/[#1319](https://github.com/arthurmaciel/ipe-lang/issues/1319)/[#1320](https://github.com/arthurmaciel/ipe-lang/issues/1320)) ([#1323](https://github.com/arthurmaciel/ipe-lang/issues/1323)) ([46ae5d2](https://github.com/arthurmaciel/ipe-lang/commit/46ae5d23a2326b3c8aa5eb2459893be76d88e551))
* **login:** URL-encode form fields in post_form ([4efe82e](https://github.com/arthurmaciel/ipe-lang/commit/4efe82e1c1ef71e921efd7e03e55967026a72c35))
* **lower:** propagate auto-trait bounds to local-derived values ([#1333](https://github.com/arthurmaciel/ipe-lang/issues/1333)) ([#1342](https://github.com/arthurmaciel/ipe-lang/issues/1342)) ([ba05fb7](https://github.com/arthurmaciel/ipe-lang/commit/ba05fb72d780da695aba62ac3b0a747472b2dbaf))
* **lower:** propagate callee auto-trait bounds across user calls (Store.toMaybe SEAL) ([#1312](https://github.com/arthurmaciel/ipe-lang/issues/1312)) ([94a6db9](https://github.com/arthurmaciel/ipe-lang/commit/94a6db9ef84db72e7ec1df08315004f0560dc179))
* **migrate:** fail-closed validate closure-return + define names before writing ([#1316](https://github.com/arthurmaciel/ipe-lang/issues/1316)) ([#1328](https://github.com/arthurmaciel/ipe-lang/issues/1328)) ([18bb499](https://github.com/arthurmaciel/ipe-lang/commit/18bb4998daa6f81d3cf213a3dd6d5091a392e91e))
* **migrate:** refuse non-UTF-8 dependency paths instead of silently corrupting ([ae8896f](https://github.com/arthurmaciel/ipe-lang/commit/ae8896f2bd1a241789a237961a44a8eb623a27ea))
* **migrate:** warn on unrecognised keys in known ipe.toml sections ([6805ab8](https://github.com/arthurmaciel/ipe-lang/commit/6805ab8aeac761c5505854e82ea3f2785f004ee4))
* **revocation:** replace unbounded HashSets with bounded HashMap&lt;id, cap_unix_secs&gt; ([#1315](https://github.com/arthurmaciel/ipe-lang/issues/1315)) ([604d619](https://github.com/arthurmaciel/ipe-lang/commit/604d6198d619b49339c41842b89d5924f118b515))
* **runtime/auth:** reissue cookie honors request_is_https for Secure parity ([#1294](https://github.com/arthurmaciel/ipe-lang/issues/1294)) ([1c6d9cb](https://github.com/arthurmaciel/ipe-lang/commit/1c6d9cb3101dc1c83f2e38fb4bd42bad203044d0))
* **runtime/auth:** reissue_set_cookie cookie-security signal without a web dep ([#1302](https://github.com/arthurmaciel/ipe-lang/issues/1302)) ([e955c5d](https://github.com/arthurmaciel/ipe-lang/commit/e955c5d8511ea6ffa625d119ca8b78a14364d582))
* **test:** rework modset-closure scanner to detect inline crate:: paths + fix web→server breach ([#1293](https://github.com/arthurmaciel/ipe-lang/issues/1293)) ([14dd92c](https://github.com/arthurmaciel/ipe-lang/commit/14dd92c174ba57bdf24e62bb09e318ff6f06af01))
* **toolchain:** declare musl static targets in the pin ([#1275](https://github.com/arthurmaciel/ipe-lang/issues/1275) follow-up) ([477c635](https://github.com/arthurmaciel/ipe-lang/commit/477c63553d3f400f7b729e92788418c9fe7ceea7))
* **toolchain:** pin channel to 1.97.1 to stop clippy drift ([#1275](https://github.com/arthurmaciel/ipe-lang/issues/1275)) ([a69f906](https://github.com/arthurmaciel/ipe-lang/commit/a69f9061c834b30329dec8be226e59a9f320142a))
* **types,lower:** default unconstrained UI-msg tvar to Unit ([#1309](https://github.com/arthurmaciel/ipe-lang/issues/1309)) ([#1326](https://github.com/arthurmaciel/ipe-lang/issues/1326)) ([04cfc8a](https://github.com/arthurmaciel/ipe-lang/commit/04cfc8abbc981aca0322f69b2a44808a14483e69))
* **types:** default cross-module unpinned/monomorphic view msg tvars ([#1347](https://github.com/arthurmaciel/ipe-lang/issues/1347)) ([#1351](https://github.com/arthurmaciel/ipe-lang/issues/1351)) ([9d9254d](https://github.com/arthurmaciel/ipe-lang/commit/9d9254dcbb421539c9b416895322d770da2b48d4))
* **types:** keep a parameter-position ui-msg tvar generic, not defaulted to () ([#1353](https://github.com/arthurmaciel/ipe-lang/issues/1353)) ([#1354](https://github.com/arthurmaciel/ipe-lang/issues/1354)) ([e937585](https://github.com/arthurmaciel/ipe-lang/commit/e937585da00284869816a9abcf9dcb97cad8cd22))

## [0.1.68](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.67...ipe-v0.1.68) (2026-08-24)


### Features

* **app-config:** wire runtime-config settings to their subsystems (fail-closed) + Secret.fromString doc ([#1281](https://github.com/arthurmaciel/ipe-lang/issues/1281)) ([c9b21e8](https://github.com/arthurmaciel/ipe-lang/commit/c9b21e8c97932fd1fcd5cc7ba573f143fba2b018))
* **app:** shape-typed runtime-config front door — Setting, Web.appWith, env-only secrets, loopback-in-dev ([#1279](https://github.com/arthurmaciel/ipe-lang/issues/1279)) ([a5912c8](https://github.com/arthurmaciel/ipe-lang/commit/a5912c8dbc0a9dc9931961de0087223946ae3a32))
* **auth:** add absolute session lifetime cap (P1 of [#1269](https://github.com/arthurmaciel/ipe-lang/issues/1269)) ([356d945](https://github.com/arthurmaciel/ipe-lang/commit/356d945a41628e963624014adb706f5eaff2746f))
* **codec:** DB structural shape and a shared column vocabulary ([#1233](https://github.com/arthurmaciel/ipe-lang/issues/1233)) ([e8fa0a9](https://github.com/arthurmaciel/ipe-lang/commit/e8fa0a9581d8a427dbb86058e78883c0be5dcf54))
* **compiler:** wire Web.authMaxLifetime through compiler ([#1269](https://github.com/arthurmaciel/ipe-lang/issues/1269) P1) ([ee39506](https://github.com/arthurmaciel/ipe-lang/commit/ee39506650ee0b378ff09b9ae28f58d70f3e4e0b))
* **compiler:** wire Web.authSlideWindow at all 7 compiler sites ([a31a02c](https://github.com/arthurmaciel/ipe-lang/commit/a31a02c7a7ec7d6b21d4215a8e7968289642a561))
* **config:** package.ipe P1 — Ipe.Package vocabulary + syntactic manifest reader (additive) ([#1285](https://github.com/arthurmaciel/ipe-lang/issues/1285)) ([a78def7](https://github.com/arthurmaciel/ipe-lang/commit/a78def70fa7532e650e070f5a8539a6e67c5f417))
* **config:** package.ipe P2 — ipe migrate config + round-trip renderer (additive) ([#1286](https://github.com/arthurmaciel/ipe-lang/issues/1286)) ([c4c30e6](https://github.com/arthurmaciel/ipe-lang/commit/c4c30e67bc6b07f864407c6a48c521d58bfb97d5))
* **config:** promote runtime-config tags to closed ADTs (HostMode/LogLevel/CsrfMode) ([#1283](https://github.com/arthurmaciel/ipe-lang/issues/1283)) ([8378ef5](https://github.com/arthurmaciel/ipe-lang/commit/8378ef549dcd863c7995afda0bc2b083f8d9ee32))
* **config:** retire ipe.toml — package.ipe is the sole project manifest ([fc0e743](https://github.com/arthurmaciel/ipe-lang/commit/fc0e7431ed462d1507fbe7cfd4c84b13f8e7cf95))
* **db:** accessor-typed Store column specs ([#1253](https://github.com/arthurmaciel/ipe-lang/issues/1253)) ([f52ca47](https://github.com/arthurmaciel/ipe-lang/commit/f52ca4706a629c05f21b6e1f90af625e9b30a94c))
* **db:** accessor-typed Store comparison & ordering leaves ([#1248](https://github.com/arthurmaciel/ipe-lang/issues/1248)) ([04ad135](https://github.com/arthurmaciel/ipe-lang/commit/04ad135713251eb6e62903c79edaaa234534a2c0))
* **db:** accessor-typed Store.eq/eqBy query columns ([#1246](https://github.com/arthurmaciel/ipe-lang/issues/1246)) ([5c347a9](https://github.com/arthurmaciel/ipe-lang/commit/5c347a9714605c97a3a9a46256d73a2254a761f8))
* **db:** codec-derived Store — fromCodec drives columns, reads, and writes ([#1238](https://github.com/arthurmaciel/ipe-lang/issues/1238)) ([16428f4](https://github.com/arthurmaciel/ipe-lang/commit/16428f44e6a1f4b1dd076fcf864c56c68ce4d8a4))
* **db:** codec↔SQL row bridge — codec-driven binds and row decode ([#1237](https://github.com/arthurmaciel/ipe-lang/issues/1237)) ([5367836](https://github.com/arthurmaciel/ipe-lang/commit/536783696762a3dc0679b3fcfdd4c1ff9fc6c254))
* **db:** data-preserving column and table renames in the Store migrate surface ([#1229](https://github.com/arthurmaciel/ipe-lang/issues/1229)) ([a069014](https://github.com/arthurmaciel/ipe-lang/commit/a069014e38c9802d9781536ce7a0a5b41e473f0c))
* **db:** row-security policy algebra (Pillar D, slice 1) ([#1263](https://github.com/arthurmaciel/ipe-lang/issues/1263)) ([aa2be93](https://github.com/arthurmaciel/ipe-lang/commit/aa2be933f197bdd4227b85dec00900e00b3afbf8))
* **db:** row-security Principal foundation — opaque unforgeable Principal + authed-route runtime + secured …As ops ([#1271](https://github.com/arthurmaciel/ipe-lang/issues/1271)) ([104415a](https://github.com/arthurmaciel/ipe-lang/commit/104415a5f71dd0e1d043f1f06edb54b9e4c02ab1))
* **db:** typed query builder and update for the codec-derived Store ([#1239](https://github.com/arthurmaciel/ipe-lang/issues/1239)) ([9615b02](https://github.com/arthurmaciel/ipe-lang/commit/9615b024fc8bb7ed03a0143f0e86a26ab7883a9a))
* **db:** WHERE-based update/delete and default column specs for the Store ([#1240](https://github.com/arthurmaciel/ipe-lang/issues/1240)) ([645007b](https://github.com/arthurmaciel/ipe-lang/commit/645007b519221b357c968ee5fbdad7e5f633feb7))
* **golden,docs:** SEAL fixture and docs for Web.authSlideWindow ([e020a7e](https://github.com/arthurmaciel/ipe-lang/commit/e020a7e26c045967b9b9f239e05a2a833731672e))
* **runtime:** P2 sliding session re-issue clamped to absolute cap ([c5138a0](https://github.com/arthurmaciel/ipe-lang/commit/c5138a0ffb0d16339fc0014730e8ee5e12773390))
* **stdlib/Markdown:** blockquotes, images (URL-guarded), hard break ([6c08615](https://github.com/arthurmaciel/ipe-lang/commit/6c086159cfb83f5146aa309e4deffe3ea5c26626))


### Bug Fixes

* **canon:** resolve Codec.auto constructors in every module of a multi-module program ([#1242](https://github.com/arthurmaciel/ipe-lang/issues/1242)) ([fd4b6d0](https://github.com/arthurmaciel/ipe-lang/commit/fd4b6d0d80d31830b9743b95dc56df5cdbcf5ae5)), closes [#1236](https://github.com/arthurmaciel/ipe-lang/issues/1236)
* **canon:** scope constructor pattern resolution to avoid stdlib-internal collisions ([#1260](https://github.com/arthurmaciel/ipe-lang/issues/1260)) ([042b9b8](https://github.com/arthurmaciel/ipe-lang/commit/042b9b8a28950e53487e2773c7c9290056cee649))
* **examples:** classify 18-job-queue green; raise sweep build budget ([#1249](https://github.com/arthurmaciel/ipe-lang/issues/1249)) ([2276d8c](https://github.com/arthurmaciel/ipe-lang/commit/2276d8cc8fa160b4411ee53424b6935e399c6d5e))
* **examples:** promote 29/31/38 from deps-deferred to green ([#1250](https://github.com/arthurmaciel/ipe-lang/issues/1250)) ([08b95e7](https://github.com/arthurmaciel/ipe-lang/commit/08b95e7c24ca170c080e6978295ecd3180969717))
* **lower:** close the point-free store-kernel SEAL hole ([#1258](https://github.com/arthurmaciel/ipe-lang/issues/1258)) ([eba622e](https://github.com/arthurmaciel/ipe-lang/commit/eba622edcebdc947e0ea88567346d067729ee32b))
* **parity:** make all sky-parity gates honest — zero comparisons = FAIL ([#1252](https://github.com/arthurmaciel/ipe-lang/issues/1252)) ([bafcce6](https://github.com/arthurmaciel/ipe-lang/commit/bafcce621c4b6d15fbf9c12ffaff83823e342bfa))
* **runtime/db:** explicit empty-WHERE guard in deleteWhere ([#1245](https://github.com/arthurmaciel/ipe-lang/issues/1245)) ([379f6a4](https://github.com/arthurmaciel/ipe-lang/commit/379f6a4d2434b3c06f4254b38dfa5cc8b7e01fb3))
* **runtime/db:** redact connection metadata from connect-time errors ([80516c0](https://github.com/arthurmaciel/ipe-lang/commit/80516c023076ee6f3369d01e9733218b10c67df5))
* **runtime/ui:** canonical crate::ui::helpers path in render test imports ([6a03a89](https://github.com/arthurmaciel/ipe-lang/commit/6a03a899c4662e89cc9f0870e683979c1f7df566))
* **runtime:** group base64 input with as_chunks::&lt;3&gt; instead of chunks_exact(3) ([#1274](https://github.com/arthurmaciel/ipe-lang/issues/1274)) ([7adf9df](https://github.com/arthurmaciel/ipe-lang/commit/7adf9dfd6b5328b5f45815603f46ee1bf3ad335a))
* **stdlib/Markdown:** working hard break + drop dead safeUrl (runtime sink is SSOT) ([f9cf8f5](https://github.com/arthurmaciel/ipe-lang/commit/f9cf8f53aa7d1ca9e70c0937f65cee15f3dde33e))
* **supply-chain:** ignore RUSTSEC-2026-0235 (rkyv OOB) in audit + deny gates ([#1278](https://github.com/arthurmaciel/ipe-lang/issues/1278)) ([a2b12a2](https://github.com/arthurmaciel/ipe-lang/commit/a2b12a29e7e8bf6ccd2ea67bdd361dab547ba059))
* **ui:** render row/column as inline-flex and el as inline-span inside Ui.paragraph ([dd9bde4](https://github.com/arthurmaciel/ipe-lang/commit/dd9bde49800c4584b0c88649e4ca59e619295691))
* **wasm:** add app_config to WASM_RUNTIME_MOD_RS; prove closure structurally ([84af06e](https://github.com/arthurmaciel/ipe-lang/commit/84af06e107153f5dd866a81ccabe68e9dbd5d7df))
* **watch:** make the readiness-fallback test deterministic ([#1256](https://github.com/arthurmaciel/ipe-lang/issues/1256)) ([4ed97d7](https://github.com/arthurmaciel/ipe-lang/commit/4ed97d7569e1e7f7a70585d0fe0ecad873ea748a))
* **web/csrf:** give CSRF cookie per-app identity via base-path suffix ([41c1241](https://github.com/arthurmaciel/ipe-lang/commit/41c1241b7f0238d2f3e145f6643ff5099ad5084f))

## [0.1.67](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.66...ipe-v0.1.67) (2026-08-20)


### Features

* **docs:** doc-test gate for fenced ipe examples in doc-strings ([#1210](https://github.com/arthurmaciel/ipe-lang/issues/1210)) ([6fa43d8](https://github.com/arthurmaciel/ipe-lang/commit/6fa43d8edc9a74ad11838d1741ffe36cff0af306))
* **parse:** doc-strings in .ipe source — lexer, AST, parser (component A) ([#1203](https://github.com/arthurmaciel/ipe-lang/issues/1203)) ([fc235a3](https://github.com/arthurmaciel/ipe-lang/commit/fc235a362a151a77b9bb1668166c847f9f7e9cc8))


### Bug Fixes

* **backend:** emit a self-contained Cargo.toml for standalone/cross builds (closes [#1152](https://github.com/arthurmaciel/ipe-lang/issues/1152)) ([#1221](https://github.com/arthurmaciel/ipe-lang/issues/1221)) ([5118416](https://github.com/arthurmaciel/ipe-lang/commit/5118416f285c4fd0d34eac9e7beaf404fadcc6cb))
* **diagnostics:** classify registry/network failure as IPE-E0001, not IPE-I0001 ICE ([#1202](https://github.com/arthurmaciel/ipe-lang/issues/1202)) ([d0dc9c7](https://github.com/arthurmaciel/ipe-lang/commit/d0dc9c7aab444044210d88670c5b66ae7c1acffe))
* **lower:** reject a function-field record with IPE-L0107 instead of the IPE-I0001 ICE (closes [#1139](https://github.com/arthurmaciel/ipe-lang/issues/1139)) ([#1217](https://github.com/arthurmaciel/ipe-lang/issues/1217)) ([507d4b0](https://github.com/arthurmaciel/ipe-lang/commit/507d4b0bac1a17b77268f7451ec454f87b1bb9a0))
* **lower:** reject non-record argument at a row-param position (closes [#1209](https://github.com/arthurmaciel/ipe-lang/issues/1209)) ([#1211](https://github.com/arthurmaciel/ipe-lang/issues/1211)) ([2fff3ec](https://github.com/arthurmaciel/ipe-lang/commit/2fff3ec2cab93510ab4e3f0fe1e7f1286dc1cc73))
* **lower:** unify the two row-witness-satisfaction checks into one predicate (closes [#1194](https://github.com/arthurmaciel/ipe-lang/issues/1194)) ([#1206](https://github.com/arthurmaciel/ipe-lang/issues/1206)) ([2be410d](https://github.com/arthurmaciel/ipe-lang/commit/2be410d0b2856623b620ea6cb2a9ae643c95dd22))
* **parse:** a module-level doc-comment before imports parses ([#1208](https://github.com/arthurmaciel/ipe-lang/issues/1208)) ([33b71eb](https://github.com/arthurmaciel/ipe-lang/commit/33b71eb053c145fca980b46dda4894b7a5862b16))
* **stdlib:** correct the failing String/Result doc-string examples ([#1222](https://github.com/arthurmaciel/ipe-lang/issues/1222)) ([449327d](https://github.com/arthurmaciel/ipe-lang/commit/449327d8edb87882057bbc18a517db4f7720c955))

## [0.1.66](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.65...ipe-v0.1.66) (2026-08-19)


### Bug Fixes

* **canon:** register isJust and isNothing as StdlibKernel variants (closes [#1193](https://github.com/arthurmaciel/ipe-lang/issues/1193)) ([#1199](https://github.com/arthurmaciel/ipe-lang/issues/1199)) ([435890a](https://github.com/arthurmaciel/ipe-lang/commit/435890a67a5dea63e72b702abe76d5d778deca9c))
* **cli:** fail closed when an Unsafe-scan module is unreadable (closes [#1142](https://github.com/arthurmaciel/ipe-lang/issues/1142)) ([#1189](https://github.com/arthurmaciel/ipe-lang/issues/1189)) ([657a30e](https://github.com/arthurmaciel/ipe-lang/commit/657a30eef95e1505c4ad6bf934c622e5e856ceb6))
* **cli:** type LockedDep.rev as PinnedRev + typed escape/index tag (closes [#1168](https://github.com/arthurmaciel/ipe-lang/issues/1168)) ([#1191](https://github.com/arthurmaciel/ipe-lang/issues/1191)) ([e6847fb](https://github.com/arthurmaciel/ipe-lang/commit/e6847fbbc329f19d8fbae92580528117fd66f173))
* **parse:** reject stepless do; drop doParallel in favor of Task.parallel (closes [#1192](https://github.com/arthurmaciel/ipe-lang/issues/1192)) ([#1197](https://github.com/arthurmaciel/ipe-lang/issues/1197)) ([614f357](https://github.com/arthurmaciel/ipe-lang/commit/614f357ea213988883ea1267b732b57cf9990746))

## [0.1.65](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.64...ipe-v0.1.65) (2026-08-19)


### Bug Fixes

* **cli:** route HOME-unset ffi scratch through ScratchDir; widen the predictable-temp_dir gate (closes [#1155](https://github.com/arthurmaciel/ipe-lang/issues/1155)) ([#1190](https://github.com/arthurmaciel/ipe-lang/issues/1190)) ([fcb4d35](https://github.com/arthurmaciel/ipe-lang/commit/fcb4d35e4614d09d381a1296e46589a5784cf5eb))
* **runtime,backend:** wrapping negate + polymorphic Number-a arithmetic so no emitted Int op panics (closes [#1146](https://github.com/arthurmaciel/ipe-lang/issues/1146)) ([#1195](https://github.com/arthurmaciel/ipe-lang/issues/1195)) ([2adedfc](https://github.com/arthurmaciel/ipe-lang/commit/2adedfc8f56b0ffb2567310ac7a50e01f46c186c))

## [0.1.64](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.63...ipe-v0.1.64) (2026-08-19)


### Bug Fixes

* **lower:** enforce wildcard-any row containment + caller field-type at ipe-time (closes [#1117](https://github.com/arthurmaciel/ipe-lang/issues/1117), closes [#1118](https://github.com/arthurmaciel/ipe-lang/issues/1118)) ([#1188](https://github.com/arthurmaciel/ipe-lang/issues/1188)) ([26b2f7b](https://github.com/arthurmaciel/ipe-lang/commit/26b2f7b30fc084d0cc82671b04f109c949cbed28))
* **release:** upload job resolves the tag from the release/dispatch event, not GITHUB_REF_NAME ([#1185](https://github.com/arthurmaciel/ipe-lang/issues/1185)) ([7920dee](https://github.com/arthurmaciel/ipe-lang/commit/7920dee6396c843ffcd5cc86625b9c265df5c07c))

## [0.1.63](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.62...ipe-v0.1.63) (2026-08-19)


### Bug Fixes

* **backend:** force ct_eq into the emitted runtime module set alongside crypto_core/secret ([#1179](https://github.com/arthurmaciel/ipe-lang/issues/1179)) ([3b92be5](https://github.com/arthurmaciel/ipe-lang/commit/3b92be5f5fa6dab636f6ab6a22832f4a011df9d8))
* **release:** smoke-tests call the ipe version subcommand, not a --version flag ([#1183](https://github.com/arthurmaciel/ipe-lang/issues/1183)) ([ed27033](https://github.com/arthurmaciel/ipe-lang/commit/ed27033b25df3d059acc3df9352f14a9d192fbc2))
* **stdlib:** scrub reference-implementation leaks + add fail-closed leak gate (closes [#1134](https://github.com/arthurmaciel/ipe-lang/issues/1134)) ([#1182](https://github.com/arthurmaciel/ipe-lang/issues/1182)) ([2f588e5](https://github.com/arthurmaciel/ipe-lang/commit/2f588e5cf99b22e3af465ac91f34bb7d03fe2be4))

## [0.1.62](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.61...ipe-v0.1.62) (2026-08-19)


### Bug Fixes

* **diagnostics:** collapse parallel renderers into typed Diagnostic taxonomy ([#1132](https://github.com/arthurmaciel/ipe-lang/issues/1132)) ([#1170](https://github.com/arthurmaciel/ipe-lang/issues/1170)) ([01c403f](https://github.com/arthurmaciel/ipe-lang/commit/01c403f7dfc786d78dab7bbe7ebdecf90c7289d4))

## [0.1.61](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.60...ipe-v0.1.61) (2026-08-19)


### Bug Fixes

* **lsp:** type the feature-result boundary so encoding bugs and bad params never launder to null ([#1169](https://github.com/arthurmaciel/ipe-lang/issues/1169)) ([c960dd9](https://github.com/arthurmaciel/ipe-lang/commit/c960dd99918adeb283fc0c328e0f0b3bf1b85acb))

## [0.1.60](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.59...ipe-v0.1.60) (2026-08-19)


### Bug Fixes

* **cli:** pin git escapes to immutable commit SHAs and unskip escape verification ([#1166](https://github.com/arthurmaciel/ipe-lang/issues/1166)) ([18aff0f](https://github.com/arthurmaciel/ipe-lang/commit/18aff0fe9a32cdcbed98d0c754c5c37ece637ee8))
* **diagnostics:** eliminate three doc-vs-code contract mismatches ([#1131](https://github.com/arthurmaciel/ipe-lang/issues/1131)) ([#1165](https://github.com/arthurmaciel/ipe-lang/issues/1165)) ([f6ff80b](https://github.com/arthurmaciel/ipe-lang/commit/f6ff80b82ca547b21ec2a384c90caf78a993b7d7))
* **examples:** add 01-hello-world.edits to fix sky-ports consistency check ([#1162](https://github.com/arthurmaciel/ipe-lang/issues/1162)) ([64f914b](https://github.com/arthurmaciel/ipe-lang/commit/64f914bb7aac095c2904ef48712a69994783793d))
* **parse:** unify leading-minus numeric-literal rule across expression and pattern ([#1164](https://github.com/arthurmaciel/ipe-lang/issues/1164)) ([871fd29](https://github.com/arthurmaciel/ipe-lang/commit/871fd295eff6fbc44ddbdebbdf1079f74854b2ce))

## [0.1.59](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.58...ipe-v0.1.59) (2026-08-18)


### Bug Fixes

* **emit:** close unescaped-splice-into-manifest class in TOML path/name emission ([#1157](https://github.com/arthurmaciel/ipe-lang/issues/1157)) ([b8750d5](https://github.com/arthurmaciel/ipe-lang/commit/b8750d5259de75836c6db18de5e3904d08b5114b)), closes [#1129](https://github.com/arthurmaciel/ipe-lang/issues/1129)
* **runtime:** constant-time equality for Mac/Key/Secret via SSOT ct_bytes_eq (closes [#1130](https://github.com/arthurmaciel/ipe-lang/issues/1130)) ([#1160](https://github.com/arthurmaciel/ipe-lang/issues/1160)) ([afd6573](https://github.com/arthurmaciel/ipe-lang/commit/afd6573f4442a9ed19d458fde8c07ee778cf3992))

## [0.1.58](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.57...ipe-v0.1.58) (2026-08-18)


### Bug Fixes

* **backend:** emit Int add/sub/mul through wrapping runtime helpers ([#1124](https://github.com/arthurmaciel/ipe-lang/issues/1124)) ([#1145](https://github.com/arthurmaciel/ipe-lang/issues/1145)) ([dfdcb12](https://github.com/arthurmaciel/ipe-lang/commit/dfdcb123b73f218f604f8e03b645f2647bda6057))
* **diagnostics:** render set-valued diagnostics in canonical string order ([#1150](https://github.com/arthurmaciel/ipe-lang/issues/1150)) ([2aeb7ee](https://github.com/arthurmaciel/ipe-lang/commit/2aeb7ee1f239fa3e3bb7824156c9542d0dfebf64))
* **lower:** erase field-read wildcard-any param to a row generic, close E0308 SEAL ([#1115](https://github.com/arthurmaciel/ipe-lang/issues/1115)) ([f8e592b](https://github.com/arthurmaciel/ipe-lang/commit/f8e592b9fc385be3a084b32f1069f4dd4b0f629f))
* **lower:** make is_retry_policy_record a full name+type predicate ([#1138](https://github.com/arthurmaciel/ipe-lang/issues/1138)) ([58b5772](https://github.com/arthurmaciel/ipe-lang/commit/58b5772267dd85504f021e469019c11d7422edbd))
* **lsp:** guard every request handler against dependency-cycle panic ([#1144](https://github.com/arthurmaciel/ipe-lang/issues/1144)) ([2aff323](https://github.com/arthurmaciel/ipe-lang/commit/2aff3235882d14e417f3b8431eaa6cd76514f35f))
* **runtime:** collapse nested if-chains and drop needless borrow to fix runtime-feature-combos CI ([#1149](https://github.com/arthurmaciel/ipe-lang/issues/1149)) ([5961144](https://github.com/arthurmaciel/ipe-lang/commit/59611440c76088a0512507e7cd6f40fec84f21e1))
* **security:** close missing-egress-fail-closed-guard on all 5 instances ([#1143](https://github.com/arthurmaciel/ipe-lang/issues/1143)) ([232b424](https://github.com/arthurmaciel/ipe-lang/commit/232b424f753d3cb5c544ad0361c84494b6fbf752))
* **security:** close TOCTOU class — exclusive scratch paths with 128-bit entropy ([#1153](https://github.com/arthurmaciel/ipe-lang/issues/1153)) ([cdfb76b](https://github.com/arthurmaciel/ipe-lang/commit/cdfb76bdd5a7befcf0d65dea0a203b2789c4b10b))
* **security:** fail closed on all four error-swallow gate instances ([#1141](https://github.com/arthurmaciel/ipe-lang/issues/1141)) ([c3f1279](https://github.com/arthurmaciel/ipe-lang/commit/c3f1279794302dbe85a8ce57cd3a5abcd58c0946))
* **security:** path newtypes prove their full invariant (closes [#1128](https://github.com/arthurmaciel/ipe-lang/issues/1128)) ([#1156](https://github.com/arthurmaciel/ipe-lang/issues/1156)) ([f964af1](https://github.com/arthurmaciel/ipe-lang/commit/f964af17e1e657c30e381fba0cd7ee32ed8a807a))
* **static:** rename hello-world to ipe-app and strip Windows UNC prefix in dep path ([#1151](https://github.com/arthurmaciel/ipe-lang/issues/1151)) ([dd854bb](https://github.com/arthurmaciel/ipe-lang/commit/dd854bb0277d86eca601b3a102910a4fc237b2b6))

## [0.1.57](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.56...ipe-v0.1.57) (2026-08-18)


### Bug Fixes

* **cli:** make `ipe version` the sole version command; drop the `--version`/`-V` flag ([#1108](https://github.com/arthurmaciel/ipe-lang/issues/1108)) ([f904ea5](https://github.com/arthurmaciel/ipe-lang/commit/f904ea58f9d2459559e6e42d2001d95a4726f85e))
* **lower:** tie wildcard-any return to threaded param, close E0308 SEAL ([#1106](https://github.com/arthurmaciel/ipe-lang/issues/1106), [#1107](https://github.com/arthurmaciel/ipe-lang/issues/1107)) ([#1111](https://github.com/arthurmaciel/ipe-lang/issues/1111)) ([9c0f520](https://github.com/arthurmaciel/ipe-lang/commit/9c0f5208224e3e92a219569bbc4896872cf2dc7a))

## [0.1.56](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.55...ipe-v0.1.56) (2026-08-17)


### Features

* **audit:** sidecar-based wrapper SSOT, generic exclusion, exclusive scratch dir ([#1034](https://github.com/arthurmaciel/ipe-lang/issues/1034)) ([21a59ca](https://github.com/arthurmaciel/ipe-lang/commit/21a59ca5e74389d40aaaecdb86521d7d9a73b588))


### Bug Fixes

* **audit:** regenerate FFI bindings from pinned crates before gate checks ([#1039](https://github.com/arthurmaciel/ipe-lang/issues/1039)) ([2a9bd92](https://github.com/arthurmaciel/ipe-lang/commit/2a9bd92bbea2a09543030ad19b25d8bac9f8355b))
* **audit:** reject [rust.wrapper]-only packages at admission (fail-closed) ([#1043](https://github.com/arthurmaciel/ipe-lang/issues/1043)) ([9c5cad7](https://github.com/arthurmaciel/ipe-lang/commit/9c5cad7c80ec4e0e7b15873fd81a13aa7a3238b4))
* **backend:** fail-closed Pat::Char and validate FFI callee ident ([#1086](https://github.com/arthurmaciel/ipe-lang/issues/1086)) ([aca7990](https://github.com/arthurmaciel/ipe-lang/commit/aca7990b6445cb41d5ccd5b37fccb766a1494bcc))
* **cli:** harden cache symlink, token argv, PR status, token file mode, wrapper SSOT ([#1085](https://github.com/arthurmaciel/ipe-lang/issues/1085)) ([d058e2d](https://github.com/arthurmaciel/ipe-lang/commit/d058e2de1e89655640710651b040d18610531083))
* **cli:** unify misuse discipline, style IO errors, and broaden machine flags ([#1032](https://github.com/arthurmaciel/ipe-lang/issues/1032)) ([2c92f69](https://github.com/arthurmaciel/ipe-lang/commit/2c92f69fa34ccb27cbacb5a36c6d1b4619282ecd))
* **css,watch:** block legacy script-execution CSS properties; deterministic watch test ([#1097](https://github.com/arthurmaciel/ipe-lang/issues/1097)) ([9d55b55](https://github.com/arthurmaciel/ipe-lang/commit/9d55b55c71d36614816ecbc006eb5d188488f911))
* **diagnostics,intern:** PathRejection enum, SSOT title, strict ident gate ([#1094](https://github.com/arthurmaciel/ipe-lang/issues/1094)) ([28c96fa](https://github.com/arthurmaciel/ipe-lang/commit/28c96fa6083e2a96e9efb61e4248687470d49a1d))
* **diagnostics:** correct IPE-L0142 remedies to honest set ([#1104](https://github.com/arthurmaciel/ipe-lang/issues/1104)) ([4ea075b](https://github.com/arthurmaciel/ipe-lang/commit/4ea075be422d63de44df64317391641d8f8bef13))
* **ffi:** close capscan asm hole, validate opaque-type decode, fix i128 double-eval ([#1084](https://github.com/arthurmaciel/ipe-lang/issues/1084)) ([9626cb6](https://github.com/arthurmaciel/ipe-lang/commit/9626cb6db1175d3b03c5129d3f4e98e2fbf0ddda))
* **ffi:** reject const-generic impls and expand Result aliases in parametric path ([#1035](https://github.com/arthurmaciel/ipe-lang/issues/1035)) ([0fa3bb3](https://github.com/arthurmaciel/ipe-lang/commit/0fa3bb33e9df7126fceb862a2c8e9a90cfe89153))
* **ffi:** restrict Result alias mapping to known std paths only ([#1038](https://github.com/arthurmaciel/ipe-lang/issues/1038)) ([8f1b596](https://github.com/arthurmaciel/ipe-lang/commit/8f1b5962278579d035636207236622b423c2a685))
* **lower,kernels:** close four SEAL/SSOT soundness gaps ([#1047](https://github.com/arthurmaciel/ipe-lang/issues/1047), [#1048](https://github.com/arthurmaciel/ipe-lang/issues/1048), [#1052](https://github.com/arthurmaciel/ipe-lang/issues/1052), [#1053](https://github.com/arthurmaciel/ipe-lang/issues/1053)) ([#1087](https://github.com/arthurmaciel/ipe-lang/issues/1087)) ([df8123c](https://github.com/arthurmaciel/ipe-lang/commit/df8123c79cb92e0c6613f2b027de8ccdd7799f4c))
* **lower:** close freshen_any_generics missing-arm class for SharedFun/FnOnceChain ([#1101](https://github.com/arthurmaciel/ipe-lang/issues/1101)) ([80c17e1](https://github.com/arthurmaciel/ipe-lang/commit/80c17e1f7cdb26f6290674621ffa213dfcb4e2d7))
* **lower:** link param-shared wildcard any to close E0308 SEAL ([#1103](https://github.com/arthurmaciel/ipe-lang/issues/1103)) ([#1105](https://github.com/arthurmaciel/ipe-lang/issues/1105)) ([47ddf26](https://github.com/arthurmaciel/ipe-lang/commit/47ddf26c1030f8092491bf89c142beb99d221346))
* **lower:** reject an undeterminable return-position wildcard `any` at ipe time ([#1102](https://github.com/arthurmaciel/ipe-lang/issues/1102)) ([0bd66ed](https://github.com/arthurmaciel/ipe-lang/commit/0bd66ed65e40183bdf34074e4b18886ea7b0a3d0))
* **lower:** unify reuse-reject predicates, scan arm guards in 4 walkers, fix kernel doc ([#1095](https://github.com/arthurmaciel/ipe-lang/issues/1095)) ([10d75b3](https://github.com/arthurmaciel/ipe-lang/commit/10d75b32fe07415867c48c97b4624ea5fdf9e8c8))
* **lsp:** validate rename identifier and filter stale diagnostic batches ([#1089](https://github.com/arthurmaciel/ipe-lang/issues/1089)) ([d313443](https://github.com/arthurmaciel/ipe-lang/commit/d313443b3104f5d41c5cdcaebb837df991077db8))
* **parse:** harden Span invariant and fix chained-access span collision ([#1080](https://github.com/arthurmaciel/ipe-lang/issues/1080)) ([d134baf](https://github.com/arthurmaciel/ipe-lang/commit/d134baf8bbfef962b4bb20a7add29169445eba73))
* **resolve:** allow file:// sources and relax CommitId to injection-shape rejection ([#1081](https://github.com/arthurmaciel/ipe-lang/issues/1081)) ([3b82f16](https://github.com/arthurmaciel/ipe-lang/commit/3b82f16eced558ad68f348feffec5e2756e756e9))
* **run:** read binary name from emitted Cargo.toml (SSOT) for native packages ([#1037](https://github.com/arthurmaciel/ipe-lang/issues/1037)) ([e5288c0](https://github.com/arthurmaciel/ipe-lang/commit/e5288c0a64ea3882483c1471e28f6226bd762952))
* **sandbox:** harden jail confinement — SBPL baseline denies, FreeBSD exclusive-create, SSOT tamper-check ([#1082](https://github.com/arthurmaciel/ipe-lang/issues/1082)) ([5238ee3](https://github.com/arthurmaciel/ipe-lang/commit/5238ee3d1e86512f5fc9c55834293d42e7c60c92))
* **security,lower:** type git sink with newtypes; freshen nested-any in return position ([#1098](https://github.com/arthurmaciel/ipe-lang/issues/1098)) ([3c4eec3](https://github.com/arthurmaciel/ipe-lang/commit/3c4eec38c1304f68b657f8728e29b0d12f12d79c))
* **security:** add csrf_pair_valid and hoist CSRF predicates to single SSOT ([#1093](https://github.com/arthurmaciel/ipe-lang/issues/1093)) ([32ecea1](https://github.com/arthurmaciel/ipe-lang/commit/32ecea11ca31bd865439f78aa89c59e491bbdd97))
* **stdlib:** close CSS raw/keyframes injection bypass and fix Palette name collision ([#1092](https://github.com/arthurmaciel/ipe-lang/issues/1092)) ([9254e34](https://github.com/arthurmaciel/ipe-lang/commit/9254e34744645dc5928038131d5def83ab1f25f9))
* **stdlib:** rename Track.Fr to TrackFr to avoid Ipe.Css.Length constructor clash ([#1042](https://github.com/arthurmaciel/ipe-lang/issues/1042)) ([ad6d945](https://github.com/arthurmaciel/ipe-lang/commit/ad6d94501258266264f0d8b1ea44cb15311d4ec5))
* **types:** sound open-record row merge preserving both extension tails ([#1090](https://github.com/arthurmaciel/ipe-lang/issues/1090)) ([7956071](https://github.com/arthurmaciel/ipe-lang/commit/79560712434e73b12ce0eba0bb2a5789d0da9614))

## [0.1.55](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.54...ipe-v0.1.55) (2026-08-17)


### Bug Fixes

* **cli:** route package audit/publish through the build runtime resolver and embed the Tier-2 probe fixture ([#1023](https://github.com/arthurmaciel/ipe-lang/issues/1023)) ([fde36d7](https://github.com/arthurmaciel/ipe-lang/commit/fde36d7e500785492f0a2ada43d07201bec7d7f4))

## [0.1.54](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.53...ipe-v0.1.54) (2026-08-16)


### Bug Fixes

* **audit:** make Tier-2 native-package certification reachable ([#1016](https://github.com/arthurmaciel/ipe-lang/issues/1016)) ([28599b5](https://github.com/arthurmaciel/ipe-lang/commit/28599b5f5f606e7a0002305ea5a10c34e1cc5fa3))

## [0.1.53](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.52...ipe-v0.1.53) (2026-08-16)


### Features

* **cli:** add `ipe package audit-entry` — index CI receiving gate ([#1010](https://github.com/arthurmaciel/ipe-lang/issues/1010)) ([24ec11c](https://github.com/arthurmaciel/ipe-lang/commit/24ec11c511851201819d0af53c26de18eba24d9a))

## [0.1.52](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.51...ipe-v0.1.52) (2026-08-16)


### Features

* **ci:** non-visual Sky↔Ipê parity harness — Increment 2 ([#1009](https://github.com/arthurmaciel/ipe-lang/issues/1009)) ([3992f7b](https://github.com/arthurmaciel/ipe-lang/commit/3992f7b41690221fda31fa5e1abeec580e57bd48))
* **cli:** add --json diagnostic output for build, run, and type-check ([#1001](https://github.com/arthurmaciel/ipe-lang/issues/1001)) ([8ca0982](https://github.com/arthurmaciel/ipe-lang/commit/8ca09828eef1079a3730101545c9360781da63e9))
* **cli:** ipe explain unified teaching interface ([#992](https://github.com/arthurmaciel/ipe-lang/issues/992)) ([#994](https://github.com/arthurmaciel/ipe-lang/issues/994)) ([c821402](https://github.com/arthurmaciel/ipe-lang/commit/c821402fc42154c30105b6cbc2df0062cf3e8199))
* **diagnostics:** teaching nudges linking ipe explain topics ([#992](https://github.com/arthurmaciel/ipe-lang/issues/992) stage 6) ([#1003](https://github.com/arthurmaciel/ipe-lang/issues/1003)) ([e711a95](https://github.com/arthurmaciel/ipe-lang/commit/e711a95e2be5815b359a6147387014fa72cc79c1))
* **ffi,cli:** teach `ipe rust add` — progress, warning banner, and a pkg-config missing-system-library diagnostic ([#993](https://github.com/arthurmaciel/ipe-lang/issues/993)) ([5b697c2](https://github.com/arthurmaciel/ipe-lang/commit/5b697c26bb673e518e45b361290908c44607309b))
* **stdlib:** Ipe.Analytics — typed, consent-gated product analytics ([#1002](https://github.com/arthurmaciel/ipe-lang/issues/1002)) ([213c492](https://github.com/arthurmaciel/ipe-lang/commit/213c49278c1c612deb768b2b0d48d5607ef34859))
* **stdlib:** Ipe.Analytics store-backed residuals — eventsStore, persist, erase, aggregates ([#1004](https://github.com/arthurmaciel/ipe-lang/issues/1004)) ([0d85d68](https://github.com/arthurmaciel/ipe-lang/commit/0d85d68eef8ef7f89abb254a8a4adbbcccde1f41))


### Bug Fixes

* **cli:** make explain frontmatter unquote total on a lone quote ([#996](https://github.com/arthurmaciel/ipe-lang/issues/996)) ([6b751b1](https://github.com/arthurmaciel/ipe-lang/commit/6b751b179bd7cb1f7f2358ac6539360927aad935))
* **converter:** accept, not declare, the unsafe capability for .Unsafe imports ([#987](https://github.com/arthurmaciel/ipe-lang/issues/987)) ([3dbf7d2](https://github.com/arthurmaciel/ipe-lang/commit/3dbf7d25a58504e381abbbee13b436c354b6e9f6))
* **emit:** unify Cons/list fn-value element carrier with the storable Arc element type ([#989](https://github.com/arthurmaciel/ipe-lang/issues/989)) ([cfa2309](https://github.com/arthurmaciel/ipe-lang/commit/cfa2309078eea2e37c1f56b1a05b1dad75f37185))
* **examples:** drop lawless Io.println discards from 08-notes-app (IPE-L0141) ([#1000](https://github.com/arthurmaciel/ipe-lang/issues/1000)) ([7ac1089](https://github.com/arthurmaciel/ipe-lang/commit/7ac10891f0b647a70a4710ad2190681fdb94bfad)), closes [#836](https://github.com/arthurmaciel/ipe-lang/issues/836)
* **lower:** gate RetryPolicy concretisation on kernel shouldRetry type ([#997](https://github.com/arthurmaciel/ipe-lang/issues/997)) ([6655aeb](https://github.com/arthurmaciel/ipe-lang/commit/6655aebc8098681691aa131d51e6f520639b4881))
* **lower:** propagate Sync bound on generic captured by list-cons lambda ([#1006](https://github.com/arthurmaciel/ipe-lang/issues/1006)) ([afd03d3](https://github.com/arthurmaciel/ipe-lang/commit/afd03d304c981ce5408488fb1411fd582eb844af))
* **stdlib:** reject serial-without-primaryKey at createSql time (Fixes [#1007](https://github.com/arthurmaciel/ipe-lang/issues/1007)) ([#1008](https://github.com/arthurmaciel/ipe-lang/issues/1008)) ([f2882f8](https://github.com/arthurmaciel/ipe-lang/commit/f2882f85271b04da92576aa97b757d854f78ab5e))
* **test:** correct stale runtime path in cargo_name SEAL; factor shared e2e helpers ([#998](https://github.com/arthurmaciel/ipe-lang/issues/998)) ([4198fb1](https://github.com/arthurmaciel/ipe-lang/commit/4198fb167c525c851055e9d732e972b258403f38)), closes [#990](https://github.com/arthurmaciel/ipe-lang/issues/990)
* **tui:** batch clear+frame into one write to eliminate cursor-move flicker ([#999](https://github.com/arthurmaciel/ipe-lang/issues/999)) ([0e63d3a](https://github.com/arthurmaciel/ipe-lang/commit/0e63d3aa177dc96e957dd524ebfa37a0d6bc74d3)), closes [#758](https://github.com/arthurmaciel/ipe-lang/issues/758)

## [0.1.51](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.50...ipe-v0.1.51) (2026-08-14)


### Features

* **cli,backend:** emit binary named from ipe.toml name field ([#974](https://github.com/arthurmaciel/ipe-lang/issues/974)) ([b468236](https://github.com/arthurmaciel/ipe-lang/commit/b4682362c05c6a555ffa9ff84af4420517aed765))
* **examples:** sky behavior-parity harness — increment 1 ([#945](https://github.com/arthurmaciel/ipe-lang/issues/945)) ([e05df28](https://github.com/arthurmaciel/ipe-lang/commit/e05df28dfad56d3fbc92954cbe11cda7bf7e93ea))
* **examples:** sky-ports offline gate + upstream-drift lock (part of the examples/sky parity harness) ([#936](https://github.com/arthurmaciel/ipe-lang/issues/936)) ([8eaa71b](https://github.com/arthurmaciel/ipe-lang/commit/8eaa71b9413ddb87a904e9a272faf8ad7d1f5b2f))
* **parity:** generalize web visual-parity to all web ports + nightly CI ([#965](https://github.com/arthurmaciel/ipe-lang/issues/965)) ([d4a902f](https://github.com/arthurmaciel/ipe-lang/commit/d4a902fe46b651a17a75ebf70a9a5810fc496ff2))
* **parity:** visual parity PoC — harness + PIL diff tool + design doc ([#964](https://github.com/arthurmaciel/ipe-lang/issues/964)) ([b82f6ad](https://github.com/arthurmaciel/ipe-lang/commit/b82f6adefcd21ca9e8cc2301329b2b0200651d54))
* **runtime:** rename IPE_LIVE_* env vars to IPE_WEB_* with back-compat aliases ([#972](https://github.com/arthurmaciel/ipe-lang/issues/972)) ([75fa27b](https://github.com/arthurmaciel/ipe-lang/commit/75fa27bd80d00df9407c4a7fe2f06476545bcf7f))
* **runtime:** unify web page shell — viewport meta + BASE_CSS on all render paths ([#970](https://github.com/arthurmaciel/ipe-lang/issues/970)) ([0737dfe](https://github.com/arthurmaciel/ipe-lang/commit/0737dfea233e5c7505562513248d31b25197c4fd))


### Bug Fixes

* **converter:** render sync effect-discard entry as effect-valued main ([#952](https://github.com/arthurmaciel/ipe-lang/issues/952)) ([3bb07f2](https://github.com/arthurmaciel/ipe-lang/commit/3bb07f2f9755b164ce6eb7020509a4a01e79301e)), closes [#947](https://github.com/arthurmaciel/ipe-lang/issues/947)
* **examples:** commit missing ipe-edits + regenerate ipe/ ports (fixes [#957](https://github.com/arthurmaciel/ipe-lang/issues/957)) ([#958](https://github.com/arthurmaciel/ipe-lang/issues/958)) ([e4ac340](https://github.com/arthurmaciel/ipe-lang/commit/e4ac3404834c8e79873b63069e1b5a4f1befff94))
* **examples:** flip 07-todo-cli + 34-multi-tier-console broken→green (IPE-L0141) ([#960](https://github.com/arthurmaciel/ipe-lang/issues/960)) ([ecd7e76](https://github.com/arthurmaciel/ipe-lang/commit/ecd7e763a8a68a8473f2745fb5c9850faff7bafb)), closes [#940](https://github.com/arthurmaciel/ipe-lang/issues/940)
* **examples:** flip 25-sky-console broken→green (IPE-T0020) ([#959](https://github.com/arthurmaciel/ipe-lang/issues/959)) ([73d1459](https://github.com/arthurmaciel/ipe-lang/commit/73d1459fdf159477fecdb9ee0ecfa82f5f97b2b8)), closes [#942](https://github.com/arthurmaciel/ipe-lang/issues/942)
* **examples:** migrate 00-standard-libs off removed Task.perform (Fixes [#941](https://github.com/arthurmaciel/ipe-lang/issues/941)) ([#962](https://github.com/arthurmaciel/ipe-lang/issues/962)) ([5494644](https://github.com/arthurmaciel/ipe-lang/commit/54946448ec3b163b627e1ef40d4672995c72e99e))
* **examples:** port 36-composite-server from broken to green ([#956](https://github.com/arthurmaciel/ipe-lang/issues/956)) ([17882c6](https://github.com/arthurmaciel/ipe-lang/commit/17882c6eb718f6d8664de6f8b15710ab39b32cb1)), closes [#943](https://github.com/arthurmaciel/ipe-lang/issues/943)
* **examples:** port simple from broken to green — replace Task.perform with do/&lt;- ([#955](https://github.com/arthurmaciel/ipe-lang/issues/955)) ([7b4609f](https://github.com/arthurmaciel/ipe-lang/commit/7b4609f2aa4f23a64e0d43cab7401c355450855a)), closes [#938](https://github.com/arthurmaciel/ipe-lang/issues/938)
* **examples:** route ported Db.unsafe* calls to Ipe.Db.Unsafe ([#939](https://github.com/arthurmaciel/ipe-lang/issues/939)) ([#954](https://github.com/arthurmaciel/ipe-lang/issues/954)) ([ebf3658](https://github.com/arthurmaciel/ipe-lang/commit/ebf3658eb06d2125edfee29b1acc07cb2067e2e4))
* **examples:** sky-parity builds+runs the emitted binary in an isolated copy ([#948](https://github.com/arthurmaciel/ipe-lang/issues/948)) ([90d2fa6](https://github.com/arthurmaciel/ipe-lang/commit/90d2fa65fa38b86ee25d157f3d9281edcedbf40e))
* **lower:** Arc-promote a fn value moved then called (SEAL) ([#981](https://github.com/arthurmaciel/ipe-lang/issues/981)) ([#983](https://github.com/arthurmaciel/ipe-lang/issues/983)) ([5e57afb](https://github.com/arthurmaciel/ipe-lang/commit/5e57afb1349f5a8afce98c89e387f9849ba255bd))
* **lower:** raise IPE-L0141 for Task-typed bare-run in sync do block ([#950](https://github.com/arthurmaciel/ipe-lang/issues/950)) ([#973](https://github.com/arthurmaciel/ipe-lang/issues/973)) ([779eccb](https://github.com/arthurmaciel/ipe-lang/commit/779eccbfe5707fe3e751bbef1401bc9626c8fb6f))
* **lower:** register RetryPolicy concrete IR before ty_contains_var guard ([#978](https://github.com/arthurmaciel/ipe-lang/issues/978)) ([4e0c2d8](https://github.com/arthurmaciel/ipe-lang/commit/4e0c2d87b3191aa9db525ae201207f3dd6661d1f))
* **runtime:** explicit sorted-key canonical JSON for signed JWT/Auth payloads ([#951](https://github.com/arthurmaciel/ipe-lang/issues/951)) ([0150454](https://github.com/arthurmaciel/ipe-lang/commit/0150454ee0e60bc0dc67ddb7132d72fd3f4e482d))
* **runtime:** preserve Json.Encode.object key order ([#949](https://github.com/arthurmaciel/ipe-lang/issues/949)) ([9ff34b4](https://github.com/arthurmaciel/ipe-lang/commit/9ff34b4b14104c99ec694a52bfda68d9b3080678))


### Performance Improvements

* **emit:** emit Task.andThen continuations as Box::new(closure) without __ipe_fn annotation ([#985](https://github.com/arthurmaciel/ipe-lang/issues/985)) ([3fdae80](https://github.com/arthurmaciel/ipe-lang/commit/3fdae80b39fe368bc0e6e0f95ec37c3dbf7514b7))
* **lower:** O(n²)→O(n) let-chain analysis via threaded LetAccum ([#980](https://github.com/arthurmaciel/ipe-lang/issues/980)) ([ee5b902](https://github.com/arthurmaciel/ipe-lang/commit/ee5b9028a17408c21b26408086c2905acb8893f0)), closes [#921](https://github.com/arthurmaciel/ipe-lang/issues/921)

## [0.1.50](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.49...ipe-v0.1.50) (2026-08-13)


### Features

* **ci:** compile every explain/doc Ipê example — doctest-style gate ([#906](https://github.com/arthurmaciel/ipe-lang/issues/906)) ([#931](https://github.com/arthurmaciel/ipe-lang/issues/931)) ([a56d444](https://github.com/arthurmaciel/ipe-lang/commit/a56d4446c9f6846b8bcd14a059ce5831279c8084))


### Bug Fixes

* **canon:** reject unknown Ipe.* stdlib import at the import ([#911](https://github.com/arthurmaciel/ipe-lang/issues/911)) ([#930](https://github.com/arthurmaciel/ipe-lang/issues/930)) ([011efad](https://github.com/arthurmaciel/ipe-lang/commit/011efad5b758edcef320c7044f67c3ba72e93d49))
* **emit:** peel capture-clone in onSubmit/HtmlEvent/lazy callbacks ([#923](https://github.com/arthurmaciel/ipe-lang/issues/923)) ([#929](https://github.com/arthurmaciel/ipe-lang/issues/929)) ([9bc4b97](https://github.com/arthurmaciel/ipe-lang/commit/9bc4b9749fc7c60fa25fcdc2d01b2d0578a8252c))
* **wrapper:** embed profile via include_str! (compile-time UTF-8, drops the flagged panic) ([#935](https://github.com/arthurmaciel/ipe-lang/issues/935)) ([7fce53f](https://github.com/arthurmaciel/ipe-lang/commit/7fce53ff7dd348a56dea92bf6b4f3670743dafba))

## [0.1.49](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.48...ipe-v0.1.49) (2026-08-12)


### Features

* **lang:** reserve _ for pattern positions — reject bare let _ = e at parse ([#869](https://github.com/arthurmaciel/ipe-lang/issues/869)) ([#926](https://github.com/arthurmaciel/ipe-lang/issues/926)) ([808cc98](https://github.com/arthurmaciel/ipe-lang/commit/808cc9834bf02783c4930f806a35eb59042243bd))


### Bug Fixes

* **emit:** route key/file/bool callbacks through capture-clone peel ([#922](https://github.com/arthurmaciel/ipe-lang/issues/922)) ([76dc975](https://github.com/arthurmaciel/ipe-lang/commit/76dc975f0ce00c2edabf73871e2ce86f19fd34f3))
* **install:** move install.sh to repo root; fix stale curl + `ipe upgrade` URLs ([#927](https://github.com/arthurmaciel/ipe-lang/issues/927)) ([b6c44fd](https://github.com/arthurmaciel/ipe-lang/commit/b6c44fda78c4051a7903dca7962a720026673280))

## [0.1.48](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.47...ipe-v0.1.48) (2026-08-12)


### Features

* **ci:** gate user-facing diagnostic text against internal jargon ([#916](https://github.com/arthurmaciel/ipe-lang/issues/916)) ([d9ee3ac](https://github.com/arthurmaciel/ipe-lang/commit/d9ee3ac241eaaffc7f556b5108fdad21bb89b065))
* **db,runtime:** dialect-polymorphic external read-path for Db.open Connection ([#852](https://github.com/arthurmaciel/ipe-lang/issues/852) Part 1) ([#888](https://github.com/arthurmaciel/ipe-lang/issues/888)) ([07e0761](https://github.com/arthurmaciel/ipe-lang/commit/07e0761d21b041ea5919e94c7d1029c91af0dbf1))
* **deploy:** single self-jailing binary by default; --bundle opt-out; --capabilities ([#874](https://github.com/arthurmaciel/ipe-lang/issues/874)) ([#917](https://github.com/arthurmaciel/ipe-lang/issues/917)) ([7927e4b](https://github.com/arthurmaciel/ipe-lang/commit/7927e4b87f654948004f1432a3614c54c52ea696))
* **diagnostics:** conversational second-person voice per error family ([#561](https://github.com/arthurmaciel/ipe-lang/issues/561) Stage 4) ([#898](https://github.com/arthurmaciel/ipe-lang/issues/898)) ([cb54652](https://github.com/arthurmaciel/ipe-lang/commit/cb546524a98becddbc86db8b056cced4bfa9c727))
* **diagnostics:** Elm-faithful layout — prose-first, code demoted ([#561](https://github.com/arthurmaciel/ipe-lang/issues/561) Stage 2) ([#895](https://github.com/arthurmaciel/ipe-lang/issues/895)) ([2529f88](https://github.com/arthurmaciel/ipe-lang/commit/2529f885dec7480f625c8e3c7be9a18c8c7edd7f))
* **diagnostics:** humble Compiler-Bug ICE for an unattributed emitted-crate cargo failure ([#915](https://github.com/arthurmaciel/ipe-lang/issues/915)) ([018edd0](https://github.com/arthurmaciel/ipe-lang/commit/018edd08b59804c5866fb1970d536459f4322225))


### Bug Fixes

* **diagnostics:** accurate titles, textual severity, multi-line/tab/unicode spans, suggestion-span fix ([#561](https://github.com/arthurmaciel/ipe-lang/issues/561) Stage 3) ([#899](https://github.com/arthurmaciel/ipe-lang/issues/899)) ([f4c374f](https://github.com/arthurmaciel/ipe-lang/commit/f4c374f55054087ce7584df0b77829bec135b9b8))
* **lower:** reject non-Task main at ipe time (IPE-L0136) — close a SEAL break ([#913](https://github.com/arthurmaciel/ipe-lang/issues/913)) ([2dab0fb](https://github.com/arthurmaciel/ipe-lang/commit/2dab0fb4c6fcbe0727b8caa2de54d48ca410e0e0))

## [0.1.47](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.46...ipe-v0.1.47) (2026-08-11)


### Features

* **deploy:** ipe deploy — self-contained toolchain-free jailed bundle ([#870](https://github.com/arthurmaciel/ipe-lang/issues/870)) ([b5e7535](https://github.com/arthurmaciel/ipe-lang/commit/b5e7535fc60acdea48bbce023083d7d89fe6e57a))


### Bug Fixes

* **ci:** serialize cwd-mutating and cargo-building integration tests ([#877](https://github.com/arthurmaciel/ipe-lang/issues/877)) ([ac2ea72](https://github.com/arthurmaciel/ipe-lang/commit/ac2ea72946a107956f3fe5424cf34fc312ef822d))
* **converter:** make rehome_kernel_alias comment/string-safe via span-pairing ([#885](https://github.com/arthurmaciel/ipe-lang/issues/885)) ([aec5ff2](https://github.com/arthurmaciel/ipe-lang/commit/aec5ff2f22bf8300e32f427ee13e1030285c1431))
* **converter:** migrate three stale Sky-vintage APIs so 36-composite-server compiles ([#880](https://github.com/arthurmaciel/ipe-lang/issues/880)) ([#884](https://github.com/arthurmaciel/ipe-lang/issues/884)) ([3dc36ce](https://github.com/arthurmaciel/ipe-lang/commit/3dc36ce24cd653869a32c86e70806500fba3d57c))
* **converter:** re-home user-source Ffi.kernel aliases onto their published qualifier ([#844](https://github.com/arthurmaciel/ipe-lang/issues/844)) ([#878](https://github.com/arthurmaciel/ipe-lang/issues/878)) ([9ebc4ec](https://github.com/arthurmaciel/ipe-lang/commit/9ebc4ec3a8aa42e59cc2e3fbdf94e1eb4640c706))
* **deploy:** clear typed error for pure apps instead of raw Io error ([#881](https://github.com/arthurmaciel/ipe-lang/issues/881)) ([8727666](https://github.com/arthurmaciel/ipe-lang/commit/87276661d074091922554e8057aa3285118c37b0)), closes [#872](https://github.com/arthurmaciel/ipe-lang/issues/872)
* **watch:** emit runtime as path-dep with correct crate root — closes [#851](https://github.com/arthurmaciel/ipe-lang/issues/851) ([#876](https://github.com/arthurmaciel/ipe-lang/issues/876)) ([3b5834b](https://github.com/arthurmaciel/ipe-lang/commit/3b5834b6099a61f51537227c7af31b9056d81398))

## [0.1.46](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.45...ipe-v0.1.46) (2026-08-11)


### Features

* **db,security:** typed read-only external Connection for Db.open ([#853](https://github.com/arthurmaciel/ipe-lang/issues/853)) ([62fd2b6](https://github.com/arthurmaciel/ipe-lang/commit/62fd2b68329f0cf965c2bd1568a718c539a9459a))


### Bug Fixes

* **backend:** record update on a non-Clone base must not emit unconditional clone ([#863](https://github.com/arthurmaciel/ipe-lang/issues/863)) ([e738578](https://github.com/arthurmaciel/ipe-lang/commit/e7385783717660ea5122ac76481979aba66f1d26))
* **canon:** reject mis-arity Connection with IPE-N0031 instead of an ICE ([#857](https://github.com/arthurmaciel/ipe-lang/issues/857)) ([78a418e](https://github.com/arthurmaciel/ipe-lang/commit/78a418e6ac6e510ca51bf2e22853a0cc118b16d8))
* **canon:** unify reserved-type-name gates into one SSOT ([#861](https://github.com/arthurmaciel/ipe-lang/issues/861)) ([ffe5846](https://github.com/arthurmaciel/ipe-lang/commit/ffe58461d0c9a52ecbde94ba375260e445e15421)), closes [#847](https://github.com/arthurmaciel/ipe-lang/issues/847)
* **diagnostics,canon:** register IPE-N0030 + dedup STDLIB_MODULE_QUALIFIERS with distinctness guards ([#859](https://github.com/arthurmaciel/ipe-lang/issues/859)) ([e2022ff](https://github.com/arthurmaciel/ipe-lang/commit/e2022ffa7b4348a8a4a719c317727382b1b4af79))
* **kernels:** add StdlibKernel::ALL completeness guard ([#686](https://github.com/arthurmaciel/ipe-lang/issues/686)) ([#865](https://github.com/arthurmaciel/ipe-lang/issues/865)) ([2423836](https://github.com/arthurmaciel/ipe-lang/commit/2423836f39af93ef714d21a31c774ec88877140e))
* **lower:** count moves hidden in an Access/Update base (close residual E0382) ([#856](https://github.com/arthurmaciel/ipe-lang/issues/856)) ([8c9442d](https://github.com/arthurmaciel/ipe-lang/commit/8c9442d7a3e2bb48f9e4fa688e0f323c9c8f559c))
* **test:** rewrite json_dec_pipeline_lambda1 to pipe form ([#864](https://github.com/arthurmaciel/ipe-lang/issues/864)) ([eee8b29](https://github.com/arthurmaciel/ipe-lang/commit/eee8b2919a36778820470944afb9f94a1c29b660))

## [0.1.45](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.44...ipe-v0.1.45) (2026-08-10)


### Features

* **cli,security:** build-time acknowledgment for .Unsafe imports + --accept-risks ([#773](https://github.com/arthurmaciel/ipe-lang/issues/773)) ([#840](https://github.com/arthurmaciel/ipe-lang/issues/840)) ([8a228cf](https://github.com/arthurmaciel/ipe-lang/commit/8a228cfa81066a86e5dbc9baefe7fa13e96e8b96))


### Bug Fixes

* **canon,security:** origin-gate Ffi.kernel so user source cannot mint kernels ([#843](https://github.com/arthurmaciel/ipe-lang/issues/843)) ([1a22484](https://github.com/arthurmaciel/ipe-lang/commit/1a22484e707a07226a04b49667be6c7649f6f8fc))
* **ci,test:** deterministic e2e shards + seal-smoke role + e2e-all gating job ([#850](https://github.com/arthurmaciel/ipe-lang/issues/850)) ([32c4ea9](https://github.com/arthurmaciel/ipe-lang/commit/32c4ea910d2ddf88de39662da797db2a65e2eb5c))
* **cli:** resolve static build-plan refusals before the unsafe-import ack ([#846](https://github.com/arthurmaciel/ipe-lang/issues/846)) ([1f4fd2a](https://github.com/arthurmaciel/ipe-lang/commit/1f4fd2a43b35e951f520038cf724fd7868c3d14b))
* **lower:** thread cross-module concrete return through a generic HOF's tyvar ([#845](https://github.com/arthurmaciel/ipe-lang/issues/845)) ([8565b48](https://github.com/arthurmaciel/ipe-lang/commit/8565b48be442e9c0fc199eac810c308570e5950d))
* **lower:** value-reuse must not assume Clone for non-Clone union payloads ([#848](https://github.com/arthurmaciel/ipe-lang/issues/848)) ([7b885b2](https://github.com/arthurmaciel/ipe-lang/commit/7b885b2ba3374d91dd4a5f2a015e9ea61b6094b2))

## [0.1.44](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.43...ipe-v0.1.44) (2026-08-10)


### Features

* **stdlib:** Ipe.Db.Dsn parse-don't-validate surface — step 1 of external Db.open ([#641](https://github.com/arthurmaciel/ipe-lang/issues/641)) ([#830](https://github.com/arthurmaciel/ipe-lang/issues/830)) ([f0dbf4c](https://github.com/arthurmaciel/ipe-lang/commit/f0dbf4c1676be76c298a68f9fd083fbb53a58aca))


### Bug Fixes

* **backend:** generic record-of-function gets Clone impl ([#814](https://github.com/arthurmaciel/ipe-lang/issues/814)) ([#823](https://github.com/arthurmaciel/ipe-lang/issues/823)) ([96be306](https://github.com/arthurmaciel/ipe-lang/commit/96be306fff770e2dd5354a011fe9d2cb9e15aaf1))
* **canon:** exposing (Type(subset)) opens only the named constructors ([#821](https://github.com/arthurmaciel/ipe-lang/issues/821)) ([b3fecc5](https://github.com/arthurmaciel/ipe-lang/commit/b3fecc59b959f62753b037baee35abf77106c1f7)), closes [#780](https://github.com/arthurmaciel/ipe-lang/issues/780)
* **effects:** Io.println is a lawful Task — reject the sync-context effect discard (IPE-L0141) ([#837](https://github.com/arthurmaciel/ipe-lang/issues/837)) ([d8ffd03](https://github.com/arthurmaciel/ipe-lang/commit/d8ffd03b80c10f4689bf148d1a40df82ab194fef))
* **html:** neutralise `</script` breakout in safe-surface `<script>` bodies (XSS) ([#833](https://github.com/arthurmaciel/ipe-lang/issues/833)) ([55a40cd](https://github.com/arthurmaciel/ipe-lang/commit/55a40cd700548eed247c1b31c5ef6278d33c3ce7)), closes [#832](https://github.com/arthurmaciel/ipe-lang/issues/832)
* **html:** render escaping guarantee + Ipe.Html.Unsafe.unsafeScript inline-script hatch ([#666](https://github.com/arthurmaciel/ipe-lang/issues/666)) ([#831](https://github.com/arthurmaciel/ipe-lang/issues/831)) ([9a97adc](https://github.com/arthurmaciel/ipe-lang/commit/9a97adc0bdca81025a4880043f071b0940e7e402))
* **runtime/web:** stamp SSE-reconnect reconciled tree so click handlers resolve ([#760](https://github.com/arthurmaciel/ipe-lang/issues/760)) ([#839](https://github.com/arthurmaciel/ipe-lang/issues/839)) ([472ba26](https://github.com/arthurmaciel/ipe-lang/commit/472ba26194d0935a390748513cc339716d4b68a4))
* **runtime:** one Length/Color CSS renderer for the Ui inline-style and stylesheet paths ([#688](https://github.com/arthurmaciel/ipe-lang/issues/688)) ([#835](https://github.com/arthurmaciel/ipe-lang/issues/835)) ([7443455](https://github.com/arthurmaciel/ipe-lang/commit/744345567733ba521787ccedfb6ba77742696276))
* **runtime:** reject empty dotted-ident segments in SqlIdent SSOT ([#827](https://github.com/arthurmaciel/ipe-lang/issues/827)) ([650f6cc](https://github.com/arthurmaciel/ipe-lang/commit/650f6cc6827bb85cd92aeffbbbb2e50b5555e5ea)), closes [#818](https://github.com/arthurmaciel/ipe-lang/issues/818)

## [0.1.43](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.42...ipe-v0.1.43) (2026-08-10)


### Features

* **codec:** Codec.auto type-driven derive ([#663](https://github.com/arthurmaciel/ipe-lang/issues/663)) ([#811](https://github.com/arthurmaciel/ipe-lang/issues/811)) ([a76f6b3](https://github.com/arthurmaciel/ipe-lang/commit/a76f6b3428cc95ce6c242da4ea5362e07db346ea))
* **codec:** full Ipe.Codec combinator surface — list/maybe/dict/enum/taggedUnion/record ([#663](https://github.com/arthurmaciel/ipe-lang/issues/663)) ([#808](https://github.com/arthurmaciel/ipe-lang/issues/808)) ([ca936c3](https://github.com/arthurmaciel/ipe-lang/commit/ca936c312ab80cd93f34e139623311b81cc79307))
* **stdlib:** Ipe.Db.Store — codec-driven injection-safe persistence ([#680](https://github.com/arthurmaciel/ipe-lang/issues/680)) ([#816](https://github.com/arthurmaciel/ipe-lang/issues/816)) ([11d6425](https://github.com/arthurmaciel/ipe-lang/commit/11d64255d8c5ecc668c0b9083da8d0b6ffc84822))


### Bug Fixes

* **backend,codec:** propagate Sync through captured composites; complete enum/taggedUnion/varN ([#807](https://github.com/arthurmaciel/ipe-lang/issues/807), [#663](https://github.com/arthurmaciel/ipe-lang/issues/663)) ([#810](https://github.com/arthurmaciel/ipe-lang/issues/810)) ([fc69c91](https://github.com/arthurmaciel/ipe-lang/commit/fc69c91263a59345ebc781082aca5466f2e9e0c7))
* **backend:** coerce SharedFun record/enum reads into higher-order-fn params ([#793](https://github.com/arthurmaciel/ipe-lang/issues/793)) ([#796](https://github.com/arthurmaciel/ipe-lang/issues/796)) ([a2626a5](https://github.com/arthurmaciel/ipe-lang/commit/a2626a564a86ad1ef23238c3231c06c1e05904c8))
* **backend:** make stored Decoder reusable via clonable Arc carrier ([#801](https://github.com/arthurmaciel/ipe-lang/issues/801)) ([#803](https://github.com/arthurmaciel/ipe-lang/issues/803)) ([8a34f1c](https://github.com/arthurmaciel/ipe-lang/commit/8a34f1c997b2bb35560683ee6fdef959d27ad804))
* **backend:** propagate Send bounds + coerce SharedFun into kernel-arg Fn for generic combinators ([#798](https://github.com/arthurmaciel/ipe-lang/issues/798)) ([#800](https://github.com/arthurmaciel/ipe-lang/issues/800)) ([90731a8](https://github.com/arthurmaciel/ipe-lang/commit/90731a8049136a05d245ada686a8aeebeafa46c7))
* **backend:** propagate Sync on Decoder-materialized tvars via capture-site matcher ([#802](https://github.com/arthurmaciel/ipe-lang/issues/802)) ([#805](https://github.com/arthurmaciel/ipe-lang/issues/805)) ([0a71c58](https://github.com/arthurmaciel/ipe-lang/commit/0a71c589fea1ee381ce3963586cf75928268f0e1))
* **cli-docs:** correct ipe doc surface in AGENTS template to match the CLI ([#812](https://github.com/arthurmaciel/ipe-lang/issues/812)) ([88b6406](https://github.com/arthurmaciel/ipe-lang/commit/88b64062c9fbc3ab9df7e81fa23a73b368360a70)), closes [#788](https://github.com/arthurmaciel/ipe-lang/issues/788)
* **lower,ir:** narrow L0126/L0127 for the Decoder/SharedFun carriers ([#799](https://github.com/arthurmaciel/ipe-lang/issues/799)) ([#806](https://github.com/arthurmaciel/ipe-lang/issues/806)) ([2750749](https://github.com/arthurmaciel/ipe-lang/commit/2750749b76425fe1b81b4a0c7cd854a690939afa))
* **runtime,db:** unsafeGetInt fails closed to 0, never saturates out-of-range float ([#745](https://github.com/arthurmaciel/ipe-lang/issues/745)) ([#820](https://github.com/arthurmaciel/ipe-lang/issues/820)) ([d55e2f4](https://github.com/arthurmaciel/ipe-lang/commit/d55e2f42256a263fbaf7f7b3d9b5a9921921337b))
* **runtime:** one SQL-identifier validator SSOT on the db.rs injection boundary ([#679](https://github.com/arthurmaciel/ipe-lang/issues/679)) ([#817](https://github.com/arthurmaciel/ipe-lang/issues/817)) ([fb72db9](https://github.com/arthurmaciel/ipe-lang/commit/fb72db9b7311040aa013deb047a32f5e363d74b4))
* **sandbox:** bind the capfloor env axis by name, not count ([#703](https://github.com/arthurmaciel/ipe-lang/issues/703)) ([#819](https://github.com/arthurmaciel/ipe-lang/issues/819)) ([e888dab](https://github.com/arthurmaciel/ipe-lang/commit/e888dab30c4006cbe4598254681670e079ad3f24))

## [0.1.42](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.41...ipe-v0.1.42) (2026-08-09)


### Features

* **lower:** FCF Approach A slice 3 — collection-element Arc carrier (frontier total, fail-closed) ([#776](https://github.com/arthurmaciel/ipe-lang/issues/776)) ([83a2ab6](https://github.com/arthurmaciel/ipe-lang/commit/83a2ab6c84f304ec75273417117f15b3222866cc))


### Bug Fixes

* **backend:** normalize fn record/enum-literal fields onto the SharedFun Arc carrier ([#789](https://github.com/arthurmaciel/ipe-lang/issues/789)) ([#792](https://github.com/arthurmaciel/ipe-lang/issues/792)) ([1697e36](https://github.com/arthurmaciel/ipe-lang/commit/1697e362cc784afd97bbc050ca08ac63e5f3cda4))
* **canon:** home Ipe.Ui's re-exported Attribute to the Ui carrier so stdui animation/grid/transition seals build ([#777](https://github.com/arthurmaciel/ipe-lang/issues/777)) ([#784](https://github.com/arthurmaciel/ipe-lang/issues/784)) ([9ba6609](https://github.com/arthurmaciel/ipe-lang/commit/9ba6609b113faaf62aecb4840c3e6f4d45bec131))
* **canon:** honor explicit exposing(Type(..)) for qualified-home union constructors ([#653](https://github.com/arthurmaciel/ipe-lang/issues/653) follow-up) ([#779](https://github.com/arthurmaciel/ipe-lang/issues/779)) ([43be51f](https://github.com/arthurmaciel/ipe-lang/commit/43be51f9e7a6c582435a1484a1eb00f2f7081cd5))
* **cli:** bare-word mode selectors (ipe doc list / ipe diff check) with deprecation shims ([#699](https://github.com/arthurmaciel/ipe-lang/issues/699)) ([#787](https://github.com/arthurmaciel/ipe-lang/issues/787)) ([b42b880](https://github.com/arthurmaciel/ipe-lang/commit/b42b88092a99f09452d5d1dfdf8b71a15503faa6))
* **ffi:** pin externally-referenced crates in emitted FFI Cargo.toml ([#777](https://github.com/arthurmaciel/ipe-lang/issues/777)) ([#785](https://github.com/arthurmaciel/ipe-lang/issues/785)) ([1ccad89](https://github.com/arthurmaciel/ipe-lang/commit/1ccad896bf878eacc160d67c3e64eb77612978df))
* **json-dec:** migrate pipeline fixtures so valid nested-decoder pipelines compile ([#777](https://github.com/arthurmaciel/ipe-lang/issues/777)) ([#783](https://github.com/arthurmaciel/ipe-lang/issues/783)) ([2810468](https://github.com/arthurmaciel/ipe-lang/commit/2810468ea11ece6ce1f4dac7161471262369de0d))
* **lower:** narrow the RetryPolicy fn-carrier exemption to the closed 5-field shape ([#665](https://github.com/arthurmaciel/ipe-lang/issues/665)) ([#790](https://github.com/arthurmaciel/ipe-lang/issues/790)) ([303ddfe](https://github.com/arthurmaciel/ipe-lang/commit/303ddfeaf03b29376970089cd7b9ac49d9f54e7b))
* **lower:** select the decimal feature on a Money/Decimal type-mention ([#777](https://github.com/arthurmaciel/ipe-lang/issues/777)) ([#781](https://github.com/arthurmaciel/ipe-lang/issues/781)) ([a755d44](https://github.com/arthurmaciel/ipe-lang/commit/a755d446826963522c2311edcf9b78bf85b47e30))
* **random:** resolve Ipe.Random shuffle/weighted/seed/seeded* members ([#672](https://github.com/arthurmaciel/ipe-lang/issues/672)) ([#791](https://github.com/arthurmaciel/ipe-lang/issues/791)) ([37e0b7f](https://github.com/arthurmaciel/ipe-lang/commit/37e0b7f992798b055d69043eeca3bde942cc58b5))
* **wasm:** emit named MainHydrationState so hydrate glue is generated for wasm ([#224](https://github.com/arthurmaciel/ipe-lang/issues/224)) ([#786](https://github.com/arthurmaciel/ipe-lang/issues/786)) ([8e0fa84](https://github.com/arthurmaciel/ipe-lang/commit/8e0fa84b03e88c8bba377a84610b381fb5a006c6))

## [0.1.41](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.40...ipe-v0.1.41) (2026-08-09)


### Features

* **lower:** FCF Approach A slices 1+2 — Arc-carrier promotion for forwarded functions ([#767](https://github.com/arthurmaciel/ipe-lang/issues/767)) ([f0bf65c](https://github.com/arthurmaciel/ipe-lang/commit/f0bf65c074d70202f9a981adcdb75560ecde550f))


### Bug Fixes

* **cli:** single-source subcommand registry so dispatch and help cannot drift ([#701](https://github.com/arthurmaciel/ipe-lang/issues/701)) ([#770](https://github.com/arthurmaciel/ipe-lang/issues/770)) ([e1e1f9f](https://github.com/arthurmaciel/ipe-lang/commit/e1e1f9fae4e2f954342a9ad137a2e47491dfe243))
* **cli:** stream emitted cargo build progress in ipe build/run ([#757](https://github.com/arthurmaciel/ipe-lang/issues/757)) ([#765](https://github.com/arthurmaciel/ipe-lang/issues/765)) ([5ee6986](https://github.com/arthurmaciel/ipe-lang/commit/5ee698649029e984252c1e715059a8c77de46bf1))
* **codegen:** clone reused non-Copy cache handle across Task steps ([#676](https://github.com/arthurmaciel/ipe-lang/issues/676)) ([#768](https://github.com/arthurmaciel/ipe-lang/issues/768)) ([eb5226f](https://github.com/arthurmaciel/ipe-lang/commit/eb5226ff8dbaf772220354f825e7ca0c68accb07))
* **doc:** single-source the documented-module registry so --list and query agree ([#698](https://github.com/arthurmaciel/ipe-lang/issues/698)) ([#771](https://github.com/arthurmaciel/ipe-lang/issues/771)) ([ad95865](https://github.com/arthurmaciel/ipe-lang/commit/ad958653dc4356fc4d1cb921d48af50e08af2cd7))

## [0.1.40](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.39...ipe-v0.1.40) (2026-08-05)


### Features

* **capability:** add the `unsafe` capability + `Ipe.<M>.Unsafe` disclosure plumbing ([#679](https://github.com/arthurmaciel/ipe-lang/issues/679) slice 0) ([#729](https://github.com/arthurmaciel/ipe-lang/issues/729)) ([a159246](https://github.com/arthurmaciel/ipe-lang/commit/a1592464232ed9dbc20a1572afc82e3b0685b354))
* **stdlib:** add Ipe.Codec JSON-direction compiled-source surface (codec slice 1) ([#740](https://github.com/arthurmaciel/ipe-lang/issues/740)) ([d96c0d5](https://github.com/arthurmaciel/ipe-lang/commit/d96c0d5369c1c4ad53d2f12fea1cc711c1459b12))
* **stdlib:** add scoped Secret.use + relocate Secret.reveal -&gt; Ipe.Secret.Unsafe.unsafeReveal (unsafe-axis slice E) ([#679](https://github.com/arthurmaciel/ipe-lang/issues/679)) ([#736](https://github.com/arthurmaciel/ipe-lang/issues/736)) ([cdde69b](https://github.com/arthurmaciel/ipe-lang/commit/cdde69b9f3a600e9e304d72a062083103e8af183))
* **stdlib:** convert Ipe.Ui layout builders to compiled-source ([#726](https://github.com/arthurmaciel/ipe-lang/issues/726)) ([0a7f808](https://github.com/arthurmaciel/ipe-lang/commit/0a7f8086fc3ee7b58e54c41645eda9e3f559c726))
* **stdlib:** relocate Html.unsafeRaw -&gt; Ipe.Html.Unsafe.unsafeRaw (unsafe-axis slice A) ([#679](https://github.com/arthurmaciel/ipe-lang/issues/679)) ([#730](https://github.com/arthurmaciel/ipe-lang/issues/730)) ([0ab85b0](https://github.com/arthurmaciel/ipe-lang/commit/0ab85b01d1b07356c82ae59796e2dc47ce8f363a))
* **stdlib:** relocate raw-SQL / untyped-read Db hatches to Ipe.Db.Unsafe + add unsafeFragment (unsafe-axis slice C) ([#679](https://github.com/arthurmaciel/ipe-lang/issues/679)) ([#733](https://github.com/arthurmaciel/ipe-lang/issues/733)) ([903cba4](https://github.com/arthurmaciel/ipe-lang/commit/903cba44734b7fc59643cc0cf9076fb5f80a3e7d))
* **stdlib:** relocate Web.Head.unsafeJsonLd to Ipe.Web.Head.Unsafe (unsafe-axis slice D) ([#679](https://github.com/arthurmaciel/ipe-lang/issues/679)) ([#735](https://github.com/arthurmaciel/ipe-lang/issues/735)) ([6a2a529](https://github.com/arthurmaciel/ipe-lang/commit/6a2a5298829f6ad60629c5a252656fe3df685ccf))


### Bug Fixes

* **lower:** close http-stream ChunkEvent/StreamId module-set SEAL breach ([#724](https://github.com/arthurmaciel/ipe-lang/issues/724)) ([d7b2c52](https://github.com/arthurmaciel/ipe-lang/commit/d7b2c52b0930958b5ab88e1ce17b9866b21589b3))

## [0.1.39](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.38...ipe-v0.1.39) (2026-08-05)


### Features

* **kernels,types:** polymorphic TyShape (type vars) + migrate the List family, on the D.2 base (Kernel Row stage D.3) ([#696](https://github.com/arthurmaciel/ipe-lang/issues/696)) ([fc17bec](https://github.com/arthurmaciel/ipe-lang/commit/fc17becf6d27d498091928f671ad8e31364da2b6))
* **kernels,types:** TyShape scheme ADT + interpreter, migrate the Bitwise family (Kernel Row stage D template slice) ([#694](https://github.com/arthurmaciel/ipe-lang/issues/694)) ([14603fe](https://github.com/arthurmaciel/ipe-lang/commit/14603fe7eb2fb8b05e54453f990d26e79d55bd5d))
* **kernels:** KernelDef descriptor projecting the existing kernel row + emit-symbol-defined invariant test (Kernel Row stage A) ([#685](https://github.com/arthurmaciel/ipe-lang/issues/685)) ([4e5c7df](https://github.com/arthurmaciel/ipe-lang/commit/4e5c7df592e4188f634fb5de55a30e7c3f447bef))
* **sandbox:** aarch64 Linux Tier-2 certifying seccomp arm ([#620](https://github.com/arthurmaciel/ipe-lang/issues/620)) ([#670](https://github.com/arthurmaciel/ipe-lang/issues/670)) ([040ba10](https://github.com/arthurmaciel/ipe-lang/commit/040ba1012651f01c20277aa612c53b3c5009c40e))
* **types:** resolve KernelDef scheme by key + arity-vs-scheme coherence test (Kernel Row stage C) ([#692](https://github.com/arthurmaciel/ipe-lang/issues/692)) ([0ae0298](https://github.com/arthurmaciel/ipe-lang/commit/0ae029879b835cf5c0b31a33a3b812e1ea27ec26))


### Bug Fixes

* **backend,lower:** emit the Ipe.Cache runtime module + close the bare-handle SEAL hole ([#661](https://github.com/arthurmaciel/ipe-lang/issues/661)) ([#684](https://github.com/arthurmaciel/ipe-lang/issues/684)) ([35c33d4](https://github.com/arthurmaciel/ipe-lang/commit/35c33d4a9959daf05bc597e1a07c9a53d18420f3))
* **canon:** resolve Random.range as an int-kernel alias ([#667](https://github.com/arthurmaciel/ipe-lang/issues/667)) ([#673](https://github.com/arthurmaciel/ipe-lang/issues/673)) ([b5eb86e](https://github.com/arthurmaciel/ipe-lang/commit/b5eb86e09bc5f868fe216a9e563c8675dfb16fa8))
* **examples:** green 02/03/18/26/32 mirror examples (Task-boundary, Element view, Http/Regex APIs) ([#580](https://github.com/arthurmaciel/ipe-lang/issues/580)) ([#669](https://github.com/arthurmaciel/ipe-lang/issues/669)) ([88b0cc4](https://github.com/arthurmaciel/ipe-lang/commit/88b0cc4451345ee333566ef5fb7722b1264cf99e))
* **examples:** remap N0036 Task.run examples 07/14/35 onto TEA auto-run entry ([#580](https://github.com/arthurmaciel/ipe-lang/issues/580)) ([#660](https://github.com/arthurmaciel/ipe-lang/issues/660)) ([74ad83d](https://github.com/arthurmaciel/ipe-lang/commit/74ad83d90f90c852968cd77c4cf11e7e4b5e5e29))
* **sandbox:** deny pidfd_getfd/bpf/userfaultfd/keyctl/kexec in the seccomp baseline (both ABIs) ([#671](https://github.com/arthurmaciel/ipe-lang/issues/671)) ([#682](https://github.com/arthurmaciel/ipe-lang/issues/682)) ([126bbdb](https://github.com/arthurmaciel/ipe-lang/commit/126bbdbf872c348a4e5868f0438cc4c7df049031))
* **sandbox:** root FreeBSD /proc-mask source outside writable scratch ([#658](https://github.com/arthurmaciel/ipe-lang/issues/658)) ([#675](https://github.com/arthurmaciel/ipe-lang/issues/675)) ([e8b0797](https://github.com/arthurmaciel/ipe-lang/commit/e8b0797acf08654a177dd94c09ba003adfaf012c))
* **types:** fail closed on a managed-loop view that settles to Html — IPE-T0020 ([#647](https://github.com/arthurmaciel/ipe-lang/issues/647)) ([#668](https://github.com/arthurmaciel/ipe-lang/issues/668)) ([217fe00](https://github.com/arthurmaciel/ipe-lang/commit/217fe00fa5f6e56c38b5d01c30ec230c269e1b36))

## [0.1.38](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.37...ipe-v0.1.38) (2026-08-04)


### Features

* **examples:** idiomatic TEA async-DB port of 17-skymon (ipe-overrides) ([#644](https://github.com/arthurmaciel/ipe-lang/issues/644)) ([a391879](https://github.com/arthurmaciel/ipe-lang/commit/a3918795b4c2b23954236011289ac4587b772000))
* **examples:** ipe-overrides/12-skyvote — TEA async-DB port ([#638](https://github.com/arthurmaciel/ipe-lang/issues/638)) ([3ac8b65](https://github.com/arthurmaciel/ipe-lang/commit/3ac8b65a6773dd09fa14c66e29cf2556d97f4a5b))
* **examples:** ipe-overrides/16-skychess — TEA async-DB port ([#580](https://github.com/arthurmaciel/ipe-lang/issues/580)) ([#639](https://github.com/arthurmaciel/ipe-lang/issues/639)) ([e9d56b7](https://github.com/arthurmaciel/ipe-lang/commit/e9d56b70436c7cd6b5af799cfaec0390b0524835))
* **scripts:** generalize the Sky→Ipê transform to any project + Go→Rust FFI dependency map ([#652](https://github.com/arthurmaciel/ipe-lang/issues/652)) ([d9fbbc3](https://github.com/arthurmaciel/ipe-lang/commit/d9fbbc3d6938f382f1be287a9d5c65c33f3a242d))


### Bug Fixes

* **canon:** scope HttpMethod verbs to Http qualifier, unshadowing user ctors ([#653](https://github.com/arthurmaciel/ipe-lang/issues/653)) ([0a0a949](https://github.com/arthurmaciel/ipe-lang/commit/0a0a949e3033be76785a2b35a3b8ab64990f2686)), closes [#646](https://github.com/arthurmaciel/ipe-lang/issues/646)
* **diagnostics:** register IPE-N0036 + IPE-N0030 so `ipe explain` resolves them ([#629](https://github.com/arthurmaciel/ipe-lang/issues/629)) ([#640](https://github.com/arthurmaciel/ipe-lang/issues/640)) ([7c793cc](https://github.com/arthurmaciel/ipe-lang/commit/7c793cc9a5284985f6c54c7ff0fa4627c5896d31))
* **emit:** sound curry lowering for `succeed` applied to a fn value ([#634](https://github.com/arthurmaciel/ipe-lang/issues/634)) ([#642](https://github.com/arthurmaciel/ipe-lang/issues/642)) ([2d75899](https://github.com/arthurmaciel/ipe-lang/commit/2d75899fbdcc5725116aa6a50a2d38ef62679d12))
* **examples:** add missing stdlib imports to 8 Sky-mirror ports ([#580](https://github.com/arthurmaciel/ipe-lang/issues/580)) ([#655](https://github.com/arthurmaciel/ipe-lang/issues/655)) ([0f8e41d](https://github.com/arthurmaciel/ipe-lang/commit/0f8e41d2f4a9a1523d9f4c857dc9e0c690e72f9d))
* **examples:** green 19-skyforum, 28-streaming-chat, 37-composite-live-shop ([#580](https://github.com/arthurmaciel/ipe-lang/issues/580)) ([#650](https://github.com/arthurmaciel/ipe-lang/issues/650)) ([c3adc63](https://github.com/arthurmaciel/ipe-lang/commit/c3adc63d0a84bf37149d575095d9abeab832856e))
* **examples:** map removed Cli/Tui/Webview mirror shapes onto Ipe.Tea.Terminal/WebView ([#656](https://github.com/arthurmaciel/ipe-lang/issues/656)) ([cc8f538](https://github.com/arthurmaciel/ipe-lang/commit/cc8f5388a6913a7e0117dce15a71c24598d543c5)), closes [#580](https://github.com/arthurmaciel/ipe-lang/issues/580)
* **examples:** remap 24-tui-kitchen-sink + 38-composite mirror shapes onto Terminal/WebView ([#580](https://github.com/arthurmaciel/ipe-lang/issues/580)) ([#659](https://github.com/arthurmaciel/ipe-lang/issues/659)) ([798a022](https://github.com/arthurmaciel/ipe-lang/commit/798a02210a98f234adb45f957231db3837ca678a))
* **lower:** fail-closed gate for a fn value reaching a record field via a reified generic slot ([#584](https://github.com/arthurmaciel/ipe-lang/issues/584)) ([#636](https://github.com/arthurmaciel/ipe-lang/issues/636)) ([229e400](https://github.com/arthurmaciel/ipe-lang/commit/229e4008d1e37f29b687752667176e5ddf51305e))
* **sandbox:** FreeBSD build-jail mounts fresh devfs + masks /proc ([#645](https://github.com/arthurmaciel/ipe-lang/issues/645)) ([#657](https://github.com/arthurmaciel/ipe-lang/issues/657)) ([aa58734](https://github.com/arthurmaciel/ipe-lang/commit/aa58734230879978f7a8b65b23190157662206e6))
* **sandbox:** FreeBSD Tier-2 jail truly denies network + filesystem axes ([#266](https://github.com/arthurmaciel/ipe-lang/issues/266)) ([#648](https://github.com/arthurmaciel/ipe-lang/issues/648)) ([7f0f1bf](https://github.com/arthurmaciel/ipe-lang/commit/7f0f1bf52decf7f7ba3e6375cfc952bf79684508))
* **sandbox:** render macOS SBPL scratch write-allow in symlink-resolved form ([#654](https://github.com/arthurmaciel/ipe-lang/issues/654)) ([b5bddff](https://github.com/arthurmaciel/ipe-lang/commit/b5bddffbcb6ff09eda2347af65bb0a0d6ffb6df1)), closes [#266](https://github.com/arthurmaciel/ipe-lang/issues/266)
* **sandbox:** Windows CreateProcessW env block sorts in uppercase-ordinal order ([#266](https://github.com/arthurmaciel/ipe-lang/issues/266)) ([#649](https://github.com/arthurmaciel/ipe-lang/issues/649)) ([4c983b8](https://github.com/arthurmaciel/ipe-lang/commit/4c983b8fec720402a050eebaa97037163154eefe))

## [0.1.37](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.36...ipe-v0.1.37) (2026-08-04)


### Features

* **backend:** converge wasm emit onto the runtime dependency-crate model ([#514](https://github.com/arthurmaciel/ipe-lang/issues/514)) ([#602](https://github.com/arthurmaciel/ipe-lang/issues/602)) ([d056102](https://github.com/arthurmaciel/ipe-lang/commit/d056102dca94d6338d5d6ca81135ce31ac95061c))
* **canon,lower,diagnostics:** CustomElement typing acceptance + fail-closed seal gate ([#333](https://github.com/arthurmaciel/ipe-lang/issues/333) increment 2) ([#600](https://github.com/arthurmaciel/ipe-lang/issues/600)) ([67d1535](https://github.com/arthurmaciel/ipe-lang/commit/67d153546191cac50a48d49786736411abcef9e1))
* **canon:** IPE-N0040 rejects hand-nested decoder pipelines, incl. binder indirection, on type-check too ([#614](https://github.com/arthurmaciel/ipe-lang/issues/614) [#615](https://github.com/arthurmaciel/ipe-lang/issues/615) [#619](https://github.com/arthurmaciel/ipe-lang/issues/619) [#622](https://github.com/arthurmaciel/ipe-lang/issues/622)) ([#633](https://github.com/arthurmaciel/ipe-lang/issues/633)) ([bc18895](https://github.com/arthurmaciel/ipe-lang/commit/bc188954c274986be8a036f2e90e553dd81871f6))
* **cli:** ipe test command + verify calls it + standardized verify output ([#609](https://github.com/arthurmaciel/ipe-lang/issues/609) [#610](https://github.com/arthurmaciel/ipe-lang/issues/610)) ([#631](https://github.com/arthurmaciel/ipe-lang/issues/631)) ([4cf38fa](https://github.com/arthurmaciel/ipe-lang/commit/4cf38fad7129c196353b084817f3f270999d8f2d))
* **cli:** rename check→type-check, add `ipe clean`, sectioned usage, safe `ipe init` re-init ([#611](https://github.com/arthurmaciel/ipe-lang/issues/611) [#607](https://github.com/arthurmaciel/ipe-lang/issues/607) [#608](https://github.com/arthurmaciel/ipe-lang/issues/608) [#612](https://github.com/arthurmaciel/ipe-lang/issues/612)) ([#621](https://github.com/arthurmaciel/ipe-lang/issues/621)) ([2d84c15](https://github.com/arthurmaciel/ipe-lang/commit/2d84c15137ca26eba773816cbdd16430322dd496))
* **cli:** streamlined stage-progress output standard + adopt in install.sh and ipe upgrade ([#613](https://github.com/arthurmaciel/ipe-lang/issues/613)) ([#616](https://github.com/arthurmaciel/ipe-lang/issues/616)) ([ee526e6](https://github.com/arthurmaciel/ipe-lang/commit/ee526e681ba5f194b7f3541b432f7211f395c1a7))
* **examples:** ipe-overrides/27-multi-session-chat — TEA async-DB port ([#635](https://github.com/arthurmaciel/ipe-lang/issues/635)) ([285008f](https://github.com/arthurmaciel/ipe-lang/commit/285008fb35fdbe94aad759e22a3ad3ea7c4ac708))
* **lower,backend:** row-poly multi-field argument rows monomorphise per call-site shape ([#287](https://github.com/arthurmaciel/ipe-lang/issues/287)) ([#617](https://github.com/arthurmaciel/ipe-lang/issues/617)) ([da3b07b](https://github.com/arthurmaciel/ipe-lang/commit/da3b07b5ee70f5779389b2c172ebbd492d57be64))


### Bug Fixes

* **canon:** local module shadows stdlib import gate; helper submodule exempt from Program/TEA gate ([#605](https://github.com/arthurmaciel/ipe-lang/issues/605)) ([95c5486](https://github.com/arthurmaciel/ipe-lang/commit/95c54861da74a2d8aec89c16617ba4c71a94be9e))
* **cli:** ipe build compiles the emitted crate so a cargo failure exits non-zero ([#590](https://github.com/arthurmaciel/ipe-lang/issues/590)) ([#627](https://github.com/arthurmaciel/ipe-lang/issues/627)) ([e0dc830](https://github.com/arthurmaciel/ipe-lang/commit/e0dc830a65042d3cd3dbf39bf5f13796a401e221))
* **cli:** rename `ipe doctor` → `ipe health`; real free-disk check; clearer version wording ([#603](https://github.com/arthurmaciel/ipe-lang/issues/603)) ([60bd42c](https://github.com/arthurmaciel/ipe-lang/commit/60bd42cf145f0fa3a07ff20849b6afe265cb9537))
* **examples/transform:** alias-aware stdlib Db raw-surface marking ([#630](https://github.com/arthurmaciel/ipe-lang/issues/630)) ([#632](https://github.com/arthurmaciel/ipe-lang/issues/632)) ([4e67e89](https://github.com/arthurmaciel/ipe-lang/commit/4e67e89729d1e8da9c17e10b26c58e7f6f11d643))
* **examples:** map Std.Live -&gt; Ipe.Tea.Web in the Sky mirror (fixes [#588](https://github.com/arthurmaciel/ipe-lang/issues/588)) ([#618](https://github.com/arthurmaciel/ipe-lang/issues/618)) ([1282864](https://github.com/arthurmaciel/ipe-lang/commit/1282864e5e3164d47559da28f657020d09d01d98))
* **examples:** web-shape view reshape (Html→Element) + Math import — mirror green 11→15/52 ([#580](https://github.com/arthurmaciel/ipe-lang/issues/580)) ([#624](https://github.com/arthurmaciel/ipe-lang/issues/624)) ([43a5195](https://github.com/arthurmaciel/ipe-lang/commit/43a5195350c5e11d42c909c9198296e3f57015a0))
* **lower:** exhaustive, uniform ir_type_mentions feature detection ([#577](https://github.com/arthurmaciel/ipe-lang/issues/577)) ([#628](https://github.com/arthurmaciel/ipe-lang/issues/628)) ([0c9d555](https://github.com/arthurmaciel/ipe-lang/commit/0c9d5552eadee29d5b0a78ed2d8f1c60f2c0f94b))
* **lower:** fail-closed gate for point-free generic-fn-carrier instantiation ([#572](https://github.com/arthurmaciel/ipe-lang/issues/572)) ([#626](https://github.com/arthurmaciel/ipe-lang/issues/626)) ([efd70a7](https://github.com/arthurmaciel/ipe-lang/commit/efd70a75fa7902cf08c79fe88de4c7ca964481f2))

## [0.1.36](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.35...ipe-v0.1.36) (2026-08-04)


### Features

* **backend:** row-polymorphic single-field argument records — Increment 1 ([#287](https://github.com/arthurmaciel/ipe-lang/issues/287)) ([#593](https://github.com/arthurmaciel/ipe-lang/issues/593)) ([8077355](https://github.com/arthurmaciel/ipe-lang/commit/80773550fd57901e1a9357e3b84f46776997fece))
* **cli:** ipe eject — self-contained Rust project with a tree-shaken vendored runtime ([#515](https://github.com/arthurmaciel/ipe-lang/issues/515)) ([#596](https://github.com/arthurmaciel/ipe-lang/issues/596)) ([9252ef5](https://github.com/arthurmaciel/ipe-lang/commit/9252ef579ce285674492417a3658fbec46781ce0))
* **runtime,backend:** bounded recursion — depth guard converts stack-overflow DoS into a contained error ([#532](https://github.com/arthurmaciel/ipe-lang/issues/532)) ([#591](https://github.com/arthurmaciel/ipe-lang/issues/591)) ([ed9d719](https://github.com/arthurmaciel/ipe-lang/commit/ed9d719aab07ff7b2716a63e91ad90fe157821b2))


### Bug Fixes

* **canon:** local module shadows stdlib import gate; helper submodule exempt from Program/TEA gate ([#589](https://github.com/arthurmaciel/ipe-lang/issues/589)) ([6801c37](https://github.com/arthurmaciel/ipe-lang/commit/6801c377adf9027be7d0c8d23c1db2f3799f9629))
* **ci,sandbox:** install nextest in e2e + macOS/Windows/FreeBSD run-jail correctness ([#266](https://github.com/arthurmaciel/ipe-lang/issues/266)) ([#599](https://github.com/arthurmaciel/ipe-lang/issues/599)) ([4676ef2](https://github.com/arthurmaciel/ipe-lang/commit/4676ef2dcf56cb3159ca8d615fb5e0c40209f382))
* **release,runtime:** Windows binary builds again + resilient/loud publish + sanction the recursion trip for panic-scan ([#598](https://github.com/arthurmaciel/ipe-lang/issues/598)) ([e1c7a2e](https://github.com/arthurmaciel/ipe-lang/commit/e1c7a2ed535c396d8da081be48c802f2c3d829aa))
* **runtime,backend:** cmd double-render + wasm url import ([#483](https://github.com/arthurmaciel/ipe-lang/issues/483)) ([#586](https://github.com/arthurmaciel/ipe-lang/issues/586)) ([5af51e9](https://github.com/arthurmaciel/ipe-lang/commit/5af51e90c24b7f6eab1f8756848781e66e4bfef8))

## [0.1.35](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.34...ipe-v0.1.35) (2026-08-03)


### Features

* **stdlib:** Ipe.Markdown follows the surrounding theme ([#548](https://github.com/arthurmaciel/ipe-lang/issues/548)) + exposes its parser ([#549](https://github.com/arthurmaciel/ipe-lang/issues/549)) ([#585](https://github.com/arthurmaciel/ipe-lang/issues/585)) ([1baa831](https://github.com/arthurmaciel/ipe-lang/commit/1baa83156406a02fe8f782277472610cd12bdc87))


### Bug Fixes

* **backend:** key record structs by full structural shape, not field-name set ([#553](https://github.com/arthurmaciel/ipe-lang/issues/553)) ([#576](https://github.com/arthurmaciel/ipe-lang/issues/576)) ([1ddd164](https://github.com/arthurmaciel/ipe-lang/commit/1ddd164ff19a3bb8cb8f8dfbd6be3048aca48dcd))
* **backend:** Web programs emit compilable crates — app serde dep ([#566](https://github.com/arthurmaciel/ipe-lang/issues/566)) + no duplicate runtime mod ([#567](https://github.com/arthurmaciel/ipe-lang/issues/567)) ([#570](https://github.com/arthurmaciel/ipe-lang/issues/570)) ([f1a818d](https://github.com/arthurmaciel/ipe-lang/commit/f1a818d9c03629142fdddb34cf9b4482768c2165))
* **cli:** fail early on a version-mismatched runtime; drop help page on build failure ([#571](https://github.com/arthurmaciel/ipe-lang/issues/571)) ([56e3bd8](https://github.com/arthurmaciel/ipe-lang/commit/56e3bd8ad224f154aaeeb7d2a5589e39c60204e2))
* **doctor:** reformat suggested-fixes as indented bright-yellow bullets ([#562](https://github.com/arthurmaciel/ipe-lang/issues/562)) ([3e32d83](https://github.com/arthurmaciel/ipe-lang/commit/3e32d83e5c02c473d3ad10b65cbcc788b36e3647))
* **examples:** task-publish uses a typed Topic, not a bare String ([#556](https://github.com/arthurmaciel/ipe-lang/issues/556)) ([#557](https://github.com/arthurmaciel/ipe-lang/issues/557)) ([7ad335f](https://github.com/arthurmaciel/ipe-lang/commit/7ad335f50bfdd1b00dea9408d7d0a2ea520dabbd))
* **examples:** typed Topic handles for pub/sub sites (IPE-T0001) ([#581](https://github.com/arthurmaciel/ipe-lang/issues/581)) ([3e82264](https://github.com/arthurmaciel/ipe-lang/commit/3e8226495eefde84cc1cbd348ca473738772423e))
* **lower:** fail-closed gate for a function instantiating a generic slot ([#579](https://github.com/arthurmaciel/ipe-lang/issues/579)) ([1d28a9b](https://github.com/arthurmaciel/ipe-lang/commit/1d28a9b8833e2cf930485cbb366c24d85630cd24))
* **lower:** scan function bodies for feature-gated types so uses_json is a superset of emission ([#578](https://github.com/arthurmaciel/ipe-lang/issues/578)) ([efb82bb](https://github.com/arthurmaciel/ipe-lang/commit/efb82bb12d8e5799d74629befb0f0a2acc0bdb12))
* **runtime:** textarea/select pseudo-class CSS no longer leaks into value ([#545](https://github.com/arthurmaciel/ipe-lang/issues/545)); fix(fmt): keep inter-constructor comments inside a type ([#554](https://github.com/arthurmaciel/ipe-lang/issues/554)) ([#582](https://github.com/arthurmaciel/ipe-lang/issues/582)) ([1e15016](https://github.com/arthurmaciel/ipe-lang/commit/1e15016b48e1a2177f76ea7bec08e079794a39b1))
* **runtime:** Time.timeString UTC ([#529](https://github.com/arthurmaciel/ipe-lang/issues/529)) + wasm-client build resolves crate::web + weak-hash crates ([#527](https://github.com/arthurmaciel/ipe-lang/issues/527)) ([#568](https://github.com/arthurmaciel/ipe-lang/issues/568)) ([d57b403](https://github.com/arthurmaciel/ipe-lang/commit/d57b4030f74de9ace55b5cb13bc93c3098f67184))
* **ui:** fillPortion flex-basis ([#543](https://github.com/arthurmaciel/ipe-lang/issues/543)) + mediaQuery cascade/target ([#544](https://github.com/arthurmaciel/ipe-lang/issues/544)); feat(stdlib): Ipe.List combinators ([#555](https://github.com/arthurmaciel/ipe-lang/issues/555)) ([#575](https://github.com/arthurmaciel/ipe-lang/issues/575)) ([081eb8d](https://github.com/arthurmaciel/ipe-lang/commit/081eb8d9b2e206f1d306f0c263cc084689002e0a))
* **verify:** resolve project src/ modules from the test stage ([#565](https://github.com/arthurmaciel/ipe-lang/issues/565)) ([#569](https://github.com/arthurmaciel/ipe-lang/issues/569)) ([a3186d4](https://github.com/arthurmaciel/ipe-lang/commit/a3186d4b2ae68d45915797a6416595882218bf10))
* **web:** client-JS event dispatch + navigation/scroll ([#546](https://github.com/arthurmaciel/ipe-lang/issues/546) [#547](https://github.com/arthurmaciel/ipe-lang/issues/547) [#550](https://github.com/arthurmaciel/ipe-lang/issues/550) [#551](https://github.com/arthurmaciel/ipe-lang/issues/551) [#552](https://github.com/arthurmaciel/ipe-lang/issues/552)) ([#583](https://github.com/arthurmaciel/ipe-lang/issues/583)) ([69c4fc4](https://github.com/arthurmaciel/ipe-lang/commit/69c4fc419ed837b32e9d0553297e35118dac42a4))

## [0.1.34](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.33...ipe-v0.1.34) (2026-08-03)


### Features

* **feature-split:** P7b — demote json off the emitted floor ([#540](https://github.com/arthurmaciel/ipe-lang/issues/540)) ([2459993](https://github.com/arthurmaciel/ipe-lang/commit/2459993c3fd055dfc0442296af2987f655be381e))
* **runtime,backend:** gate chrono behind time-core/log so a bare Program drops it (feature-split P4) ([#531](https://github.com/arthurmaciel/ipe-lang/issues/531)) ([03e1179](https://github.com/arthurmaciel/ipe-lang/commit/03e1179cec15029c34ccd114a143a61e4718b86f))
* **runtime,backend:** gate encoding codecs behind a feature (feature-split P2) + fix static allocator splice ([#524](https://github.com/arthurmaciel/ipe-lang/issues/524)) ([e4d1b95](https://github.com/arthurmaciel/ipe-lang/commit/e4d1b95c0633b9329aeeb49b4a7426fb937b3e4a))
* **runtime,backend:** gate regex/uuid/random behind features (feature-split P3) + fix http-only encoding under-inclusion ([#526](https://github.com/arthurmaciel/ipe-lang/issues/526)) ([f934987](https://github.com/arthurmaciel/ipe-lang/commit/f934987f989a0bd8dc62bc84e3ac2dcf2ac7ee5a))
* **runtime,backend:** gate rust_decimal + unicode-general-category so a bare Program drops them (feature-split P5) ([#536](https://github.com/arthurmaciel/ipe-lang/issues/536)) ([a35b0e6](https://github.com/arthurmaciel/ipe-lang/commit/a35b0e66d2cd72cfeff073120ff4a3d9fee19e9a))
* **runtime:** gate crypto_core behind crypto-core feature, secret behind secret (phase 6) ([#538](https://github.com/arthurmaciel/ipe-lang/issues/538)) ([59468bd](https://github.com/arthurmaciel/ipe-lang/commit/59468bd84fd094d717a4b14d1620b21410f4280f))
* **runtime:** String.toInt trims surrounding Unicode whitespace ([#530](https://github.com/arthurmaciel/ipe-lang/issues/530)) ([9ba9cdb](https://github.com/arthurmaciel/ipe-lang/commit/9ba9cdb5d20e009444d259b73efd9fe8e9706c1c))


### Bug Fixes

* **backend:** reorder Db.Decode.andThen args to the runtime's decoder-first shape ([#535](https://github.com/arthurmaciel/ipe-lang/issues/535)) ([432243a](https://github.com/arthurmaciel/ipe-lang/commit/432243adf26b7cd02162bb1d07666df31c7bf174))
* **parse:** distinct sub-spans per access-chain node to stop type-region collision ([#537](https://github.com/arthurmaciel/ipe-lang/issues/537)) ([f0392f7](https://github.com/arthurmaciel/ipe-lang/commit/f0392f7e7c0d5612d61c209b28c3f0c44e6e80d7))

## [0.1.33](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.32...ipe-v0.1.33) (2026-08-03)


### Features

* **backend:** runtime feature-map SSOT + feature-set closure SEAL (S3 P2) ([#508](https://github.com/arthurmaciel/ipe-lang/issues/508)) ([8634a60](https://github.com/arthurmaciel/ipe-lang/commit/8634a60d09d41288b35af675e95b50e601943314))
* **cli:** ipe doctor — environment diagnostics + consent-gated setup ([#512](https://github.com/arthurmaciel/ipe-lang/issues/512)) ([#519](https://github.com/arthurmaciel/ipe-lang/issues/519)) ([f73ee80](https://github.com/arthurmaciel/ipe-lang/commit/f73ee80a818c495f4e3c3b0c0ecab47d7d12f91c))
* **cli:** S3 P4+P5 — dep-model default emit, embed+materialize runtime, walk-up IPE_RUNTIME_DIR ([#517](https://github.com/arthurmaciel/ipe-lang/issues/517)) ([684d602](https://github.com/arthurmaciel/ipe-lang/commit/684d60274122b0d62c11337821c867c593e02611))
* **emit,runtime:** dependency-model native emit behind IPE_RUNTIME_DEP (S3 P3) ([#511](https://github.com/arthurmaciel/ipe-lang/issues/511)) ([9ed0c39](https://github.com/arthurmaciel/ipe-lang/commit/9ed0c395cfd66d7443b79cc6d92c7eb618f56f8a))
* goldens are byte-identical. ([4d3dc8b](https://github.com/arthurmaciel/ipe-lang/commit/4d3dc8b98f1716e22813496356d20524aff08b1f))
* **lower:** function-level dependency emission via IR reachability ([#509](https://github.com/arthurmaciel/ipe-lang/issues/509)) ([#520](https://github.com/arthurmaciel/ipe-lang/issues/520)) ([9c79f0e](https://github.com/arthurmaciel/ipe-lang/commit/9c79f0e527d446f37705c8216560e93e11e04986))


### Bug Fixes

* **runtime:** gate log's wasm browser-console path on the wasm-client feature ([#518](https://github.com/arthurmaciel/ipe-lang/issues/518)) ([1341f58](https://github.com/arthurmaciel/ipe-lang/commit/1341f58bed263d2d94207238a7c6249c061c8e39))

## [0.1.32](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.31...ipe-v0.1.32) (2026-08-02)


### Features

* **backend,runtime:** gate chrono-tz on uses_time (drop IANA zone DB from non-Time programs) ([#502](https://github.com/arthurmaciel/ipe-lang/issues/502)) ([58b2621](https://github.com/arthurmaciel/ipe-lang/commit/58b2621946427a4cf42ddc3de2c783e8ec6d1b7d))
* **backend,runtime:** synchronous fn main for pure programs — hello-world 53 crates ([#498](https://github.com/arthurmaciel/ipe-lang/issues/498)) ([9f8d4e6](https://github.com/arthurmaciel/ipe-lang/commit/9f8d4e6ada4e9781630bc8d783b8b22c7cfa596b))
* **backend:** gate the rsa crate off the always-on crypto_core floor ([#497](https://github.com/arthurmaciel/ipe-lang/issues/497)) ([b2fa817](https://github.com/arthurmaciel/ipe-lang/commit/b2fa81748fe79892c03184498f44cebe33b8bf79))
* **backend:** gate the url crate on uses_url so pure programs shed its idna/ICU4X subtree ([#495](https://github.com/arthurmaciel/ipe-lang/issues/495)) ([4d81da3](https://github.com/arthurmaciel/ipe-lang/commit/4d81da34b240cbe207430e5a78e885ab3331cb41))
* **playground:** add sandboxed jail-runner and wire /run to it ([#490](https://github.com/arthurmaciel/ipe-lang/issues/490)) ([ba9ebdc](https://github.com/arthurmaciel/ipe-lang/commit/ba9ebdcf4999d64878b5b005403d9835e2ab7ee1))
* **runtime:** crate feature-parity with emitted trimming (S3 precondition) ([#504](https://github.com/arthurmaciel/ipe-lang/issues/504)) ([1a0ceab](https://github.com/arthurmaciel/ipe-lang/commit/1a0ceabc37e6a97edd997587d20696f4d0165477))


### Bug Fixes

* **lower:** give a generic enum-payload type argument the Arc fn carrier ([#484](https://github.com/arthurmaciel/ipe-lang/issues/484)) ([#506](https://github.com/arthurmaciel/ipe-lang/issues/506)) ([59c6147](https://github.com/arthurmaciel/ipe-lang/commit/59c61473affaa63a02f691f4e0dc848d7612eca2))

## [0.1.31](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.30...ipe-v0.1.31) (2026-08-01)


### Features

* **backend:** gate csv crate behind Ipe.Csv usage ([#481](https://github.com/arthurmaciel/ipe-lang/issues/481)) ([9c6816f](https://github.com/arthurmaciel/ipe-lang/commit/9c6816f9b60213176dfca4e510d5d36f6cc6eab2))
* **backend:** gate flate2 + zstd behind Ipe.Compression usage ([#480](https://github.com/arthurmaciel/ipe-lang/issues/480)) ([89d8d59](https://github.com/arthurmaciel/ipe-lang/commit/89d8d593918e8ffb63e442f8a1e0f50aaa5e0e87))
* **backend:** gate heavy crypto on uses_crypto + jwt on uses_jwt||uses_auth ([#475](https://github.com/arthurmaciel/ipe-lang/issues/475) D-E) ([#489](https://github.com/arthurmaciel/ipe-lang/issues/489)) ([9377cbf](https://github.com/arthurmaciel/ipe-lang/commit/9377cbf3aa441dff66fc88aa73bc30789e67f969))
* **backend:** gate toml + serde_yaml behind Ipe.Config TOML/YAML decoder usage ([#478](https://github.com/arthurmaciel/ipe-lang/issues/478)) ([325f452](https://github.com/arthurmaciel/ipe-lang/commit/325f452f4c4b4070f159514b536052cdfd56c4d1))


### Bug Fixes

* **goldens:** align two stale run-oracles with sanctioned surface/semantics ([#487](https://github.com/arthurmaciel/ipe-lang/issues/487)) ([a83e3af](https://github.com/arthurmaciel/ipe-lang/commit/a83e3af7b543931440653d297861c38732aafc0b))
* **lower:** Arc-carrier a non-literal fn value into a user-enum payload ctor ([#486](https://github.com/arthurmaciel/ipe-lang/issues/486)) ([5f0c617](https://github.com/arthurmaciel/ipe-lang/commit/5f0c6177fc9de00b055e078d78f49be2ad97e919))

## [0.1.30](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.29...ipe-v0.1.30) (2026-07-31)


### Features

* **backend:** gate reqwest + http_client behind actual HTTP-client usage ([#466](https://github.com/arthurmaciel/ipe-lang/issues/466)) ([#474](https://github.com/arthurmaciel/ipe-lang/issues/474)) ([544566c](https://github.com/arthurmaciel/ipe-lang/commit/544566c30ad1bbded0dec71977025daef882fe4a))
* **cli:** human-friendly error when the Rust toolchain is missing ([#467](https://github.com/arthurmaciel/ipe-lang/issues/467)) ([#469](https://github.com/arthurmaciel/ipe-lang/issues/469)) ([c99aa0a](https://github.com/arthurmaciel/ipe-lang/commit/c99aa0a365bc2881f7e1ddf247dcb7e1d4f64ffe))
* **lower:** per-module fresh-name allocation seeding (byte-identical) ([#279](https://github.com/arthurmaciel/ipe-lang/issues/279)) ([#468](https://github.com/arthurmaciel/ipe-lang/issues/468)) ([a973a94](https://github.com/arthurmaciel/ipe-lang/commit/a973a940657bebce2cbb825086855282d60caed8))
* **playground:** replace build.sh with an Ipê build script and add an Ipê static server ([#477](https://github.com/arthurmaciel/ipe-lang/issues/477)) ([6639749](https://github.com/arthurmaciel/ipe-lang/commit/663974912b60d26e64f2dacf1b70ad5c97bb5a63))
* **playground:** sandboxed server build+run, relocated into examples/ ([#317](https://github.com/arthurmaciel/ipe-lang/issues/317), closes [#465](https://github.com/arthurmaciel/ipe-lang/issues/465)) ([#472](https://github.com/arthurmaciel/ipe-lang/issues/472)) ([a6a8a7c](https://github.com/arthurmaciel/ipe-lang/commit/a6a8a7cdbdbaa3e3e6dc0365655c582b74c990ed))
* **static:** aarch64 triple-aware C-compiler preflight + C-free CProfile axis ([#270](https://github.com/arthurmaciel/ipe-lang/issues/270)) ([#463](https://github.com/arthurmaciel/ipe-lang/issues/463)) ([8b4f81f](https://github.com/arthurmaciel/ipe-lang/commit/8b4f81f4a7c202dd2a94aada2d3a7a13bec8d841))


### Bug Fixes

* **sandbox:** gate the FreeBSD shell-quote helper off Windows so the Tier-2 build-jail crate compiles there ([#292](https://github.com/arthurmaciel/ipe-lang/issues/292)) ([#460](https://github.com/arthurmaciel/ipe-lang/issues/460)) ([ae52c01](https://github.com/arthurmaciel/ipe-lang/commit/ae52c0169f27a09f83a81b41b600e5046dd77558))
* serve .wasm browser-noise files as application/wasm ([#476](https://github.com/arthurmaciel/ipe-lang/issues/476)) ([5fde088](https://github.com/arthurmaciel/ipe-lang/commit/5fde088e213331eed8e2ca177208142ae859a786))

## [0.1.29](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.28...ipe-v0.1.29) (2026-07-31)


### Features

* **backend:** monomorphize direct-position Fn params to impl Fn ([#431](https://github.com/arthurmaciel/ipe-lang/issues/431)) ([#455](https://github.com/arthurmaciel/ipe-lang/issues/455)) ([7ec1040](https://github.com/arthurmaciel/ipe-lang/commit/7ec1040d598d841ef540dbc1c72f00de56f69289))
* **canon,diagnostics:** CustomElement JS-boundary reserved-type seal ([#333](https://github.com/arthurmaciel/ipe-lang/issues/333)) ([#443](https://github.com/arthurmaciel/ipe-lang/issues/443)) ([0007618](https://github.com/arthurmaciel/ipe-lang/commit/00076184ab3798c528b31d4e299c37e167ad8438))
* **ffi:** Rust.Ffi.call asserted-call — exact-carrier shims, ffi-raw capability, panic boundary ([#396](https://github.com/arthurmaciel/ipe-lang/issues/396)) ([#448](https://github.com/arthurmaciel/ipe-lang/issues/448)) ([745fbec](https://github.com/arthurmaciel/ipe-lang/commit/745fbec20051219c91c5fa87be44a4b4a36c898f))
* **http:** typed Url request target + fail-closed API-layer scheme narrowing ([#399](https://github.com/arthurmaciel/ipe-lang/issues/399)) ([#441](https://github.com/arthurmaciel/ipe-lang/issues/441)) ([83e21d5](https://github.com/arthurmaciel/ipe-lang/commit/83e21d5eac1e6bda821beb55de55f800a9aa6ac2))
* **index:** curated-index-repository side — schema, validator, admission CI ([#291](https://github.com/arthurmaciel/ipe-lang/issues/291)) ([#440](https://github.com/arthurmaciel/ipe-lang/issues/440)) ([7cfc21f](https://github.com/arthurmaciel/ipe-lang/commit/7cfc21f7bd76c24b8a41b8f2823f839b6e0dd77a))
* **io,runtime:** echo-suppressed password line read (Io.readSecret) ([#402](https://github.com/arthurmaciel/ipe-lang/issues/402)) ([#436](https://github.com/arthurmaciel/ipe-lang/issues/436)) ([b289601](https://github.com/arthurmaciel/ipe-lang/commit/b2896013e4cd51fc844714feb65937da434ef5db))
* **lower,backend,types:** first-class functions in enum variant payloads — Phase 2 carrier normalization ([#445](https://github.com/arthurmaciel/ipe-lang/issues/445)) ([103ece2](https://github.com/arthurmaciel/ipe-lang/commit/103ece2cdd70bc5081c0986479988c63a76a0d44))
* **lower:** first-class functions in record fields — Phase 1 carrier normalization ([#438](https://github.com/arthurmaciel/ipe-lang/issues/438)) ([ae1904d](https://github.com/arthurmaciel/ipe-lang/commit/ae1904d98bddd10844a0e9dec65861f41bfdd649))
* **runtime:** async FFI join-error funnel — no silently dropped panic payloads ([#396](https://github.com/arthurmaciel/ipe-lang/issues/396) async-breadth) ([#437](https://github.com/arthurmaciel/ipe-lang/issues/437)) ([01e23ab](https://github.com/arthurmaciel/ipe-lang/commit/01e23ab346965a5d807c74cd3f94bfc2d665d147))


### Bug Fixes

* **backend:** dedup libc dependency in emitted manifest for live/webview + readSecret shapes ([#446](https://github.com/arthurmaciel/ipe-lang/issues/446)) ([#449](https://github.com/arthurmaciel/ipe-lang/issues/449)) ([e5b93ac](https://github.com/arthurmaciel/ipe-lang/commit/e5b93ac519f325070e844e79a7591e22a646f962))
* **http:** resolve HttpMethod ADT surface as values, patterns, and methodToString ([#432](https://github.com/arthurmaciel/ipe-lang/issues/432)) ([#447](https://github.com/arthurmaciel/ipe-lang/issues/447)) ([d1f4549](https://github.com/arthurmaciel/ipe-lang/commit/d1f454980b6f2d5ff89b156c3cdb42712dec4cbb))
* **lower,backend:** erase Ipe.PubSub.Topic phantom uniformly across decl and CAF emit ([#457](https://github.com/arthurmaciel/ipe-lang/issues/457)) ([#458](https://github.com/arthurmaciel/ipe-lang/issues/458)) ([f480b42](https://github.com/arthurmaciel/ipe-lang/commit/f480b426aea0b41bb25ba3237f6097a924834074))
* **runtime:** disambiguate url crate from local Url newtype in ws_client ([#433](https://github.com/arthurmaciel/ipe-lang/issues/433)) ([#444](https://github.com/arthurmaciel/ipe-lang/issues/444)) ([d800c56](https://github.com/arthurmaciel/ipe-lang/commit/d800c5628eb8a0138a6ba9862698a53361347e00))
* **test:** add missing Ipe.Ui import to five onsubmit live_e2e fixtures ([#456](https://github.com/arthurmaciel/ipe-lang/issues/456)) ([f840ee7](https://github.com/arthurmaciel/ipe-lang/commit/f840ee7a2b2707ce42bea357aa0434d2595b2328))
* **test:** isolate g_http_live cargo-build tests from concurrent emit-dir wipes ([#454](https://github.com/arthurmaciel/ipe-lang/issues/454)) ([15fc3dc](https://github.com/arthurmaciel/ipe-lang/commit/15fc3dc733c92eb0caa54d4166ca27e005ce2faf))
* **test:** web routed-view golden returns Element per framework contract, not Html via Ui.layout ([#450](https://github.com/arthurmaciel/ipe-lang/issues/450)) ([#451](https://github.com/arthurmaciel/ipe-lang/issues/451)) ([d9308fa](https://github.com/arthurmaciel/ipe-lang/commit/d9308fa26879f2f8d084b3d90d9dc6ff16a0d274))

## [0.1.28](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.27...ipe-v0.1.28) (2026-07-31)


### Features

* **ffi:** define-transparency unification — all-identity-carrier define types surface as records/unions through the transparent-import glue ([#427](https://github.com/arthurmaciel/ipe-lang/issues/427)) ([55933a6](https://github.com/arthurmaciel/ipe-lang/commit/55933a69d38d68bfd08fb1334aef5300e9b3d2a3))
* **stdlib:** Ipe.Url.Parser routing patterns over the typed Url ([#399](https://github.com/arthurmaciel/ipe-lang/issues/399)) ([#425](https://github.com/arthurmaciel/ipe-lang/issues/425)) ([bcb132c](https://github.com/arthurmaciel/ipe-lang/commit/bcb132c558586ddcf1bd96110011cf1170382142))


### Bug Fixes

* **runtime,ui:** flow paragraph el children inline on the web backend ([#434](https://github.com/arthurmaciel/ipe-lang/issues/434)) ([3e724d3](https://github.com/arthurmaciel/ipe-lang/commit/3e724d3f7092bd297431d61c9bab8698690fbc6d))
* **stdlib:** drop the Ipe.Pure band-aid; arity-0 effect kernels take () directly ([#429](https://github.com/arthurmaciel/ipe-lang/issues/429)) ([54fbc88](https://github.com/arthurmaciel/ipe-lang/commit/54fbc88297c44932787e59a3babf24b3dd4f7cfa))

## [0.1.27](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.26...ipe-v0.1.27) (2026-07-31)


### Features

* **doc:** local-first module grouping + searchable soft-dark HTML site ([#418](https://github.com/arthurmaciel/ipe-lang/issues/418)) ([b7f2953](https://github.com/arthurmaciel/ipe-lang/commit/b7f2953cef4885ed4c730c74ec89e6ec5f6ddc56))
* **emit:** native formatter replaces the rustfmt subprocess — full byte-parity incl. or-patterns ([#278](https://github.com/arthurmaciel/ipe-lang/issues/278)) ([#415](https://github.com/arthurmaciel/ipe-lang/issues/415)) ([9de5efd](https://github.com/arthurmaciel/ipe-lang/commit/9de5efd2a742d90309cca691954eac6c76fd71fd))


### Bug Fixes

* **runtime/db:** Db.Decode int rejects out-of-range instead of saturating ([#420](https://github.com/arthurmaciel/ipe-lang/issues/420)) ([2f025d9](https://github.com/arthurmaciel/ipe-lang/commit/2f025d9786352f7314b376f2310588ff1604a1a4))
* **stdlib:** tail-recursive Result.combine / Maybe.combine ([#419](https://github.com/arthurmaciel/ipe-lang/issues/419)) ([0eafc48](https://github.com/arthurmaciel/ipe-lang/commit/0eafc48759f6608bc13c37c6957189b04aa077b7))

## [0.1.26](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.25...ipe-v0.1.26) (2026-07-31)


### Features

* **canon:** move renderStatic to shape-neutral Ipe.Html ([#323](https://github.com/arthurmaciel/ipe-lang/issues/323)) ([#404](https://github.com/arthurmaciel/ipe-lang/issues/404)) ([6e9fbca](https://github.com/arthurmaciel/ipe-lang/commit/6e9fbca1fab61531acd189ba4fcfecccc54bdd6e))
* **db:** typed SQL part 2 — mark the stringly row-read surface unsafe* ([#376](https://github.com/arthurmaciel/ipe-lang/issues/376)) ([#405](https://github.com/arthurmaciel/ipe-lang/issues/405)) ([9e8ef8f](https://github.com/arthurmaciel/ipe-lang/commit/9e8ef8fbdf329561a2ee6f9329f939c18bb44e78))
* **ffi:** panic-boundary + fail-closed getter classification ([#396](https://github.com/arthurmaciel/ipe-lang/issues/396) pkg 1) ([#407](https://github.com/arthurmaciel/ipe-lang/issues/407)) ([7cb01fc](https://github.com/arthurmaciel/ipe-lang/commit/7cb01fcc53e88ff3e26a189c4b41ba5b723b16b6))
* **ffi:** transparent-import decode side — inspector schema + classification + .ipei vocab ([#396](https://github.com/arthurmaciel/ipe-lang/issues/396)) ([#408](https://github.com/arthurmaciel/ipe-lang/issues/408)) ([d9d2bb3](https://github.com/arthurmaciel/ipe-lang/commit/d9d2bb37f8a042f4254aba8359ff372e3c36cb44))
* **ffi:** transparent-import write-side cutover — record/union surface + conversion glue ([#396](https://github.com/arthurmaciel/ipe-lang/issues/396)) ([#414](https://github.com/arthurmaciel/ipe-lang/issues/414)) ([2c11ec5](https://github.com/arthurmaciel/ipe-lang/commit/2c11ec5710adcedbec1c6fea0d74d79d51c4fdc3))
* **stdlib:** additive Elm coverage — Bitwise, Tuple, Random Generator ([#274](https://github.com/arthurmaciel/ipe-lang/issues/274)) ([#409](https://github.com/arthurmaciel/ipe-lang/issues/409)) ([795ee6f](https://github.com/arthurmaciel/ipe-lang/commit/795ee6fa942dd0406e2284feddb2559786b77d69))
* **stdlib:** route hand-written String/Basics through their kernels ([#271](https://github.com/arthurmaciel/ipe-lang/issues/271)) ([#401](https://github.com/arthurmaciel/ipe-lang/issues/401)) ([437df51](https://github.com/arthurmaciel/ipe-lang/commit/437df5166e5f89dbed68fe0db6cdf371f899bc96))
* **web:** onNavigate cfg field — URL navigation flows through update ([#393](https://github.com/arthurmaciel/ipe-lang/issues/393)) ([cefea5f](https://github.com/arthurmaciel/ipe-lang/commit/cefea5f8f65a9001cbebefe0d6cffdccab4af0b5))


### Bug Fixes

* **cli:** resolve project-root entry for capabilities and --emit-ir; friendlier check/explain defaults ([#411](https://github.com/arthurmaciel/ipe-lang/issues/411)) ([df699b1](https://github.com/arthurmaciel/ipe-lang/commit/df699b1bf48bc3b63dc33c47816157d16a6f24eb))
* **ssrf:** correct stale module doc — guard is production-gated, not opt-in ([#403](https://github.com/arthurmaciel/ipe-lang/issues/403)) ([65e2258](https://github.com/arthurmaciel/ipe-lang/commit/65e22588058e0ed8b182c36a484b4e44ef0f872a))

## [0.1.25](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.24...ipe-v0.1.25) (2026-07-30)


### Features

* **audit:** Windows Tier-2 native .ps1 probe wrapper — promote windows-x64 to a certifying platform ([#260](https://github.com/arthurmaciel/ipe-lang/issues/260)) ([#386](https://github.com/arthurmaciel/ipe-lang/issues/386)) ([dd94474](https://github.com/arthurmaciel/ipe-lang/commit/dd9447483dbecfb836ffb1236f9604265196799b))
* **canon,lsp:** shape-scoped Cmd/Sub + IPE-N0035 cross-shape gate + Web PubSub doc ([#302](https://github.com/arthurmaciel/ipe-lang/issues/302), [#303](https://github.com/arthurmaciel/ipe-lang/issues/303)) ([#331](https://github.com/arthurmaciel/ipe-lang/issues/331)) ([1646bb8](https://github.com/arthurmaciel/ipe-lang/commit/1646bb831df37dca448341103b1f0b4728d8e186))
* **cli:** infer --target wasm from [wasm].mode in ipe.toml ([#320](https://github.com/arthurmaciel/ipe-lang/issues/320)) ([#366](https://github.com/arthurmaciel/ipe-lang/issues/366)) ([b2bbfc9](https://github.com/arthurmaciel/ipe-lang/commit/b2bbfc9f02042ac8f4baf54e03cf066e59777fe7))
* **cli:** ipe verify — one-command project gate (fmt + type-check + build) ([#301](https://github.com/arthurmaciel/ipe-lang/issues/301)) ([#361](https://github.com/arthurmaciel/ipe-lang/issues/361)) ([9ce9b2a](https://github.com/arthurmaciel/ipe-lang/commit/9ce9b2aa70194b510c70ef104f75ddd1468eed83))
* **db:** mark the raw-SQL escape hatch — Db.execRaw → Db.unsafeExecRaw ([#339](https://github.com/arthurmaciel/ipe-lang/issues/339)) ([#377](https://github.com/arthurmaciel/ipe-lang/issues/377)) ([b4e9f8f](https://github.com/arthurmaciel/ipe-lang/commit/b4e9f8f62fe3fd79a71b110c62b1dfd783bfefb4))
* **doc:** always include stdlib; add --list and &lt;module&gt; query ([#325](https://github.com/arthurmaciel/ipe-lang/issues/325)) ([#370](https://github.com/arthurmaciel/ipe-lang/issues/370)) ([82e5a76](https://github.com/arthurmaciel/ipe-lang/commit/82e5a76eb94a1efff7b7a985ad665d1d38208d83))
* **http:** HttpMethod ADT replaces stringly Http.method ([#343](https://github.com/arthurmaciel/ipe-lang/issues/343)) ([#364](https://github.com/arthurmaciel/ipe-lang/issues/364)) ([6b5874b](https://github.com/arthurmaciel/ipe-lang/commit/6b5874b06aaf728cdb2973b787e800615a30cccc))
* **lexer,canon:** path "…" literal sugar for typed Path ([#358](https://github.com/arthurmaciel/ipe-lang/issues/358)) ([#373](https://github.com/arthurmaciel/ipe-lang/issues/373)) ([0b8d23b](https://github.com/arthurmaciel/ipe-lang/commit/0b8d23b98528862ffd7ad435e33f31a112791028))
* **runtime:** Windows-aware Path.clean; drop cfg(windows) compile_error ([#359](https://github.com/arthurmaciel/ipe-lang/issues/359)) ([#368](https://github.com/arthurmaciel/ipe-lang/issues/368)) ([2609a98](https://github.com/arthurmaciel/ipe-lang/commit/2609a988b73dec8bb7fbf28aae45b7158676f22e))
* **stdlib,types:** typed pub/sub Topic a payload contract ([#340](https://github.com/arthurmaciel/ipe-lang/issues/340)) [salvaged] ([#372](https://github.com/arthurmaciel/ipe-lang/issues/372)) ([e6ade1e](https://github.com/arthurmaciel/ipe-lang/commit/e6ade1ebde6d15f9c2e28d13f179746a1b0fa625))
* **stdlib:** compiled Regex type + Regex.compile — invalid patterns are typed Err ([#341](https://github.com/arthurmaciel/ipe-lang/issues/341)) ([#360](https://github.com/arthurmaciel/ipe-lang/issues/360)) ([c684294](https://github.com/arthurmaciel/ipe-lang/commit/c6842945a02562779967e29ecf2459e34a0a281f))
* **stdlib:** Ipe.Markdown — markdown → Ui.Element renderer ([#321](https://github.com/arthurmaciel/ipe-lang/issues/321)) ([#380](https://github.com/arthurmaciel/ipe-lang/issues/380)) ([d500806](https://github.com/arthurmaciel/ipe-lang/commit/d500806541ac0b2919e5205883a449db302fb450))
* **stdlib:** locale-correct case mapping — Locale + String.toUpperIn/toLowerIn (ICU4X) ([#277](https://github.com/arthurmaciel/ipe-lang/issues/277)) ([#388](https://github.com/arthurmaciel/ipe-lang/issues/388)) ([99872dc](https://github.com/arthurmaciel/ipe-lang/commit/99872dce561bea7ffe09992fec0d965f9247b908))
* **stdlib:** typed Ipe.Url (parse-don't-validate) + injection-safe query builder ([#347](https://github.com/arthurmaciel/ipe-lang/issues/347)) ([#383](https://github.com/arthurmaciel/ipe-lang/issues/383)) ([d455011](https://github.com/arthurmaciel/ipe-lang/commit/d455011a131a1689ba5e29ded6921d0e435437bb))
* **stdlib:** typed Path (parse-don't-validate) + Ipe.File migration ([#334](https://github.com/arthurmaciel/ipe-lang/issues/334)) ([#357](https://github.com/arthurmaciel/ipe-lang/issues/357)) ([438f95c](https://github.com/arthurmaciel/ipe-lang/commit/438f95cdf959b53f81d326136d71f1a8d118f093))
* **stdlib:** typed security newtypes — Crypto Key/Mac, Email EmailAddress ([#344](https://github.com/arthurmaciel/ipe-lang/issues/344)) ([#367](https://github.com/arthurmaciel/ipe-lang/issues/367)) ([a772025](https://github.com/arthurmaciel/ipe-lang/commit/a7720256edf62bdd35f81657b2f1469f78cb22c3))
* **surface:** drop Task.run + Task.perform from the Ipê surface ([#282](https://github.com/arthurmaciel/ipe-lang/issues/282)) ([#389](https://github.com/arthurmaciel/ipe-lang/issues/389)) ([e727ad7](https://github.com/arthurmaciel/ipe-lang/commit/e727ad75cac70dd2c64a02af5d24398a4f757b24))
* **types:** closed-union case refuses catch-all arms — IPE-T0018 fail-closed ([#276](https://github.com/arthurmaciel/ipe-lang/issues/276)) ([#392](https://github.com/arthurmaciel/ipe-lang/issues/392)) ([480433e](https://github.com/arthurmaciel/ipe-lang/commit/480433e72aa80bf8c2b4a4763ee2327987a70689))
* **types:** exhaustiveness-aware wildcard warning IPE-T0018 ([#272](https://github.com/arthurmaciel/ipe-lang/issues/272)) ([#379](https://github.com/arthurmaciel/ipe-lang/issues/379)) ([b9f8d55](https://github.com/arthurmaciel/ipe-lang/commit/b9f8d5527b89b94836c34745eee8f330fb8b1f72))
* **verify:** wire the test stage (Ipe.Test runner) ([#390](https://github.com/arthurmaciel/ipe-lang/issues/390)) ([11201b2](https://github.com/arthurmaciel/ipe-lang/commit/11201b2ca98c3dbaa3eba985cfc15f609e107d25))
* **wasm:** client-side router for the WasmClient shape ([#268](https://github.com/arthurmaciel/ipe-lang/issues/268)) ([#391](https://github.com/arthurmaciel/ipe-lang/issues/391)) ([fb5d165](https://github.com/arthurmaciel/ipe-lang/commit/fb5d165ca2294f1e4983ba710305d4a1de9fa8ba))


### Bug Fixes

* **bytes:** migrate Email/attachment byte pipeline to the typed Bytes carrier ([#275](https://github.com/arthurmaciel/ipe-lang/issues/275)) ([#387](https://github.com/arthurmaciel/ipe-lang/issues/387)) ([4312307](https://github.com/arthurmaciel/ipe-lang/commit/43123076a2a7fb75c4d5add66ec24f1046ca5d5e))
* **cli:** box the CliError::Pipeline diagnostic to shrink the driver error ([#332](https://github.com/arthurmaciel/ipe-lang/issues/332)) ([#350](https://github.com/arthurmaciel/ipe-lang/issues/350)) ([cf8add1](https://github.com/arthurmaciel/ipe-lang/commit/cf8add1fba019ef2d770ded12d6e9645167de254))
* **cli:** ipe upgrade no-prebuilt-binary is a typed error, never shows help ([#351](https://github.com/arthurmaciel/ipe-lang/issues/351)) ([#365](https://github.com/arthurmaciel/ipe-lang/issues/365)) ([6d11ea5](https://github.com/arthurmaciel/ipe-lang/commit/6d11ea503fe40884bf086a55ac00589b991f660a))
* **cli:** route all human-facing prose through style::gutter — closes [#354](https://github.com/arthurmaciel/ipe-lang/issues/354) ([#374](https://github.com/arthurmaciel/ipe-lang/issues/374)) ([2314b5f](https://github.com/arthurmaciel/ipe-lang/commit/2314b5f827d2a4094f636b50f78efdd6ee5a3810))
* **diagnostics:** ipe check caret parity with build + capped/collapsed 'did you mean' ([#355](https://github.com/arthurmaciel/ipe-lang/issues/355)) ([#356](https://github.com/arthurmaciel/ipe-lang/issues/356)) ([333dac8](https://github.com/arthurmaciel/ipe-lang/commit/333dac8de51da4de06a9ccbaab287e0bcff0cf50))
* **html:** close the raw-String HTML/script injection hole — Html.raw→unsafeRaw, Head.jsonLd→unsafeJsonLd ([#338](https://github.com/arthurmaciel/ipe-lang/issues/338)) ([#378](https://github.com/arthurmaciel/ipe-lang/issues/378)) ([c5a0181](https://github.com/arthurmaciel/ipe-lang/commit/c5a01812b8c82f3fac1dd398c04e4350cf292181))
* **install:** success + report-bugs lines at the 2-space banner/GUTTER indent ([#353](https://github.com/arthurmaciel/ipe-lang/issues/353)) ([6d74342](https://github.com/arthurmaciel/ipe-lang/commit/6d743420f72e95f0af4b10d6b589d65e1ffffb38))
* **path:** harden escapes_root — reject any leading all-dots (&gt;=2) element ([#384](https://github.com/arthurmaciel/ipe-lang/issues/384)) ([cc8ed1d](https://github.com/arthurmaciel/ipe-lang/commit/cc8ed1dac710cbde3b1013c403368d57fe2b67e3))
* **stdlib:** Money.parseCurrency returns Maybe Currency (kill silent CurrencyRaw default) ([#363](https://github.com/arthurmaciel/ipe-lang/issues/363)) ([fd77fd5](https://github.com/arthurmaciel/ipe-lang/commit/fd77fd5424c4ed06cf1c8327b87b3cacad2c3875))
* **test:** make doc-serve test robust to the framed announce line ([#375](https://github.com/arthurmaciel/ipe-lang/issues/375)) ([2412bed](https://github.com/arthurmaciel/ipe-lang/commit/2412bed2177358f6d3000ae835ff712896c02b67))
* **web:** SSE reconnect reconciles page with connection URL ([#385](https://github.com/arthurmaciel/ipe-lang/issues/385)) ([0b45851](https://github.com/arthurmaciel/ipe-lang/commit/0b45851882b49cccaedcf52b7b1a623d621568d6))

## [0.1.24](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.23...ipe-v0.1.24) (2026-07-30)


### Features

* **cli:** add `ipe check` — type-check a project without build or run ([#346](https://github.com/arthurmaciel/ipe-lang/issues/346)) ([2a1010e](https://github.com/arthurmaciel/ipe-lang/commit/2a1010e2e100eb39712d3564c883a6a76ab29d3d))
* **lexer,canon:** strip source indentation margin from triple-quoted strings via anchor column ([#324](https://github.com/arthurmaciel/ipe-lang/issues/324)) ([70346bb](https://github.com/arthurmaciel/ipe-lang/commit/70346bb45ecab1004253655f37bf8f2c4b03affe))
* **stdlib:** Ipe.Process.run — no-shell subprocess execution, WasmClient-denied ([#316](https://github.com/arthurmaciel/ipe-lang/issues/316)) ([#336](https://github.com/arthurmaciel/ipe-lang/issues/336)) ([89198e5](https://github.com/arthurmaciel/ipe-lang/commit/89198e50548f410a71e67cf2c25b3f59e3c27287))

## [0.1.23](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.22...ipe-v0.1.23) (2026-07-30)


### Features

* **audit:** promote Tier-2 native certification to FreeBSD; keep Windows deferred ([#149](https://github.com/arthurmaciel/ipe-lang/issues/149)) ([#261](https://github.com/arthurmaciel/ipe-lang/issues/261)) ([89fd217](https://github.com/arthurmaciel/ipe-lang/commit/89fd2176c2eb0b40513af59e18015afe25a217a5))
* **error:** Ipe.Error inspector kernels + Ipe.Test.expectErr/kindName ([#288](https://github.com/arthurmaciel/ipe-lang/issues/288)) ([#309](https://github.com/arthurmaciel/ipe-lang/issues/309)) ([58fe06e](https://github.com/arthurmaciel/ipe-lang/commit/58fe06e1416cac40a70aeb97ad687e159f693131))
* **shapes:** consolidate Tui+Console into Terminal + Ui.cells escape node ([#296](https://github.com/arthurmaciel/ipe-lang/issues/296)) ([d6eb635](https://github.com/arthurmaciel/ipe-lang/commit/d6eb635dc215222ecfc951b5e18f7d93ca58a2f9))


### Bug Fixes

* **backend:** emit top-level nullary bindings as evaluate-once shared values ([#315](https://github.com/arthurmaciel/ipe-lang/issues/315)) ([139922b](https://github.com/arthurmaciel/ipe-lang/commit/139922b351370a80329f744de4c67b91a95a1337))
* **canon:** make reachable stdlib member imply backing kernel by construction ([#286](https://github.com/arthurmaciel/ipe-lang/issues/286)) ([#306](https://github.com/arthurmaciel/ipe-lang/issues/306)) ([5c3e961](https://github.com/arthurmaciel/ipe-lang/commit/5c3e96108ea7f5b18c4ead783728b9a230a50e1e))
* **ci:** green main — compare builtin, sky-transform round-trip, panic-scan gate ([#304](https://github.com/arthurmaciel/ipe-lang/issues/304)) ([0bcc874](https://github.com/arthurmaciel/ipe-lang/commit/0bcc874db6405d084872641e1e1806bfe30b8c17))
* **ci:** migrate Tier-C-broken examples + remove sky-parity job ([#262](https://github.com/arthurmaciel/ipe-lang/issues/262)) ([922ace3](https://github.com/arthurmaciel/ipe-lang/commit/922ace347fcd8d96809bf16895e35a65e91ed5f8))
* **ci:** migrate Tier-C-broken examples + remove sky-parity job ([#264](https://github.com/arthurmaciel/ipe-lang/issues/264)) ([6230e9f](https://github.com/arthurmaciel/ipe-lang/commit/6230e9f66905b5ad2456a75d5fb09a67b33db6e6))
* **cli:** route ipe analysis surfaces through the injection-aware source graph ([#310](https://github.com/arthurmaciel/ipe-lang/issues/310)) ([#313](https://github.com/arthurmaciel/ipe-lang/issues/313)) ([463baa9](https://github.com/arthurmaciel/ipe-lang/commit/463baa917139d91d5cca57da6b124693d069de27))
* **json:** strict integer decoder + Elm behaviour verdict ledger ([#293](https://github.com/arthurmaciel/ipe-lang/issues/293)) ([#308](https://github.com/arthurmaciel/ipe-lang/issues/308)) ([f279bbe](https://github.com/arthurmaciel/ipe-lang/commit/f279bbe7d6d3d7a231623cd89615c8eb59d397a5))

## [0.1.22](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.21...ipe-v0.1.22) (2026-07-29)


### Features

* **canon:** Prelude→Basics + three-tier auto-import ([#231](https://github.com/arthurmaciel/ipe-lang/issues/231)) ([#244](https://github.com/arthurmaciel/ipe-lang/issues/244)) ([cdd2414](https://github.com/arthurmaciel/ipe-lang/commit/cdd241481dc89e1a8c54a3a07fde7cce34b9a8a1))
* **lsp:** add-import quick-fix for the IPE-N0034 must-import diagnostic ([#242](https://github.com/arthurmaciel/ipe-lang/issues/242)) ([#258](https://github.com/arthurmaciel/ipe-lang/issues/258)) ([9853a7c](https://github.com/arthurmaciel/ipe-lang/commit/9853a7cb82b200e40167824785c75f2696da6702))
* **pubsub:** activate top-level Ipe.PubSub Task surface + relocate TEA-side under Ipe.Tea.Web.PubSub ([#235](https://github.com/arthurmaciel/ipe-lang/issues/235) Stage 3) ([#252](https://github.com/arthurmaciel/ipe-lang/issues/252)) ([4515bc0](https://github.com/arthurmaciel/ipe-lang/commit/4515bc06e46e58498f7ab05973c9b8aa278cd15e))
* **resolve:** enforce Tier-C explicit-import per ADR 0047 ([#243](https://github.com/arthurmaciel/ipe-lang/issues/243)) ([#256](https://github.com/arthurmaciel/ipe-lang/issues/256)) ([e5e7760](https://github.com/arthurmaciel/ipe-lang/commit/e5e77607a0d335fdf665ce45bb9ad99f2735bc07))
* **sandbox:** Windows + FreeBSD returning build-jail arms ([#228](https://github.com/arthurmaciel/ipe-lang/issues/228), impl of ADR 0051) ([#253](https://github.com/arthurmaciel/ipe-lang/issues/253)) ([971906c](https://github.com/arthurmaciel/ipe-lang/commit/971906ca0cb6bac94e25ac910cdb14bc3a2b8a18))
* **shapes:** relocate TEA shapes under Ipe.Tea.&lt;Shape&gt; + Program gate + scaffold/guard ([#235](https://github.com/arthurmaciel/ipe-lang/issues/235) Stage 1, closes [#238](https://github.com/arthurmaciel/ipe-lang/issues/238)) ([#248](https://github.com/arthurmaciel/ipe-lang/issues/248)) ([a7b36fd](https://github.com/arthurmaciel/ipe-lang/commit/a7b36fd134949b5f0905444d8a1ec7763717b2e3))
* **shapes:** unify Web/WebView view on Element + Web.appHtml raw-Html escape ([#235](https://github.com/arthurmaciel/ipe-lang/issues/235) Stage 2) ([#250](https://github.com/arthurmaciel/ipe-lang/issues/250)) ([588ad72](https://github.com/arthurmaciel/ipe-lang/commit/588ad728cbb0481c1e36c97ae1a6dadf7e55871b))


### Bug Fixes

* **sandbox:** losslessly lower FreeBSD jail command= + correct shell-free claim ([#254](https://github.com/arthurmaciel/ipe-lang/issues/254)) ([#259](https://github.com/arthurmaciel/ipe-lang/issues/259)) ([c3ab280](https://github.com/arthurmaciel/ipe-lang/commit/c3ab28078b3448a394bd5e8acefe282735ca8763))
* **wasm:** hydrate glue references the real emitted record-alias type name ([#224](https://github.com/arthurmaciel/ipe-lang/issues/224)) ([#234](https://github.com/arthurmaciel/ipe-lang/issues/234)) ([4c256de](https://github.com/arthurmaciel/ipe-lang/commit/4c256de119d4eb47b89f6eaa1caaf53d460efed0))

## [0.1.21](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.20...ipe-v0.1.21) (2026-07-28)


### Features

* **audit:** macOS Tier-2 native enforcement ([#149](https://github.com/arthurmaciel/ipe-lang/issues/149) sub-PR 4) ([#196](https://github.com/arthurmaciel/ipe-lang/issues/196)) ([a97d8ee](https://github.com/arthurmaciel/ipe-lang/commit/a97d8ee6cd9eb179a32eeaacfe3915f407d6f7d1))
* **audit:** Tier-2 exercise harness — Tier-2 now certifies native packages on Linux ([#149](https://github.com/arthurmaciel/ipe-lang/issues/149) sub-PR 3) ([#193](https://github.com/arthurmaciel/ipe-lang/issues/193)) ([ebd579e](https://github.com/arthurmaciel/ipe-lang/commit/ebd579e54c5ddb3a9c690853db39df8c20f4f41e))
* **audit:** Tier-2 native differential-confinement reconciler + fail-closed gate ([#149](https://github.com/arthurmaciel/ipe-lang/issues/149) sub-PR 2) ([#192](https://github.com/arthurmaciel/ipe-lang/issues/192)) ([5bcac8c](https://github.com/arthurmaciel/ipe-lang/commit/5bcac8c8a24f797a5ae6739e6681bd3dbf85cd6b))
* **ci:** harden clippy gate to pedantic/correctness/style/complexity ([#167](https://github.com/arthurmaciel/ipe-lang/issues/167)) ([206b5d0](https://github.com/arthurmaciel/ipe-lang/commit/206b5d0665ac128dbdf0f33bf1001383d781fc24))
* **cli:** headless PR-open for ipe package publish ([#171](https://github.com/arthurmaciel/ipe-lang/issues/171)) ([#175](https://github.com/arthurmaciel/ipe-lang/issues/175)) ([4eca539](https://github.com/arthurmaciel/ipe-lang/commit/4eca539d40ed3582235531fbca3de969441ee77a))
* **cli:** ipe doc — API documentation generation ([#141](https://github.com/arthurmaciel/ipe-lang/issues/141)) ([#223](https://github.com/arthurmaciel/ipe-lang/issues/223)) ([ac5c1e4](https://github.com/arthurmaciel/ipe-lang/commit/ac5c1e4386c22b84a9d87b444a96fb92912a5658))
* **cli:** ipe doc — HTML site, cross-reference linking, serve ([#222](https://github.com/arthurmaciel/ipe-lang/issues/222)) ([#225](https://github.com/arthurmaciel/ipe-lang/issues/225)) ([dc312c9](https://github.com/arthurmaciel/ipe-lang/commit/dc312c9da2775ba35b2a8e843edfa3ef635f8c0a))
* **cli:** ipe login — GitHub device-code OAuth for a publish token ([#138](https://github.com/arthurmaciel/ipe-lang/issues/138)) ([#170](https://github.com/arthurmaciel/ipe-lang/issues/170)) ([0672c1d](https://github.com/arthurmaciel/ipe-lang/commit/0672c1d15625a31eae277c9b4b5f42d5bb2608a8))
* **examples:** network-only Sky mirror with committed trees + anchored edits ([#181](https://github.com/arthurmaciel/ipe-lang/issues/181)) ([6831ad6](https://github.com/arthurmaciel/ipe-lang/commit/6831ad6059b67209986b57a1eca98cd7a6ac86bd))
* **lower,backend:** function-value reuse for contained record-of-functions ([#178](https://github.com/arthurmaciel/ipe-lang/issues/178)) ([#185](https://github.com/arthurmaciel/ipe-lang/issues/185)) ([fe1d6f0](https://github.com/arthurmaciel/ipe-lang/commit/fe1d6f0cbb01616fc38d21f52c5c93074b29cd2c))
* **parse:** `do` and `doParallel` notation ([#199](https://github.com/arthurmaciel/ipe-lang/issues/199)) ([659e4ed](https://github.com/arthurmaciel/ipe-lang/commit/659e4ed8b4b7962304b6f1ad7d4f745eee2e0fcc))
* **parse:** the `>>` / `<<` function-composition operators ([#177](https://github.com/arthurmaciel/ipe-lang/issues/177)) ([#183](https://github.com/arthurmaciel/ipe-lang/issues/183)) ([0b15f88](https://github.com/arthurmaciel/ipe-lang/commit/0b15f88f0678f6498e85d50aeed50103f733061b))
* **patterns:** or-patterns (| alternatives) in case…of ([#214](https://github.com/arthurmaciel/ipe-lang/issues/214)) ([#233](https://github.com/arthurmaciel/ipe-lang/issues/233)) ([3011fd2](https://github.com/arthurmaciel/ipe-lang/commit/3011fd261ed7aa3ebd365090704d5a557589063b))
* **sandbox:** macOS run-jail SBPL arm → JailForTarget::Holds on macOS ([#198](https://github.com/arthurmaciel/ipe-lang/issues/198)) ([#212](https://github.com/arthurmaciel/ipe-lang/issues/212)) ([6349f77](https://github.com/arthurmaciel/ipe-lang/commit/6349f77c6bd71440532b7d55d9338b60368fb203))
* **sandbox:** Tier-2 audit — build-jail outcome primitive + design ([#149](https://github.com/arthurmaciel/ipe-lang/issues/149) sub-PR 1) ([#191](https://github.com/arthurmaciel/ipe-lang/issues/191)) ([045b43b](https://github.com/arthurmaciel/ipe-lang/commit/045b43bba6c5b1762a9fef448950e7cb9097d60e))
* **sandbox:** Windows runtime run-jail arm (partial per-axis confinement) ([#215](https://github.com/arthurmaciel/ipe-lang/issues/215)) ([#220](https://github.com/arthurmaciel/ipe-lang/issues/220)) ([1a1094c](https://github.com/arthurmaciel/ipe-lang/commit/1a1094ce18e4be2817c8baecea4bbca3ecaa7d3c))
* **stdlib:** Io.println/eprintln kernels + dev-only Debug.log, remove Log.println ([#207](https://github.com/arthurmaciel/ipe-lang/issues/207)) ([957da73](https://github.com/arthurmaciel/ipe-lang/commit/957da73a67fab3f583143636862903a34f5b77fd))
* **tooling:** regen-goldens tool + decouple emit template from golden fixture ([#206](https://github.com/arthurmaciel/ipe-lang/issues/206)) ([7a50d87](https://github.com/arthurmaciel/ipe-lang/commit/7a50d87e19751d56062294d4cb13072c054f6ec1))


### Bug Fixes

* **audit:** honest surface — Tier-2 certifies linux-x64 AND macos-arm64 ([#149](https://github.com/arthurmaciel/ipe-lang/issues/149)) ([#229](https://github.com/arthurmaciel/ipe-lang/issues/229)) ([064add5](https://github.com/arthurmaciel/ipe-lang/commit/064add5e27cb065a2c0095557e8ff85f5b72d0db))
* **ci:** ASCII-only PowerShell in the Windows admission-sandbox skip step ([#189](https://github.com/arthurmaciel/ipe-lang/issues/189)) ([b7dadc7](https://github.com/arthurmaciel/ipe-lang/commit/b7dadc7558fcaf7634404a989dfed9f50f013630))
* **ci:** repoint static.yml + fuzz to relocated example homes (post-[#188](https://github.com/arthurmaciel/ipe-lang/issues/188)) ([#194](https://github.com/arthurmaciel/ipe-lang/issues/194)) ([768f1c4](https://github.com/arthurmaciel/ipe-lang/commit/768f1c409842a38930ca8800364636ef69c6cb64))
* **cli:** inject the compiled-source stdlib closure in capability inference ([#169](https://github.com/arthurmaciel/ipe-lang/issues/169)) ([#176](https://github.com/arthurmaciel/ipe-lang/issues/176)) ([7cb173b](https://github.com/arthurmaciel/ipe-lang/commit/7cb173b5ed5a8f7dd68446feef0cc5d971893c70))
* **examples:** wasm-* build — Ipe.Live→Ipe.Web + wasm-safe async, add to sweep ([#209](https://github.com/arthurmaciel/ipe-lang/issues/209)) ([#227](https://github.com/arthurmaciel/ipe-lang/issues/227)) ([e840919](https://github.com/arthurmaciel/ipe-lang/commit/e8409198ded0b673e63425d3f2acf9497875e3b1))
* **resolve:** exclude hidden dirs from the package content hash ([#201](https://github.com/arthurmaciel/ipe-lang/issues/201)) ([25734c1](https://github.com/arthurmaciel/ipe-lang/commit/25734c147a7dab22ec39be9c22d58e32f53c902a))
* **sweep:** honest cli exit-code gate + self-explanatory HS256 error ([#182](https://github.com/arthurmaciel/ipe-lang/issues/182)) ([b49098a](https://github.com/arthurmaciel/ipe-lang/commit/b49098a387db3b46b79774ee6b55f589f6fe010d))

## [0.1.20](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.19...ipe-v0.1.20) (2026-07-26)


### Features

* **cli:** wire ipe package publish live submit (fork push + prefilled PR) ([#165](https://github.com/arthurmaciel/ipe-lang/issues/165)) ([329bf27](https://github.com/arthurmaciel/ipe-lang/commit/329bf270a9f6fb0c021c762b665d1c901eae8a56)), closes [#137](https://github.com/arthurmaciel/ipe-lang/issues/137) [#152](https://github.com/arthurmaciel/ipe-lang/issues/152)


### Bug Fixes

* **cli:** surface the real diagnostic when package capability inference finds nothing lowerable ([#168](https://github.com/arthurmaciel/ipe-lang/issues/168)) ([0bf550c](https://github.com/arthurmaciel/ipe-lang/commit/0bf550c2cc627804b3fc90cd7d1f0c91e248930a)), closes [#159](https://github.com/arthurmaciel/ipe-lang/issues/159)

## [0.1.19](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.18...ipe-v0.1.19) (2026-07-26)


### Features

* **cli:** apply 2-space gutter + frame to all human-facing output ([#164](https://github.com/arthurmaciel/ipe-lang/issues/164)) ([5956c10](https://github.com/arthurmaciel/ipe-lang/commit/5956c107e4bcea26f07be381092ae70264ca8cc3))
* **cli:** distribute AGENTS.md — ipe init writes it + ipe upgrade-agents refreshes it ([#146](https://github.com/arthurmaciel/ipe-lang/issues/146)) ([#158](https://github.com/arthurmaciel/ipe-lang/issues/158)) ([15d2096](https://github.com/arthurmaciel/ipe-lang/commit/15d20968fffc4863b2dda2cee0919711049a2126))
* **cli:** frame + gutter human output uniformly (part of [#148](https://github.com/arthurmaciel/ipe-lang/issues/148)) ([#153](https://github.com/arthurmaciel/ipe-lang/issues/153)) ([474cd59](https://github.com/arthurmaciel/ipe-lang/commit/474cd5985589f8c748eb95f802bf6559e973be2e))
* **cli:** ipe package publish — compute the index entry and open the index PR ([#151](https://github.com/arthurmaciel/ipe-lang/issues/151)) ([373455e](https://github.com/arthurmaciel/ipe-lang/commit/373455e8770dddedd621506319d18add610e42da))
* **cli:** ipe upgrade — self-update via the release installer ([#145](https://github.com/arthurmaciel/ipe-lang/issues/145)) ([#161](https://github.com/arthurmaciel/ipe-lang/issues/161)) ([cba4090](https://github.com/arthurmaciel/ipe-lang/commit/cba4090ac18ce955539e29ec639465431703cea5))
* **cli:** show human-friendly build progress ([#143](https://github.com/arthurmaciel/ipe-lang/issues/143)) ([#160](https://github.com/arthurmaciel/ipe-lang/issues/160)) ([d06705f](https://github.com/arthurmaciel/ipe-lang/commit/d06705ff01f518379d332fd0e5c5d0c8f912470c))
* **cli:** suggest the nearest command when one is mistyped ([#147](https://github.com/arthurmaciel/ipe-lang/issues/147)) ([#162](https://github.com/arthurmaciel/ipe-lang/issues/162)) ([3c1326c](https://github.com/arthurmaciel/ipe-lang/commit/3c1326cc0e8a711f95fd70005b950c6fb560250a))


### Bug Fixes

* **backend:** skip the rustfmt normalization pass when rustfmt is absent ([#156](https://github.com/arthurmaciel/ipe-lang/issues/156)) ([ab384ca](https://github.com/arthurmaciel/ipe-lang/commit/ab384cad3f105caa660991d9cca20da3a0e03d5d))

## [0.1.18](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.17...ipe-v0.1.18) (2026-07-26)


### Features

* **install:** add binary availability check and cargo detection ([7c9147f](https://github.com/arthurmaciel/ipe-lang/commit/7c9147f137830a7916263f2ffbd72fd91509c6f2))
* polish install.sh — +2sp indent, ~/.cargo/env detection, reword bugs line ([#136](https://github.com/arthurmaciel/ipe-lang/issues/136)) ([6fb3e7a](https://github.com/arthurmaciel/ipe-lang/commit/6fb3e7a1d308615dd7b365e6894524264247b553))
* **sandbox:** scope the runtime jail to native-bearing programs (ADR 0040) ([#101](https://github.com/arthurmaciel/ipe-lang/issues/101)) ([9a12f23](https://github.com/arthurmaciel/ipe-lang/commit/9a12f23a1790f08c8df03819a3cb5bd7463622e7))


### Bug Fixes

* **installer:** mirror the style footer phrase (fixes install_style_drift) ([#154](https://github.com/arthurmaciel/ipe-lang/issues/154)) ([46d24bb](https://github.com/arthurmaciel/ipe-lang/commit/46d24bba1f631828ae9f344952594382d9817180))

## [0.1.17](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.16...ipe-v0.1.17) (2026-07-25)


### Bug Fixes

* **case:** ipê is not valid -&gt; Ipê ([dc7689f](https://github.com/arthurmaciel/ipe-lang/commit/dc7689f4c7a090d95c89a05f19d3e3fb842b1d02))
* **ipe-cli:** add --stdin flag to ipe fmt for editor integration ([34b6c40](https://github.com/arthurmaciel/ipe-lang/commit/34b6c40ea4afd42cf4b47b10c0ea8c58806db921))

## [0.1.16](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.15...ipe-v0.1.16) (2026-07-24)


### Bug Fixes

* **runtime:** gate cli_run_cmd on the tui feature (its sole caller) ([#93](https://github.com/arthurmaciel/ipe-lang/issues/93)) ([cb1f625](https://github.com/arthurmaciel/ipe-lang/commit/cb1f6251217d1f56300927dbf64a5c89f4f4f3fa))

## [0.1.15](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.14...ipe-v0.1.15) (2026-07-22)


### Features

* [#337](https://github.com/arthurmaciel/ipe-lang/issues/337) row polymorphism + first-class accessors ([#10](https://github.com/arthurmaciel/ipe-lang/issues/10)) ([90af7a5](https://github.com/arthurmaciel/ipe-lang/commit/90af7a5f16bf10028dd4220aa18a1f212504b38d))
* [#337](https://github.com/arthurmaciel/ipe-lang/issues/337) row-polymorphic record annotations { r | f : T } ([#14](https://github.com/arthurmaciel/ipe-lang/issues/14)) ([d0c2514](https://github.com/arthurmaciel/ipe-lang/commit/d0c2514f1aa80ce22161a7fbcdabe3c8ca77eb78))
* **#210:** seal Ipe.Email — Email.send + EmailMessage/EmailProvider fold ([e1486e4](https://github.com/arthurmaciel/ipe-lang/commit/e1486e4768ad2737b30f53d9d953dcb15d9763d0))
* **backend:** [#315](https://github.com/arthurmaciel/ipe-lang/issues/315) call-arg combining render primitive + fn_call_width ([#12](https://github.com/arthurmaciel/ipe-lang/issues/12)) ([becfd89](https://github.com/arthurmaciel/ipe-lang/commit/becfd891a6626476e5d4fc2a531da7a3e9636383))
* **backend:** [#315](https://github.com/arthurmaciel/ipe-lang/issues/315) leaf-arm + statement emitters toward cutover ([#9](https://github.com/arthurmaciel/ipe-lang/issues/9)) ([a5bb75e](https://github.com/arthurmaciel/ipe-lang/commit/a5bb75ee22d7ddf5b697b8574a6773f324c295e5))
* **backend:** [#315](https://github.com/arthurmaciel/ipe-lang/issues/315) native emitter sweep to 0 divergences (cutover gated by non-body content) ([#32](https://github.com/arthurmaciel/ipe-lang/issues/32)) ([5581976](https://github.com/arthurmaciel/ipe-lang/commit/558197635e215d68beff405b67aacc7cd3e31760))
* **backend:** [#315](https://github.com/arthurmaciel/ipe-lang/issues/315) port IpeStringify format! emitters to native Doc rendering ([#35](https://github.com/arthurmaciel/ipe-lang/issues/35)) ([ce4a766](https://github.com/arthurmaciel/ipe-lang/commit/ce4a7660796ca3e6a48257e5116f17ab2f57f7ff))
* **backend:** [#315](https://github.com/arthurmaciel/ipe-lang/issues/315) recursive-Shape combine + chain glue — sweep 9→5 ([#16](https://github.com/arthurmaciel/ipe-lang/issues/16)) ([29ff276](https://github.com/arthurmaciel/ipe-lang/commit/29ff2761462b48145a9794d875287bff9d7c894a))
* **backend:** [#315](https://github.com/arthurmaciel/ipe-lang/issues/315) wire native Doc emitter into production emit_func ([#40](https://github.com/arthurmaciel/ipe-lang/issues/40)) ([f20e430](https://github.com/arthurmaciel/ipe-lang/commit/f20e430fec9a0fb20a3c40ca6d807bc27c01de23))
* **backend:** assignment-RHS-break Doc token for the let-value layout axis ([3d07e66](https://github.com/arthurmaciel/ipe-lang/commit/3d07e66caafd881205f0a486f5017f856db94b69))
* **backend:** native Doc emitter for Expr::Match via MatchArmTail ([0e4b182](https://github.com/arthurmaciel/ipe-lang/commit/0e4b182317cf742dfb1e520d15c16e029f863de5))
* **backend:** native Doc emitters for Lambda/SharedLambda + immediately-applied Apply ([740ba27](https://github.com/arthurmaciel/ipe-lang/commit/740ba2772ef25e38c34b52fcb27f11dd552f2682))
* **backend:** native Rust formatter Doc IR + renderer (P0) ([a675f3f](https://github.com/arthurmaciel/ipe-lang/commit/a675f3f484ab70a6c106dd5a527b7c5eb50aa037))
* **backend:** P1 Doc-building emit path — binop-chain builder + SEAL property test ([f7dbaeb](https://github.com/arthurmaciel/ipe-lang/commit/f7dbaeba919bd41b3155aa8a78047470a049107c))
* **backend:** real flat-vs-break Group in native renderer + structured if builder ([ff902e7](https://github.com/arthurmaciel/ipe-lang/commit/ff902e753ce2dc4d20b2f7d86a0c229c5943be2d))
* **backend:** SEAL-visible BraceBody Doc token for rustfmt brace add/strip ([e562ac9](https://github.com/arthurmaciel/ipe-lang/commit/e562ac9912db8a429bb9d86921b595bae24a9fa7))
* **backend:** structured Ctor Doc builder (payload + runtime-enum) ([aadb94c](https://github.com/arthurmaciel/ipe-lang/commit/aadb94c32ff32ead5790384ec0c5c31786c1f2b4))
* **backend:** structured delimited-list Doc builders + break-conditional trailing comma ([bcdc2c7](https://github.com/arthurmaciel/ipe-lang/commit/bcdc2c7f141b693c0c549f7ecfcde245c49dbb1a))
* **backend:** structured Destructure-block Doc builder ([c8c0e46](https://github.com/arthurmaciel/ipe-lang/commit/c8c0e46ff948a63bc0458b1e37a1ed095b2ca85b))
* **backend:** structured general-apply Doc builder ([059e4e5](https://github.com/arthurmaciel/ipe-lang/commit/059e4e52c16bd93aa5b83429c249c82b24013837))
* **backend:** structured generic call-tail Doc builder ([0fc9554](https://github.com/arthurmaciel/ipe-lang/commit/0fc9554c2a1a91f490e058f534eda6b1bb282d82))
* **backend:** structured let-block Doc builder ([7e7c274](https://github.com/arthurmaciel/ipe-lang/commit/7e7c274ee1ad8966bb7b729f9257b7f5eb8343b0))
* **backend:** structured record-literal Doc builder ([7cd66ca](https://github.com/arthurmaciel/ipe-lang/commit/7cd66cadfd5083030ab13dbfcf0c32ac6d65292f))
* **backend:** structured record-update Doc builder ([fb00c59](https://github.com/arthurmaciel/ipe-lang/commit/fb00c59105e47d565b5be4c2e14a7c026ee342db))
* **backend:** structured sync task-seq Doc builder ([87caa50](https://github.com/arthurmaciel/ipe-lang/commit/87caa50abafbd37590fc3cfafbe99588ac245c32))
* **ci:** examples-sweep bot-commits the refreshed upstream mirror ([5b71393](https://github.com/arthurmaciel/ipe-lang/commit/5b7139328c222d078ac0b0d23f13e4690e59bfd2))
* **ci:** live upstream-Sky parity comparison (retires the cached oracle) ([2404d2e](https://github.com/arthurmaciel/ipe-lang/commit/2404d2ec2de99ff9b985ef6b9353d203196e70cf))
* **cli:** add `ipe version` (also --version / -V) ([f504895](https://github.com/arthurmaciel/ipe-lang/commit/f5048959458057b210c9372c67a341b47464c064))
* **cli:** aligned --help column + consent-based installer PATH setup ([#50](https://github.com/arthurmaciel/ipe-lang/issues/50)) ([fb98598](https://github.com/arthurmaciel/ipe-lang/commit/fb98598988dc6fd877ea5fc9e329c22458c460af))
* **cli:** capabilities acceptance over examples + README ([333a3b4](https://github.com/arthurmaciel/ipe-lang/commit/333a3b42b98f27c66dbf07e2d5cec65e884983e7))
* **cli:** CLI-UI single-source-of-truth (style module) + installer polish + SSOT principle ([#75](https://github.com/arthurmaciel/ipe-lang/issues/75)) ([720e2c6](https://github.com/arthurmaciel/ipe-lang/commit/720e2c6b1304d10084c7baa3eb690e70845e5b16))
* **cli:** declutter ipe help (soft yellow, no optional-arg overview, bug-report footer) ([#15](https://github.com/arthurmaciel/ipe-lang/issues/15)) ([2f1b6dd](https://github.com/arthurmaciel/ipe-lang/commit/2f1b6dd85434decc6b20518cad82f4b7673c619b))
* **cli:** default entry for build/run/watch in project directories ([ebe88c7](https://github.com/arthurmaciel/ipe-lang/commit/ebe88c765479c391a4a467f4d76b12d1e3cc5735))
* **cli:** human-first output model — --plain/--json, gutter, error-shows-help, Package authoring section ([#78](https://github.com/arthurmaciel/ipe-lang/issues/78)) ([ea01f7f](https://github.com/arthurmaciel/ipe-lang/commit/ea01f7f3530646557c3916149d47c720828ec2e3))
* **cli:** ipe capabilities report + declared-set verify ([7eb4877](https://github.com/arthurmaciel/ipe-lang/commit/7eb48774be0c008278510ebeb96aa80b2e1ce81c))
* **cli:** ipe fmt — elm-format-compatible source formatter ([8e3cbef](https://github.com/arthurmaciel/ipe-lang/commit/8e3cbefe6969d990dea0dcfa9a3c07d5547986fe))
* **cli:** ipe init scaffolds an Ipe.Live counter project ([60277f6](https://github.com/arthurmaciel/ipe-lang/commit/60277f64e91a8dade4ca8c898740a47e9b2c8ff0))
* **cli:** ipe run --static — shared static-flag parser + plan resolver across build/run; binary located via cargo metadata target_directory (honours CARGO_TARGET_DIR / user target-dir pins) ([5e25b11](https://github.com/arthurmaciel/ipe-lang/commit/5e25b11ddd4b452eed3a97446477b62912915448))
* **cli:** sectioned, coloured top-level help and per-command --help ([976dc92](https://github.com/arthurmaciel/ipe-lang/commit/976dc92030706e38005e358f6083fb5a2177ba41))
* **cli:** SP2 — ipe rust group + ipe.toml schema ([#4](https://github.com/arthurmaciel/ipe-lang/issues/4)) ([364b213](https://github.com/arthurmaciel/ipe-lang/commit/364b213fc5dd69b9a95d17e5db8147ddf0397d69))
* **cli:** SP3 — index resolver + lockfile + ipe add ([#8](https://github.com/arthurmaciel/ipe-lang/issues/8)) ([c358c2a](https://github.com/arthurmaciel/ipe-lang/commit/c358c2af27271ed2b766c0f888eb537fa8251bad))
* **cli:** SP5 — ipe diff + enforced semver ([#11](https://github.com/arthurmaciel/ipe-lang/issues/11)) ([038ad53](https://github.com/arthurmaciel/ipe-lang/commit/038ad534d0b65ab74f57ed80e1c0b030547e7b44))
* **cli:** typed arg parsing — invalid optional-flag combinations unrepresentable + exhaustive tests ([#34](https://github.com/arthurmaciel/ipe-lang/issues/34)) ([783e922](https://github.com/arthurmaciel/ipe-lang/commit/783e92212020b6d6c2bde9dd1c11564be9790af5))
* **emit:** post-emit rustfmt pass (fail-closed) so emitted Rust is rustfmt-clean; regenerate 73 goldens to canonical form ([3f624bc](https://github.com/arthurmaciel/ipe-lang/commit/3f624bc8a246e2eaf7a2ec541cb4cd050d8aaa7f))
* **examples:** 13-skyshop transpose in progress — Db+Auth de-shimmed onto real SDKs, 8-crate cache checked in ([41aeca9](https://github.com/arthurmaciel/ipe-lang/commit/41aeca91c1920133fda3b629e32eea29526c09e3))
* **examples:** add examples/sky/manifest.toml — Sky→Ipe patch registry ([#299](https://github.com/arthurmaciel/ipe-lang/issues/299)) ([60764be](https://github.com/arthurmaciel/ipe-lang/commit/60764bebbc9d183f054e492f54f46e089dfe1cf0))
* **examples:** bring composite examples 36-38 into sweep scope ([#377](https://github.com/arthurmaciel/ipe-lang/issues/377)) ([#83](https://github.com/arthurmaciel/ipe-lang/issues/83)) ([6f6193a](https://github.com/arthurmaciel/ipe-lang/commit/6f6193a9af83587b69b41fba2d874d286bb25e40))
* **examples:** port go-ffi examples to Ipê + Rust crates (7 examples) ([#80](https://github.com/arthurmaciel/ipe-lang/issues/80)) ([c1f3bf7](https://github.com/arthurmaciel/ipe-lang/commit/c1f3bf782b2f78274d6f5db3297cb5086d196d15))
* **examples:** track the upstream Sky example mirror (42 examples, source-only) ([ee24e09](https://github.com/arthurmaciel/ipe-lang/commit/ee24e0987162f83520eb1e7f823abda672d546f4))
* **ffi-inspector:** param-shape admission — conversion-bound nominal targets (identity + From&lt;String&gt; preference), enum-level non_exhaustive ctor restoration, Clone-enum field accessors ([0c7e9d2](https://github.com/arthurmaciel/ipe-lang/commit/0c7e9d28594b19b3ac95a9ed72eceded2b9d5dbd))
* **ffi-inspector:** resumable manifest inspection — stable probe root + cross-crate proof-map checkpoint ([989ee3b](https://github.com/arthurmaciel/ipe-lang/commit/989ee3bd35091840062b910f9929e0a3973b9a26))
* **ffi-inspector:** stripe-send — doc-hidden surfacing + cross-crate Send proof (3 of 4 walls) ([8a2f590](https://github.com/arthurmaciel/ipe-lang/commit/8a2f5902ffec29c2b8487934bd9ce842650083c2))
* **ffi-inspector:** stripe-send F2 — cross-crate proven-public Output paths (GLOBAL_XC_PUBLIC_PATHS) ([3146360](https://github.com/arthurmaciel/ipe-lang/commit/314636064522c0e887470a520963df966a1569d2))
* **ffi-inspector:** stripe-send F2 (cont.) — resolve cross-crate send Output in type_to_typeref ([a29b0d3](https://github.com/arthurmaciel/ipe-lang/commit/a29b0d30903717cd3b06f41962ba8a49d4a73c70))
* **ffi-inspector:** stripe-send W4 — return-nameability by defining-type identity (4th wall) ([1fefa83](https://github.com/arthurmaciel/ipe-lang/commit/1fefa83f99f6c129552704695019674120bb0982))
* **ffi:** [#317](https://github.com/arthurmaciel/ipe-lang/issues/317)+[#326](https://github.com/arthurmaciel/ipe-lang/issues/326) auto-binding coverage — bundle-generics, dyn-Fn systems, multi-result tuples ([#72](https://github.com/arthurmaciel/ipe-lang/issues/72)) ([572ddbd](https://github.com/arthurmaciel/ipe-lang/commit/572ddbdd1ada659dd04e4920b619786b8dbf781a))
* **ffi:** [#347](https://github.com/arthurmaciel/ipe-lang/issues/347) sync closure adapter ([rust.provide.closure]) ([#36](https://github.com/arthurmaciel/ipe-lang/issues/36)) ([72cfd04](https://github.com/arthurmaciel/ipe-lang/commit/72cfd041b1c87a29e3415f4590fdf638b507e605))
* **ffi:** [#350](https://github.com/arthurmaciel/ipe-lang/issues/350) closure-manifest glue + [#348](https://github.com/arthurmaciel/ipe-lang/issues/348) struct-with-trait-impl ([#38](https://github.com/arthurmaciel/ipe-lang/issues/38)) ([ade2673](https://github.com/arthurmaciel/ipe-lang/commit/ade2673adffb0c3d118384f57e06b5b5bc9b06a1))
* **ffi:** [#352](https://github.com/arthurmaciel/ipe-lang/issues/352) provide.* Ipê-side forwarder plumbing ([#46](https://github.com/arthurmaciel/ipe-lang/issues/46)) ([cc9718b](https://github.com/arthurmaciel/ipe-lang/commit/cc9718b34d7e26a562797466d0b9fc2bcd07653b))
* **ffi:** [#353](https://github.com/arthurmaciel/ipe-lang/issues/353) provide.closure opaque returns ([#47](https://github.com/arthurmaciel/ipe-lang/issues/47)) ([bc86028](https://github.com/arthurmaciel/ipe-lang/commit/bc86028122e36aee235f36877a1f46191c07d397))
* **ffi:** [#354](https://github.com/arthurmaciel/ipe-lang/issues/354) opaque struct fields / enum payloads ([#57](https://github.com/arthurmaciel/ipe-lang/issues/57)) ([41af8c7](https://github.com/arthurmaciel/ipe-lang/commit/41af8c77b55e55422ab08c76a8db91ae84595c0a))
* **ffi:** [#364](https://github.com/arthurmaciel/ipe-lang/issues/364) Tier 2 phases 1-3 — bind author-supplied Rust wrapper crates ([#62](https://github.com/arthurmaciel/ipe-lang/issues/62)) ([28618f7](https://github.com/arthurmaciel/ipe-lang/commit/28618f7a7536b4c293ae6ddc65e02e2092e1114c))
* **ffi:** [#365](https://github.com/arthurmaciel/ipe-lang/issues/365) Tier 2 capability inference + fail-closed enforcement ([#71](https://github.com/arthurmaciel/ipe-lang/issues/71)) ([965aa15](https://github.com/arthurmaciel/ipe-lang/commit/965aa158a2616ad47c7e3441ad3ee9f83b989267))
* **ffi:** [#366](https://github.com/arthurmaciel/ipe-lang/issues/366) Tier 2 #[ipe::provide] trait-impl escape hatch ([#69](https://github.com/arthurmaciel/ipe-lang/issues/69)) ([2cc5114](https://github.com/arthurmaciel/ipe-lang/commit/2cc5114470177a84a6c7b67d4ffa96b90c5222db))
* **ffi:** [#369](https://github.com/arthurmaciel/ipe-lang/issues/369) closure-&gt;run handoff — drive foreign loops with Ipê closures ([#70](https://github.com/arthurmaciel/ipe-lang/issues/70)) ([8c4b662](https://github.com/arthurmaciel/ipe-lang/commit/8c4b6627baa46a7aeb1df4ebb462fd76599b612e))
* **ffi:** async wrappers arm AbortOnDrop + route JoinError through ipe_error_from_foreign (Δ1/Δ2) ([cde8092](https://github.com/arthurmaciel/ipe-lang/commit/cde809246b7feeef8acfb5d3d53f28340bfda23f))
* **ffi:** async-returning provide.closure ([#55](https://github.com/arthurmaciel/ipe-lang/issues/55)) ([8bce55b](https://github.com/arthurmaciel/ipe-lang/commit/8bce55badf5c678df9e4066fa0a78e0c75dc28b2))
* **ffi:** async-SDK consumer path — closed-instance synthesis, alias fold, used-set forwarder DCE; firestore 0.49 bound shim-free E2E ([d5327f2](https://github.com/arthurmaciel/ipe-lang/commit/d5327f276d727792c2ecec4fc2f56e294bcfb4e5))
* **ffi:** borrow-thread &self/&mut self FFI readers through the result ([9b1f4ce](https://github.com/arthurmaciel/ipe-lang/commit/9b1f4ce6bd936b6fb4bb83b2998bcaf38d0f63c2))
* **ffi:** checked fallible setters for narrowing integer fields — try_from + typed Err replaces the setter drop (no silent truncation; f32/containers stay dropped) ([af035d3](https://github.com/arthurmaciel/ipe-lang/commit/af035d3ded91ab211fd177fc287189960363a4ef))
* **ffi:** firebase-bind shim-free — rs-firebase-admin-sdk 4.3 SEAL green (verify chain live) ([06f334b](https://github.com/arthurmaciel/ipe-lang/commit/06f334bd68899f582987da9501ccc458ee406756))
* **ffi:** foreign-type-one-home — defid-keyed nominal unification across the installed-crate catalog ([857eb62](https://github.com/arthurmaciel/ipe-lang/commit/857eb62acf482f1b3c1c38b8a0c8317f41d8fc4c))
* **ffi:** one-shot manifest install + submodule Ipe-head path map + prerelease pin pass-through ([46f4e23](https://github.com/arthurmaciel/ipe-lang/commit/46f4e23af417ed9c06d0382a97859f078311e2bb))
* **ffi:** pkg.json is the sole catalog source — load re-derives the full consumer view ([9154383](https://github.com/arthurmaciel/ipe-lang/commit/915438347af734a8bb9b278b6b9cb76eac08f6bb))
* **ffi:** provide.enum (P4) + Debug derive — Iced binding spike ([#42](https://github.com/arthurmaciel/ipe-lang/issues/42)) ([eef982a](https://github.com/arthurmaciel/ipe-lang/commit/eef982a8e8d6a499c4d9ce38f19200b25d2c43b4))
* **ffi:** stripe-send W4 verified end-to-end + multi-crate dep-line unification ([1a20c74](https://github.com/arthurmaciel/ipe-lang/commit/1a20c746b27966b6b453157d715c51864744791d))
* **ffi:** version-pinned crate specs + feature/pin propagation through ipe add/install ([0d9c433](https://github.com/arthurmaciel/ipe-lang/commit/0d9c4336626d1855fce90b513d10d2430f34df32))
* **install:** fix curl (23), add spinner/percent/ETA + friendly branded messages ([#28](https://github.com/arthurmaciel/ipe-lang/issues/28)) ([b27654d](https://github.com/arthurmaciel/ipe-lang/commit/b27654d0ed7f3bdb72bec2772c23db14245f13ab))
* **kernels:** add Database capability; reclassify Db-family kernels ([5ec4ccd](https://github.com/arthurmaciel/ipe-lang/commit/5ec4ccde5c3c897cf785b84411901b4885146b64))
* **kernels:** per-kernel capability tag + Capability vocabulary ([2fd7401](https://github.com/arthurmaciel/ipe-lang/commit/2fd74017f2b80c97af362cdbd31a6e118d05b20e))
* **lower:** whole-program capability inference ([5a48b73](https://github.com/arthurmaciel/ipe-lang/commit/5a48b734ffcc31015c2caffaf267252db9b6e6d7))
* **lsp,db:** per-module typecheck_module query SEAM + migrate home-keyed handlers ([570760e](https://github.com/arthurmaciel/ipe-lang/commit/570760e20c2568b3acecf783f5eb1723a40175ae))
* **lsp:** [#295](https://github.com/arthurmaciel/ipe-lang/issues/295) document formatting + rangeFormatting ([71f81b6](https://github.com/arthurmaciel/ipe-lang/commit/71f81b6b429e649f5f655d42b56e756b5f571a10))
* **lsp:** [#296](https://github.com/arthurmaciel/ipe-lang/issues/296) code actions — diagnostic-driven quick-fixes ([3177844](https://github.com/arthurmaciel/ipe-lang/commit/3177844f6a33861cd31a0a46ebbc1bd7dedc3a4f))
* **lsp:** [#297](https://github.com/arthurmaciel/ipe-lang/issues/297) semantic tokens full — 10-type legend over the parse AST ([7ef7aa2](https://github.com/arthurmaciel/ipe-lang/commit/7ef7aa24619d6599d558d0a51908044f0e3e0d07))
* **lsp:** [#298](https://github.com/arthurmaciel/ipe-lang/issues/298) signature help + inlay hints ([8e5b3dc](https://github.com/arthurmaciel/ipe-lang/commit/8e5b3dc68619b2696ef9c2175fdb794778b06566))
* **lsp:** completion, go-to-definition, find-references, rename ([926bb34](https://github.com/arthurmaciel/ipe-lang/commit/926bb34f3008e8f2a755243f3688f027432dba4b))
* **lsp:** document links + folding ranges ([62e9141](https://github.com/arthurmaciel/ipe-lang/commit/62e9141e07b49e496153bdec2addf3880098a7ea))
* **lsp:** ipe lsp server — live diagnostics, hover, document symbols over the salsa graph ([64b684e](https://github.com/arthurmaciel/ipe-lang/commit/64b684e7a4a8aa014a7023fe4786626ba494f0a6))
* **lsp:** type-directed completion via additive ExpectedTypes solver sidecar ([d1b475e](https://github.com/arthurmaciel/ipe-lang/commit/d1b475e27066286828d09a79501ef1588065a03a))
* **lsp:** wire [#295](https://github.com/arthurmaciel/ipe-lang/issues/295)-298 into server — capabilities + request handlers ([f0b5046](https://github.com/arthurmaciel/ipe-lang/commit/f0b5046600cbacbf97c65c8462be38fef74b8825))
* **pkg:** [#368](https://github.com/arthurmaciel/ipe-lang/issues/368) SP4 Tier-1 package gate + ipe package audit ([#66](https://github.com/arthurmaciel/ipe-lang/issues/66)) ([5838ff5](https://github.com/arthurmaciel/ipe-lang/commit/5838ff5de03157dd07bad5a3bc3f846e0fb8e1b9))
* **runtime:** process-global tokio runtime for block_on + AbortOnDrop cancel guard (async-FFI bridge H1/Δ1 primitives) ([e901c2b](https://github.com/arthurmaciel/ipe-lang/commit/e901c2bf2a586ac6e3861231c2ad5e0d6d8cde57))
* **security:** [#359](https://github.com/arthurmaciel/ipe-lang/issues/359) drive the abrupt-failure ledger toward zero ([#58](https://github.com/arthurmaciel/ipe-lang/issues/58)) ([ba4c309](https://github.com/arthurmaciel/ipe-lang/commit/ba4c3091ec33785b975d610d00a7d29cff7b5442))
* **security:** [#371](https://github.com/arthurmaciel/ipe-lang/issues/371) runtime capability sandbox + admit-and-isolate Tier 2 wrappers ([#82](https://github.com/arthurmaciel/ipe-lang/issues/82)) ([04214e5](https://github.com/arthurmaciel/ipe-lang/commit/04214e5ab0868dace57586c4c254fc7f8f746ee7))
* **security:** token-scanner gate + clippy hardening for authored abrupt-failure ([#54](https://github.com/arthurmaciel/ipe-lang/issues/54)) ([843a17b](https://github.com/arthurmaciel/ipe-lang/commit/843a17baedb626ed4ec90bec2ad02e14fb61a67b))
* **static:** [#244](https://github.com/arthurmaciel/ipe-lang/issues/244) add aarch64-unknown-linux-musl static target (config + CI) ([297927a](https://github.com/arthurmaciel/ipe-lang/commit/297927aef8385db05b66492b15a4c489f90a681b))
* **static:** pin rust-lld self-contained for aarch64-musl — portable static cross-build (no musl-cross-gcc) ([2935170](https://github.com/arthurmaciel/ipe-lang/commit/2935170bb92e1fca5f1917daa5b4a15c44031d38))
* **stdlib:** [#339](https://github.com/arthurmaciel/ipe-lang/issues/339) pure elm/core fills (List/Dict/Set/Result/Char/String) ([#43](https://github.com/arthurmaciel/ipe-lang/issues/43)) ([37da719](https://github.com/arthurmaciel/ipe-lang/commit/37da7192da96bf9ca651bc594ded7a4482402145))
* **stdlib:** [#342](https://github.com/arthurmaciel/ipe-lang/issues/342) Task + decoder combinators ([#49](https://github.com/arthurmaciel/ipe-lang/issues/49)) ([1fc9149](https://github.com/arthurmaciel/ipe-lang/commit/1fc91496758dfa4ac63dd02f2018243b111264b3))
* **stdlib:** Cmd.map / Sub.map ([#44](https://github.com/arthurmaciel/ipe-lang/issues/44)) ([eca501b](https://github.com/arthurmaciel/ipe-lang/commit/eca501b9265720c1970b290ee67df220e935fbdf))
* **sweep:** fail loud on unpatched new upstream examples + self-regression docs ([#300](https://github.com/arthurmaciel/ipe-lang/issues/300)) ([f60bdb5](https://github.com/arthurmaciel/ipe-lang/commit/f60bdb50cc045b75664ba10d0b4ab520fc696ebe))
* **sweep:** IPE_SWEEP_STATIC=1 — per-example --static musl build (CWD = emitted crate dir), ldd-asserted static-ness, static-binary RUN, webview typed-refusal assertion ([d177666](https://github.com/arthurmaciel/ipe-lang/commit/d177666721ad4a7c6db89810986498cd5a7b0869))
* **sweep:** Ipê-only upstream-mirror sweep, retire the Go-oracle equivalence infra ([7773a7f](https://github.com/arthurmaciel/ipe-lang/commit/7773a7f9c12a6eed634dfe00251aebcb32933c95))
* **types,db:** per-module scoped typecheck behind typed interfaces ([6991b4c](https://github.com/arthurmaciel/ipe-lang/commit/6991b4c9f79e3b3987e641613020c2005db5f9c8))
* **wasm:** browser TEA sink + target-neutral dom re-home ([4d0a74c](https://github.com/arthurmaciel/ipe-lang/commit/4d0a74c8f28211e8f2f5bb7ba37662bb8fbbc3de))
* **wasm:** compile the Ipê frontend to WASM + browser-native playground ([40587ca](https://github.com/arthurmaciel/ipe-lang/commit/40587ca95b78ab4c6073950e0c092249fc931d3f))
* **wasm:** Ipe.Env.public kernel + build-time publicEnv embedding ([#287](https://github.com/arthurmaciel/ipe-lang/issues/287)) ([6729c68](https://github.com/arthurmaciel/ipe-lang/commit/6729c68081dc9fe9df8ec7231ad1d84e40d4c95a))
* **wasm:** M0 pure-kernel wasm floor — runtime builds to wasm32-unknown-unknown (default + json) as an enforced CI gate ([9a66a2d](https://github.com/arthurmaciel/ipe-lang/commit/9a66a2d2272e1afbca5654729832593c45c6eee6))
* **wasm:** M1 target-keyed kernel gate + M2 emission branch + M3 browser slice — ipe build --target wasm, Ipe.Ui proven in Chromium ([9523e03](https://github.com/arthurmaciel/ipe-lang/commit/9523e03d01b3f724cd56b07153626913ba23c75c))
* **wasm:** M4 Cmd/Sub browser-effects bridge — Log/Random/Http/WebSocket/Task substitutes, timers, in-tab pub/sub ([e95af5a](https://github.com/arthurmaciel/ipe-lang/commit/e95af5ad106fce8ae05eccf3f13e8e3e94429ca0))
* **wasm:** M5 Layer-2 module classification + reachability closure + [wasm] ipe.toml config (IPE-N0030) ([d668b89](https://github.com/arthurmaciel/ipe-lang/commit/d668b897d32cf9e576fedbbca3a56499e9d634b2))
* **wasm:** M6 Target A MVP — pure-client SPA end-to-end ([#240](https://github.com/arthurmaciel/ipe-lang/issues/240)) ([30533d1](https://github.com/arthurmaciel/ipe-lang/commit/30533d1de968f44ed406e121ddc4fea52a4a9d44))
* **wasm:** M7 SSR hydration — island serialiser, adopt path, hydrate export, field-type gate ([0b7f543](https://github.com/arthurmaciel/ipe-lang/commit/0b7f543108a5ffc7e8ef67b126555ef4c01f6012))
* **wasm:** M8 playground B1 — server-compile-then-ship-WASM backend ([0171f27](https://github.com/arthurmaciel/ipe-lang/commit/0171f27dfd023bab77dd56ff616d7e9ef0d1813a))


### Bug Fixes

* **#210:** register Ipe.Config family — Decoder carrier + 16 kernels SEAL ([627afe0](https://github.com/arthurmaciel/ipe-lang/commit/627afe0563141f68355390b4cc5b6ed4eb902cec))
* **backend,lower:** SEAL 13-skyshop — cfg-record arg-order hoist, sync-capture param promotion trigger, single-boundary Arc callback ([4c2ac25](https://github.com/arthurmaciel/ipe-lang/commit/4c2ac252c345920f0bcd1ad8682be597926c7860))
* **backend/tests:** pass wasm_hydrate_mode to EmitCtx::build test call sites (WASM M7 arity debt) ([711c725](https://github.com/arthurmaciel/ipe-lang/commit/711c725f151f520a24fdb518908e9234a5e59e5a))
* **backend:** close the module-set SEAL breach class (tea/live/http_stream drift) ([d3d0bd8](https://github.com/arthurmaciel/ipe-lang/commit/d3d0bd806ad128175f728600f522affd312daffb))
* **backend:** emitter emits at most one consecutive blank line ([7e69cb8](https://github.com/arthurmaciel/ipe-lang/commit/7e69cb8dd81798a81601d82de6abcb1923efd803))
* **backend:** FFI shake keep-decision accumulates instead of overwriting ([#283](https://github.com/arthurmaciel/ipe-lang/issues/283)) ([1a08994](https://github.com/arthurmaciel/ipe-lang/commit/1a08994c12097be16306a81e9bb4067e2ce41432))
* **backend:** two emitter fallbacks fail closed instead of emitting invalid Rust ([#281](https://github.com/arthurmaciel/ipe-lang/issues/281)) ([13ae62d](https://github.com/arthurmaciel/ipe-lang/commit/13ae62df0ae42ed3c1003e3c1494046df882df71))
* **canon:** bound type-alias expansion with depth + node-count limits (IPE-N0032) ([2d973e6](https://github.com/arthurmaciel/ipe-lang/commit/2d973e6f6dae10ee6b6322e9736d91cc8d5a0cf9))
* **canon:** canon-arity-gate — reject mis-arity built-in containers (IPE-N0031) ([1089a76](https://github.com/arthurmaciel/ipe-lang/commit/1089a76ae6096bbdc7d0a109ca725ab1e32f0962))
* **canon:** qualified cross-module alias references expand without exposing ([3fe074f](https://github.com/arthurmaciel/ipe-lang/commit/3fe074f073d3df9cdf45a0035269ab741090138d))
* **ci:** clippy duration_suboptimal_units (from_secs-&gt;from_mins, toolchain drift: CI stable was ahead of local rustup) + golden_alias_move_seal stale substring assertions (rustfmt reflow, same class as [#269](https://github.com/arthurmaciel/ipe-lang/issues/269)) + .gitignore drop ../sky ref + point oracle-version comment at its SSOT (tools/oracle/README.md) ([737eb50](https://github.com/arthurmaciel/ipe-lang/commit/737eb5030bb1baed34f24431ea77bcf26ddf4669))
* **ci:** clippy duration_suboptimal_units in lsp_stdio_e2e.rs (from_secs(60)-&gt;from_mins(1)) ([a69d923](https://github.com/arthurmaciel/ipe-lang/commit/a69d9233eb97d28f9973586ab1e461a54d32d8a4))
* **ci:** clippy map_unwrap_or in ipe_watch scope.rs (map_or(0, |d| d.as_nanos())) ([3dea51c](https://github.com/arthurmaciel/ipe-lang/commit/3dea51c8da00fe8a7626588ce09af616620bf0b3))
* **ci:** e2e shards — set IPE_ORACLE_SHARED_TARGET, closing the disk-exhaustion class ([bf61ebb](https://github.com/arthurmaciel/ipe-lang/commit/bf61ebbd555fdba38e8b06657d9ff478738479f6))
* **ci:** install jail primitives for static e2e + pin goldens to LF ([#86](https://github.com/arthurmaciel/ipe-lang/issues/86)) ([dbdd2a0](https://github.com/arthurmaciel/ipe-lang/commit/dbdd2a0bdf477b27f10e0bf6caed149a0f9ada1b))
* **ci:** install wry/tao Linux link deps in e2e job to clear SEAL breach ([#51](https://github.com/arthurmaciel/ipe-lang/issues/51)) ([4378a36](https://github.com/arthurmaciel/ipe-lang/commit/4378a36a54940fc223eb2200fa3a8854f3a071c3))
* **ci:** nextest ci profile, 6 E2E shards, sccache v0.0.9, --no-fail-fast ([d9adfbe](https://github.com/arthurmaciel/ipe-lang/commit/d9adfbe3f3c8b82d681025ab4522ea66427fb07e))
* **ci:** sky-parity picks the compiler binary, not the FFI inspector ([8239648](https://github.com/arthurmaciel/ipe-lang/commit/82396481cd0ee74fa3c3784862bee6a76266a078))
* **ci:** stale golden-test substring assertions masked by nextest fail-fast ([#191](https://github.com/arthurmaciel/ipe-lang/issues/191), [#193](https://github.com/arthurmaciel/ipe-lang/issues/193), [#195](https://github.com/arthurmaciel/ipe-lang/issues/195), [#190](https://github.com/arthurmaciel/ipe-lang/issues/190), ws-onerror, Ipe.Ui.Animation/Transition) ([facd9a7](https://github.com/arthurmaciel/ipe-lang/commit/facd9a76e7d6920dc0e867588df61742e75ae3b2))
* **ci:** three more E2E failures the disk-exhaustion fix stopped masking (server-clone reflow, webview Linux link gap, watch cold-build headroom) ([193760c](https://github.com/arthurmaciel/ipe-lang/commit/193760ce78a2c4dab6f21912d57e3f855cf64fb5))
* **cli:** clear nightly-clippy debt in wasm bundle step and manifest parsing ([47d89c2](https://github.com/arthurmaciel/ipe-lang/commit/47d89c2f3682ef58f15f165c320c46bf96b4bc7c))
* **clippy+fmt:** ffi.rs map_or + doc-paragraph split; rustfmt resolve.rs/types-lib drift ([89280bf](https://github.com/arthurmaciel/ipe-lang/commit/89280bf30629a99b948792820cfc1d49abbd20d7))
* **clippy:** clear pre-existing --all-targets lint debt in LSP, backend, canon, types, playground ([78d1d6e](https://github.com/arthurmaciel/ipe-lang/commit/78d1d6e07cd8ad3fe66e4c87363f8c5f7c7248f4))
* **cli:** rewrite two test match blocks as let-else (clippy pedantic on --all-targets) ([#3](https://github.com/arthurmaciel/ipe-lang/issues/3)) ([d5a7b37](https://github.com/arthurmaciel/ipe-lang/commit/d5a7b370760e39a4ca3f98eefed386afcea46d99))
* **cli:** Usage error strings match the redesigned help ([#23](https://github.com/arthurmaciel/ipe-lang/issues/23)) ([c0872ee](https://github.com/arthurmaciel/ipe-lang/commit/c0872ee57b08eae365f4ae14be2fc5a96d7718db))
* **deps:** regenerate package-lock.json — was stale, missing pixelmatch/pngjs entirely (only had playwright) ([d5d6dcf](https://github.com/arthurmaciel/ipe-lang/commit/d5d6dcf0961c6e3f3afe792dca24e22139e74a55))
* **diagnostics:** drop duplicate unreachable BuiltinTypeArity render arm (merge artifact) ([803d751](https://github.com/arthurmaciel/ipe-lang/commit/803d7515ba588b5fdb73207e0fb912e5940ef56a))
* **docs:** correct stale warm-db-reuse doc — the parity gate already exists ([#277](https://github.com/arthurmaciel/ipe-lang/issues/277)) ([96ece49](https://github.com/arthurmaciel/ipe-lang/commit/96ece49a8517fbaae2131e785e13b7b76d9ffa00))
* **emit:** opaque-type special-cases keyed on old Std home -&gt; Ipe (Cache/Config/Email) ([4a3cb4c](https://github.com/arthurmaciel/ipe-lang/commit/4a3cb4cd2be14f960ea7f37b0e002e8db4dfb8dd))
* **example:** 41-money-allocate-regression — correct main sig (drop Never) + fromMajor takes Int not Decimal; T4's example never compiled as shipped ([375e339](https://github.com/arthurmaciel/ipe-lang/commit/375e339b1ff5b81748415cda0579ccc10f3b905f))
* examples-sweep 26/29/31 build+run green ([#33](https://github.com/arthurmaciel/ipe-lang/issues/33)) ([26c0c11](https://github.com/arthurmaciel/ipe-lang/commit/26c0c1167d66e5a266307e106783bc45d6ff5fc8))
* **examples:** patch 00-standard-libs Money tests for Ipê's Result API ([bdfbca2](https://github.com/arthurmaciel/ipe-lang/commit/bdfbca2ea2a65b11664c51a2ce1c798d9239fc04))
* **examples:** restore native 01-hello-world; untrack sky-out build output ([bab7bc6](https://github.com/arthurmaciel/ipe-lang/commit/bab7bc6d65a94891237defdb9415dbc07ff4f1f4))
* **explain:** github issue links + trailing newline ([#18](https://github.com/arthurmaciel/ipe-lang/issues/18)) ([f8fbc6f](https://github.com/arthurmaciel/ipe-lang/commit/f8fbc6fa78359c0461a9739d0a5b41243a739a02))
* **ffi-inspector:** private-path-admission — drop external trait UFCS qualifiers threading a private module ([b1de3de](https://github.com/arthurmaciel/ipe-lang/commit/b1de3de4569d02b46587afdbfd605dd95138743c))
* **ffi-inspector:** serde-trait identity by raw defining path — restores the firestore serde document surface ([b8afea3](https://github.com/arthurmaciel/ipe-lang/commit/b8afea35b35d6932e9f77d0ce2367e5418f58915))
* **ffi-sandbox:** T1 F2-F6 — two-phase no-egress jail, narrowed ~/.cargo binds, mandatory caps + concurrent drain, bwrap-or-refuse, bounded owned cache root, scratch under ~/.cache/ipe + install prompt ([adf54c3](https://github.com/arthurmaciel/ipe-lang/commit/adf54c328ff444ebe68f74cd5bcefca33c6da5a6))
* **ffi:** [#326](https://github.com/arthurmaciel/ipe-lang/issues/326) admit coercible multi-result tuples for non-borrow-reader methods ([#21](https://github.com/arthurmaciel/ipe-lang/issues/21)) ([f37fe03](https://github.com/arthurmaciel/ipe-lang/commit/f37fe03f8e775b68b5ee5ddfb8dac3c3e167f52c))
* **ffi:** [#363](https://github.com/arthurmaciel/ipe-lang/issues/363) refuse recursive provide types at decode (SEAL) ([#61](https://github.com/arthurmaciel/ipe-lang/issues/61)) ([51bc01d](https://github.com/arthurmaciel/ipe-lang/commit/51bc01d0e6895a375f4b638e00beee2ba8438710))
* **ffi:** compositional OK-lift for generic wrappers + owned pass for bare-str substitutes ([5a04388](https://github.com/arthurmaciel/ipe-lang/commit/5a043886381beabe8edbddbddfdf728f59e207ff))
* **ffi:** fail-closed on reuse of a non-Clone FFI opaque handle (SEAL) ([3b0c86e](https://github.com/arthurmaciel/ipe-lang/commit/3b0c86ef51fd4286ad763cd80c5b6f089e8922df))
* **ffi:** fallible setter surface carries the Result layer the wrapper renders ([92c4905](https://github.com/arthurmaciel/ipe-lang/commit/92c490579d13dbd4418213a843d8b526ab3eba9b))
* **ffi:** gate Cargo feature names at the manifest boundary ([c159a9a](https://github.com/arthurmaciel/ipe-lang/commit/c159a9a914c203db0842042b58c26a69a6a5da1b))
* **ffi:** gate dep features + transitive name at the pkg.json decode boundary ([50f7934](https://github.com/arthurmaciel/ipe-lang/commit/50f793451e6668f9a31e536429cdcd73ab7e7e5b))
* **ffi:** maybe-coercion — IpeMaybe&lt;-&gt;Option at synthesised-instance boundaries ([dfa851c](https://github.com/arthurmaciel/ipe-lang/commit/dfa851ce1db08ad88ea78f83aea4784dd797d25b))
* **ffi:** one-home unification verified E2E — stripe 6-crate SEAL green ([36a4413](https://github.com/arthurmaciel/ipe-lang/commit/36a441383235c92ac7c0e584da566bb4447da748))
* **ffi:** seal the RCE sandbox for SDK-scale installs — chunk per crate + calibrate caps ([#309](https://github.com/arthurmaciel/ipe-lang/issues/309)) ([d2bec5d](https://github.com/arthurmaciel/ipe-lang/commit/d2bec5d87ef571b4894e405e568a84b48e8480f2))
* **ffi:** T1 clippy clean-up + warm-load byte-identity test ([80a5171](https://github.com/arthurmaciel/ipe-lang/commit/80a51714323e126636a5045fefa5b105ab936e38))
* **ffi:** T1 F1 — validated type/path/selector newtypes at the FFI decode boundary + re-derive load_catalog from validated inspection doc ([f1082f5](https://github.com/arthurmaciel/ipe-lang/commit/f1082f516ca619ad9077b3496ef8cab93190981c))
* **ffi:** T1 F1e — graceful legacy fallback for caches without pkg.json ([1a71754](https://github.com/arthurmaciel/ipe-lang/commit/1a717549b6370fae9cefb757033b51ac009207cb))
* **ffi:** validate crate version at decode boundary (CrateVersion newtype) ([6becd88](https://github.com/arthurmaciel/ipe-lang/commit/6becd887652bac03e9fe25ab5cf87c668cc7d327))
* **ffi:** validate pkg_path at the pkginfo decode boundary ([fe0338e](https://github.com/arthurmaciel/ipe-lang/commit/fe0338e3e9088cf8432b00817e3a2674e61cb40b))
* **fmt:** [#338](https://github.com/arthurmaciel/ipe-lang/issues/338) parenthesise negative literals in atom position ([#24](https://github.com/arthurmaciel/ipe-lang/issues/24)) ([3156db5](https://github.com/arthurmaciel/ipe-lang/commit/3156db56ce741dec9c95ec749bc4fdbe101a61df))
* **fmt:** a simple-reference first call arg always hugs the broken head line ([6d095cf](https://github.com/arthurmaciel/ipe-lang/commit/6d095cfc6b308e5dd16a16f54a843ba1ac7c8dbc))
* **fmt:** backward pipe `<|` breaks at the end of the left operand's line ([01a039a](https://github.com/arthurmaciel/ipe-lang/commit/01a039ac8096c6a6e92954ad2e74093a5e872b13))
* **fmt:** elm-format parity — modal layout, paren-safety, let/lambda/signature bugs ([cfa4d0b](https://github.com/arthurmaciel/ipe-lang/commit/cfa4d0bcc80666af9e95213a864ace98fee3570f))
* **fmt:** emit a trailing chain lambda bare, without wrapping parens ([eecf197](https://github.com/arthurmaciel/ipe-lang/commit/eecf197c4047448ffac350ab51a919d4bea642b4))
* **fmt:** FAJoinFirst hugs first call arg only when a block arg is present ([ae118a3](https://github.com/arthurmaciel/ipe-lang/commit/ae118a3dd8b74d7710c7886d5d67271b67aef00e))
* **fmt:** indent record-update fields one level past the brace ([ebed6f8](https://github.com/arthurmaciel/ipe-lang/commit/ebed6f8e3681f1e803d90080506927197e617a6c))
* **fmt:** keep multiline-string call args inline; break modal lambda bodies ([d1830dc](https://github.com/arthurmaciel/ipe-lang/commit/d1830dc91a047e8963ae9aae231f06ac31e26469))
* **fmt:** reflow shake_ffi_by_fn_ident signature — clears pre-existing rustfmt drift (workspace now fmt-clean) ([0b92cb0](https://github.com/arthurmaciel/ipe-lang/commit/0b92cb0df89f2fd9e8567ac04479dcfff0dc7145))
* **fmt:** two blank lines between a pre-header comment block and the module header ([1d31f00](https://github.com/arthurmaciel/ipe-lang/commit/1d31f004b4f6e3a913450c2667bf66f05465490e))
* **gate:** 13 rename-stale test + 2 real bugs surfaced by full-workspace run ([01e6fed](https://github.com/arthurmaciel/ipe-lang/commit/01e6feda1f67432c3e77acbd0bd47318994ff7b1))
* **gate:** clippy --all-targets clean (pedantic + nursery, clippy 1.92) ([53e3740](https://github.com/arthurmaciel/ipe-lang/commit/53e3740787bef25cce042e8b5d3f768bbd61cc21))
* **gate:** recover corrupted stdlib .ipe + reserved-namespace + compiled-source fixes ([6343643](https://github.com/arthurmaciel/ipe-lang/commit/634364358cd59bf905e3cbb73d39e468fa6cd656))
* **gate:** rename stragglers surfaced by full-workspace compile ([e11ced3](https://github.com/arthurmaciel/ipe-lang/commit/e11ced3c1e52d87f0a7f9587025b3f5d6447d54b))
* **gate:** resolve 6 workspace test failures — 4 stale rustfmt snapshots, 1 feature-gated dispatch test, 1 Db.Decode registry drift ([c8041ea](https://github.com/arthurmaciel/ipe-lang/commit/c8041eab1751550dac61274fbb3c412be0267d0a))
* **install:** allow backslash in INSTALL_DIR so Windows paths (D:\...) install ([#81](https://github.com/arthurmaciel/ipe-lang/issues/81)) ([1e74d8b](https://github.com/arthurmaciel/ipe-lang/commit/1e74d8bf90db22de9b04acafcd09468050a0ddbd))
* **ipe_backend:** [#233](https://github.com/arthurmaciel/ipe-lang/issues/233) Stream.stream re-wrap moves captured non-Copy strings (2x E0507) ([bcdfb03](https://github.com/arthurmaciel/ipe-lang/commit/bcdfb03ec53b2c7e4b9174978e8dc80e1a17ffc1))
* **ipe_canon:** register Sub.subscribeWebSocket in QUALIFIERS (anti-drift gap from [#210](https://github.com/arthurmaciel/ipe-lang/issues/210) WebSocket) ([6aaf010](https://github.com/arthurmaciel/ipe-lang/commit/6aaf010833ff96e13f69c0bc6d31573567853b5c))
* **ipe_lower,backend:** [#228](https://github.com/arthurmaciel/ipe-lang/issues/228) type-directed onSubmit handler classification ([3d5c1b9](https://github.com/arthurmaciel/ipe-lang/commit/3d5c1b9c9fb38430cf591a7a78fa4b00e2660fcf))
* **ipe_lower:** fold Ipe.Csv `{header,rows}` record to nominal CsvDoc ([#232](https://github.com/arthurmaciel/ipe-lang/issues/232)) ([e320dd9](https://github.com/arthurmaciel/ipe-lang/commit/e320dd939a69e16dcc95e744978c95a42ae98e38))
* **ipe:** thread on_form on two Expr::Call sites in cache.rs test IR ([889ef36](https://github.com/arthurmaciel/ipe-lang/commit/889ef36a53be23f29d814006b3c458c73d505f29))
* **ir:** bound the IR pretty-printer's recursion depth ([#282](https://github.com/arthurmaciel/ipe-lang/issues/282)) ([bad60bf](https://github.com/arthurmaciel/ipe-lang/commit/bad60bff3a08f2d77e95591efdb11b24a171dae7))
* **jwt:** seal the JWT Algorithm descriptor in Ipe.Secret ([#276](https://github.com/arthurmaciel/ipe-lang/issues/276)) ([5a609ae](https://github.com/arthurmaciel/ipe-lang/commit/5a609ae87afa70b8d752548ae70c28516a17ec22))
* **kernels:** complete required_runtime_module SSOT for PubSub kernels ([1164814](https://github.com/arthurmaciel/ipe-lang/commit/1164814474a122bbc8ae68baba5907558fa94499))
* **lsp:** don't drop the prior project layout on a transient load failure ([#278](https://github.com/arthurmaciel/ipe-lang/issues/278)) ([d7bed12](https://github.com/arthurmaciel/ipe-lang/commit/d7bed12b7ffacfcd14bb00c0a5434aab70e68d95))
* **mirror-parity:** D1 bare Css keyword constants + D2 record-alias-ctor coexistence; advance D3-18 row-poly, file rest ([a7df836](https://github.com/arthurmaciel/ipe-lang/commit/a7df8362dd7272005ce9b96fda5f7eabb707dbb7))
* **money:** kernel-wire Ipe.Money — route currency table / format / FX / allocate through guarded Money_* kernels ([8d45b03](https://github.com/arthurmaciel/ipe-lang/commit/8d45b03cb6208bb97c038ca929aa46e6bbd94c32))
* **parse:** reject space-before-dot instead of misparsing as field access ([9eec146](https://github.com/arthurmaciel/ipe-lang/commit/9eec1467c210e0c7b43471842c78a519ba327a0a))
* **playground:** correct IPE_RUNTIME_DIR path in README + resolver error to src/runtime/rust/src ([5bc57de](https://github.com/arthurmaciel/ipe-lang/commit/5bc57de8e70f58554711bd743a44b4bb22d6a3df))
* **project:** module discovery filtered .sky not .ipe (post-rename regression) ([5678e22](https://github.com/arthurmaciel/ipe-lang/commit/5678e2215522b1d06219719f25070a6a40315ef3))
* **rename:** normalize skyshop config to ipe.toml + fix stray ipe.toml/out in README usage ([#212](https://github.com/arthurmaciel/ipe-lang/issues/212)) ([5488229](https://github.com/arthurmaciel/ipe-lang/commit/54882299554c9ffc7d7f72a26db5787d60a70115))
* **rename:** update base64 expected constant for renamed 'Hello, Ipe!' plaintext ([#212](https://github.com/arthurmaciel/ipe-lang/issues/212)) ([2ffb474](https://github.com/arthurmaciel/ipe-lang/commit/2ffb474eba1736add14bde2abf56598693fa7fb9))
* **rename:** update string_reverse expected constant for renamed 'ipewasm' ([#212](https://github.com/arthurmaciel/ipe-lang/issues/212)) ([aa3c89c](https://github.com/arthurmaciel/ipe-lang/commit/aa3c89c922593d3001bbe506868cf53e7b89dba7))
* **runtime:** deliver outstanding init Cmd.perform effects before EOF terminates cli_program ([#379](https://github.com/arthurmaciel/ipe-lang/issues/379)) ([#85](https://github.com/arthurmaciel/ipe-lang/issues/85)) ([b07b42e](https://github.com/arthurmaciel/ipe-lang/commit/b07b42e6315a745285c33d87654889859af04ffa))
* **runtime:** enforce WS per-message size cap at the framing layer ([#274](https://github.com/arthurmaciel/ipe-lang/issues/274)) ([7a19539](https://github.com/arthurmaciel/ipe-lang/commit/7a1953965172ead483c737562d9c52f5c7e9817d))
* **runtime:** reap abandoned Server.Stream.stream handlers on a TTL ([#273](https://github.com/arthurmaciel/ipe-lang/issues/273)) ([4e730e9](https://github.com/arthurmaciel/ipe-lang/commit/4e730e99d54532d6b01b29f2888a8a1d7978d288))
* **runtime:** refuse to push the ingest token over cleartext HTTP ([#275](https://github.com/arthurmaciel/ipe-lang/issues/275)) ([e3338ec](https://github.com/arthurmaciel/ipe-lang/commit/e3338ec3b7aaced6c72aa0d26d577469096e1972))
* **runtime:** ssrf sibling refs crate::ssrf -&gt; super::ssrf (SEAL: emitted build) ([abb4135](https://github.com/arthurmaciel/ipe-lang/commit/abb41357e5cde0d6e7ff5516ebd6b7e889755c82))
* **runtime:** stop byte-slicing caller-derived JWT descriptor in error messages ([4a98578](https://github.com/arthurmaciel/ipe-lang/commit/4a98578e046d632760581c3bf7a64d53ac63fdb2))
* **sandbox:** skip run-jail e2e when the environment cannot establish a jail, not only when bwrap is absent ([#380](https://github.com/arthurmaciel/ipe-lang/issues/380)) ([#88](https://github.com/arthurmaciel/ipe-lang/issues/88)) ([43b2f7f](https://github.com/arthurmaciel/ipe-lang/commit/43b2f7fe2bf58c3f7af2f7dcb09736bf7cfc94ec))
* **seal-006:** route Basics.toString stringify family through IpeStringify ([9d569cf](https://github.com/arthurmaciel/ipe-lang/commit/9d569cfdacc369ab740edb7f798b9b35eab04ae4))
* **stdlib:** [#261](https://github.com/arthurmaciel/ipe-lang/issues/261) Money.add/sub/sumOf → Result Error Money (currency-mismatch now typed Err) ([969fb19](https://github.com/arthurmaciel/ipe-lang/commit/969fb19d53baabec3cc0183f2856ef415fb7af2e))
* **stdlib:** [#324](https://github.com/arthurmaciel/ipe-lang/issues/324) identify + fix 4 00-standard-libs run-time failures ([#22](https://github.com/arthurmaciel/ipe-lang/issues/22)) ([7dcbf21](https://github.com/arthurmaciel/ipe-lang/commit/7dcbf2160bde4fcdf491012a426dbe3c06d63e05))
* **sweep:** _shape_match strips {- -} block comments, not just -- lines ([0693b9f](https://github.com/arthurmaciel/ipe-lang/commit/0693b9fe52a66b6927d5e177229a7cc6be10ae6c))
* **sweep,ci:** mirror fetches upstream FIRST (local only as offline fallback); ci golden E2E compares against latest installed Sky, retire the cached expected_go oracle ([680edd1](https://github.com/arthurmaciel/ipe-lang/commit/680edd11bad095d109748fdfa67e51530da98c44))
* **sweep:** example_shape classifier -&gt; Ipe.* namespace (Live/Tui/Webview/Http) ([6099d34](https://github.com/arthurmaciel/ipe-lang/commit/6099d347a1b85b0c287aafe19d179234c09019e6))
* **sweep:** FFI-install examples SKIP, not false-RED (13-skyshop) ([ab71e37](https://github.com/arthurmaciel/ipe-lang/commit/ab71e37015f9c9b85a7d7d92e3ccf1201aca1f1c))
* **sweep:** mirror renames sky.toml -&gt; ipe.toml (Ipê's canonical manifest) ([fad2316](https://github.com/arthurmaciel/ipe-lang/commit/fad23166a9dcfc24366abd76f7057419819ca2da))
* **T2:** close SEAL-breach class — exhaustiveness over Prelude builtin ADTs, crate::-qualified top-level calls, live mod-ident gate ([aabbe0d](https://github.com/arthurmaciel/ipe-lang/commit/aabbe0d68974318ba4edbfd0a10c468ac911090e))
* **t3:** bound untrusted recursion/allocation — closes CO-FRONT-001, RT-UI-001, RT-TUI-001, RT-TUI-002 ([17151fe](https://github.com/arthurmaciel/ipe-lang/commit/17151feffa1e9c09e65560a6955df32a9a7c4d51))
* **t4:** JWT-exp NumericDate + Money allocate correctness (CO-INCR-001/002/003, RT-AUTH-001/002/003) ([4d8fc7c](https://github.com/arthurmaciel/ipe-lang/commit/4d8fc7c1f4484733d1c30a95be3aee3823be325f))
* **T5:** data/decode completeness + incremental wiring + SEAL (6 findings) ([8a4ef82](https://github.com/arthurmaciel/ipe-lang/commit/8a4ef82bb2f48ab111223bd815bb129745822465))
* **tests:** repair pre-existing base failures — env_public Module field + kernel-resolution allowlist ([bf3ca58](https://github.com/arthurmaciel/ipe-lang/commit/bf3ca58722998b99b96a5be3b74d710a042161f4))
* **wasm:** M1 gate WebSocket Sub-tier substitute — onOpen/onMessage/onClose/onError live in a browser ([#286](https://github.com/arthurmaciel/ipe-lang/issues/286)) ([bc57e10](https://github.com/arthurmaciel/ipe-lang/commit/bc57e10930cd2f892fbdd8b3bda31d23d685b8e5))
* **watch:** retry the rebuild cycle after a transient resolve failure ([#279](https://github.com/arthurmaciel/ipe-lang/issues/279)) ([3dc1000](https://github.com/arthurmaciel/ipe-lang/commit/3dc100051796b0c3a3a6824ac4fbfc7f05f49b2b))
* **watch:** scope the tests/ watch rule to the root-level directory only ([#280](https://github.com/arthurmaciel/ipe-lang/issues/280)) ([554c90d](https://github.com/arthurmaciel/ipe-lang/commit/554c90d7ca090d26dd243f03cec315c7f373f9d1))

## [0.1.14](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.13...ipe-v0.1.14) (2026-07-22)


### Bug Fixes

* **ci:** install jail primitives for static e2e + pin goldens to LF ([#86](https://github.com/arthurmaciel/ipe-lang/issues/86)) ([dbdd2a0](https://github.com/arthurmaciel/ipe-lang/commit/dbdd2a0bdf477b27f10e0bf6caed149a0f9ada1b))
* **sandbox:** skip run-jail e2e when the environment cannot establish a jail, not only when bwrap is absent ([#380](https://github.com/arthurmaciel/ipe-lang/issues/380)) ([#88](https://github.com/arthurmaciel/ipe-lang/issues/88)) ([43b2f7f](https://github.com/arthurmaciel/ipe-lang/commit/43b2f7fe2bf58c3f7af2f7dcb09736bf7cfc94ec))

## [0.1.13](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.12...ipe-v0.1.13) (2026-07-22)


### Features

* **examples:** bring composite examples 36-38 into sweep scope ([#377](https://github.com/arthurmaciel/ipe-lang/issues/377)) ([#83](https://github.com/arthurmaciel/ipe-lang/issues/83)) ([6f6193a](https://github.com/arthurmaciel/ipe-lang/commit/6f6193a9af83587b69b41fba2d874d286bb25e40))
* **security:** [#371](https://github.com/arthurmaciel/ipe-lang/issues/371) runtime capability sandbox + admit-and-isolate Tier 2 wrappers ([#82](https://github.com/arthurmaciel/ipe-lang/issues/82)) ([04214e5](https://github.com/arthurmaciel/ipe-lang/commit/04214e5ab0868dace57586c4c254fc7f8f746ee7))


### Bug Fixes

* **runtime:** deliver outstanding init Cmd.perform effects before EOF terminates cli_program ([#379](https://github.com/arthurmaciel/ipe-lang/issues/379)) ([#85](https://github.com/arthurmaciel/ipe-lang/issues/85)) ([b07b42e](https://github.com/arthurmaciel/ipe-lang/commit/b07b42e6315a745285c33d87654889859af04ffa))

## [0.1.12](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.11...ipe-v0.1.12) (2026-07-22)


### Features

* **cli:** CLI-UI single-source-of-truth (style module) + installer polish + SSOT principle ([#75](https://github.com/arthurmaciel/ipe-lang/issues/75)) ([720e2c6](https://github.com/arthurmaciel/ipe-lang/commit/720e2c6b1304d10084c7baa3eb690e70845e5b16))
* **cli:** human-first output model — --plain/--json, gutter, error-shows-help, Package authoring section ([#78](https://github.com/arthurmaciel/ipe-lang/issues/78)) ([ea01f7f](https://github.com/arthurmaciel/ipe-lang/commit/ea01f7f3530646557c3916149d47c720828ec2e3))
* **examples:** port go-ffi examples to Ipê + Rust crates (7 examples) ([#80](https://github.com/arthurmaciel/ipe-lang/issues/80)) ([c1f3bf7](https://github.com/arthurmaciel/ipe-lang/commit/c1f3bf782b2f78274d6f5db3297cb5086d196d15))


### Bug Fixes

* **install:** allow backslash in INSTALL_DIR so Windows paths (D:\...) install ([#81](https://github.com/arthurmaciel/ipe-lang/issues/81)) ([1e74d8b](https://github.com/arthurmaciel/ipe-lang/commit/1e74d8bf90db22de9b04acafcd09468050a0ddbd))

## [0.1.11](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.10...ipe-v0.1.11) (2026-07-21)


### Features

* **ffi:** [#317](https://github.com/arthurmaciel/ipe-lang/issues/317)+[#326](https://github.com/arthurmaciel/ipe-lang/issues/326) auto-binding coverage — bundle-generics, dyn-Fn systems, multi-result tuples ([#72](https://github.com/arthurmaciel/ipe-lang/issues/72)) ([572ddbd](https://github.com/arthurmaciel/ipe-lang/commit/572ddbdd1ada659dd04e4920b619786b8dbf781a))
* **ffi:** [#365](https://github.com/arthurmaciel/ipe-lang/issues/365) Tier 2 capability inference + fail-closed enforcement ([#71](https://github.com/arthurmaciel/ipe-lang/issues/71)) ([965aa15](https://github.com/arthurmaciel/ipe-lang/commit/965aa158a2616ad47c7e3441ad3ee9f83b989267))
* **ffi:** [#366](https://github.com/arthurmaciel/ipe-lang/issues/366) Tier 2 #[ipe::provide] trait-impl escape hatch ([#69](https://github.com/arthurmaciel/ipe-lang/issues/69)) ([2cc5114](https://github.com/arthurmaciel/ipe-lang/commit/2cc5114470177a84a6c7b67d4ffa96b90c5222db))
* **ffi:** [#369](https://github.com/arthurmaciel/ipe-lang/issues/369) closure-&gt;run handoff — drive foreign loops with Ipê closures ([#70](https://github.com/arthurmaciel/ipe-lang/issues/70)) ([8c4b662](https://github.com/arthurmaciel/ipe-lang/commit/8c4b6627baa46a7aeb1df4ebb462fd76599b612e))
* **pkg:** [#368](https://github.com/arthurmaciel/ipe-lang/issues/368) SP4 Tier-1 package gate + ipe package audit ([#66](https://github.com/arthurmaciel/ipe-lang/issues/66)) ([5838ff5](https://github.com/arthurmaciel/ipe-lang/commit/5838ff5de03157dd07bad5a3bc3f846e0fb8e1b9))

## [0.1.10](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.9...ipe-v0.1.10) (2026-07-21)


### Features

* **ffi:** [#364](https://github.com/arthurmaciel/ipe-lang/issues/364) Tier 2 phases 1-3 — bind author-supplied Rust wrapper crates ([#62](https://github.com/arthurmaciel/ipe-lang/issues/62)) ([28618f7](https://github.com/arthurmaciel/ipe-lang/commit/28618f7a7536b4c293ae6ddc65e02e2092e1114c))

## [0.1.9](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.8...ipe-v0.1.9) (2026-07-21)


### Features

* **security:** [#359](https://github.com/arthurmaciel/ipe-lang/issues/359) drive the abrupt-failure ledger toward zero ([#58](https://github.com/arthurmaciel/ipe-lang/issues/58)) ([ba4c309](https://github.com/arthurmaciel/ipe-lang/commit/ba4c3091ec33785b975d610d00a7d29cff7b5442))


### Bug Fixes

* **ffi:** [#363](https://github.com/arthurmaciel/ipe-lang/issues/363) refuse recursive provide types at decode (SEAL) ([#61](https://github.com/arthurmaciel/ipe-lang/issues/61)) ([51bc01d](https://github.com/arthurmaciel/ipe-lang/commit/51bc01d0e6895a375f4b638e00beee2ba8438710))

## [0.1.8](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.7...ipe-v0.1.8) (2026-07-21)


### Features

* **ffi:** [#354](https://github.com/arthurmaciel/ipe-lang/issues/354) opaque struct fields / enum payloads ([#57](https://github.com/arthurmaciel/ipe-lang/issues/57)) ([41af8c7](https://github.com/arthurmaciel/ipe-lang/commit/41af8c77b55e55422ab08c76a8db91ae84595c0a))
* **ffi:** async-returning provide.closure ([#55](https://github.com/arthurmaciel/ipe-lang/issues/55)) ([8bce55b](https://github.com/arthurmaciel/ipe-lang/commit/8bce55badf5c678df9e4066fa0a78e0c75dc28b2))
* **security:** token-scanner gate + clippy hardening for authored abrupt-failure ([#54](https://github.com/arthurmaciel/ipe-lang/issues/54)) ([843a17b](https://github.com/arthurmaciel/ipe-lang/commit/843a17baedb626ed4ec90bec2ad02e14fb61a67b))

## [0.1.7](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.6...ipe-v0.1.7) (2026-07-21)


### Features

* **cli:** aligned --help column + consent-based installer PATH setup ([#50](https://github.com/arthurmaciel/ipe-lang/issues/50)) ([fb98598](https://github.com/arthurmaciel/ipe-lang/commit/fb98598988dc6fd877ea5fc9e329c22458c460af))


### Bug Fixes

* **ci:** install wry/tao Linux link deps in e2e job to clear SEAL breach ([#51](https://github.com/arthurmaciel/ipe-lang/issues/51)) ([4378a36](https://github.com/arthurmaciel/ipe-lang/commit/4378a36a54940fc223eb2200fa3a8854f3a071c3))

## [0.1.6](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.5...ipe-v0.1.6) (2026-07-21)


### Features

* **ffi:** [#353](https://github.com/arthurmaciel/ipe-lang/issues/353) provide.closure opaque returns ([#47](https://github.com/arthurmaciel/ipe-lang/issues/47)) ([bc86028](https://github.com/arthurmaciel/ipe-lang/commit/bc86028122e36aee235f36877a1f46191c07d397))
* **stdlib:** [#342](https://github.com/arthurmaciel/ipe-lang/issues/342) Task + decoder combinators ([#49](https://github.com/arthurmaciel/ipe-lang/issues/49)) ([1fc9149](https://github.com/arthurmaciel/ipe-lang/commit/1fc91496758dfa4ac63dd02f2018243b111264b3))

## [0.1.5](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.4...ipe-v0.1.5) (2026-07-21)


### Features

* **ffi:** [#352](https://github.com/arthurmaciel/ipe-lang/issues/352) provide.* Ipê-side forwarder plumbing ([#46](https://github.com/arthurmaciel/ipe-lang/issues/46)) ([cc9718b](https://github.com/arthurmaciel/ipe-lang/commit/cc9718b34d7e26a562797466d0b9fc2bcd07653b))
* **stdlib:** Cmd.map / Sub.map ([#44](https://github.com/arthurmaciel/ipe-lang/issues/44)) ([eca501b](https://github.com/arthurmaciel/ipe-lang/commit/eca501b9265720c1970b290ee67df220e935fbdf))

## [0.1.4](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.3...ipe-v0.1.4) (2026-07-21)


### Features

* **backend:** [#315](https://github.com/arthurmaciel/ipe-lang/issues/315) port IpeStringify format! emitters to native Doc rendering ([#35](https://github.com/arthurmaciel/ipe-lang/issues/35)) ([ce4a766](https://github.com/arthurmaciel/ipe-lang/commit/ce4a7660796ca3e6a48257e5116f17ab2f57f7ff))
* **backend:** [#315](https://github.com/arthurmaciel/ipe-lang/issues/315) wire native Doc emitter into production emit_func ([#40](https://github.com/arthurmaciel/ipe-lang/issues/40)) ([f20e430](https://github.com/arthurmaciel/ipe-lang/commit/f20e430fec9a0fb20a3c40ca6d807bc27c01de23))
* **ffi:** [#347](https://github.com/arthurmaciel/ipe-lang/issues/347) sync closure adapter ([rust.provide.closure]) ([#36](https://github.com/arthurmaciel/ipe-lang/issues/36)) ([72cfd04](https://github.com/arthurmaciel/ipe-lang/commit/72cfd041b1c87a29e3415f4590fdf638b507e605))
* **ffi:** [#350](https://github.com/arthurmaciel/ipe-lang/issues/350) closure-manifest glue + [#348](https://github.com/arthurmaciel/ipe-lang/issues/348) struct-with-trait-impl ([#38](https://github.com/arthurmaciel/ipe-lang/issues/38)) ([ade2673](https://github.com/arthurmaciel/ipe-lang/commit/ade2673adffb0c3d118384f57e06b5b5bc9b06a1))
* **ffi:** provide.enum (P4) + Debug derive — Iced binding spike ([#42](https://github.com/arthurmaciel/ipe-lang/issues/42)) ([eef982a](https://github.com/arthurmaciel/ipe-lang/commit/eef982a8e8d6a499c4d9ce38f19200b25d2c43b4))
* **stdlib:** [#339](https://github.com/arthurmaciel/ipe-lang/issues/339) pure elm/core fills (List/Dict/Set/Result/Char/String) ([#43](https://github.com/arthurmaciel/ipe-lang/issues/43)) ([37da719](https://github.com/arthurmaciel/ipe-lang/commit/37da7192da96bf9ca651bc594ded7a4482402145))

## [0.1.3](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.2...ipe-v0.1.3) (2026-07-21)


### Features

* **backend:** [#315](https://github.com/arthurmaciel/ipe-lang/issues/315) native emitter sweep to 0 divergences (cutover gated by non-body content) ([#32](https://github.com/arthurmaciel/ipe-lang/issues/32)) ([5581976](https://github.com/arthurmaciel/ipe-lang/commit/558197635e215d68beff405b67aacc7cd3e31760))
* **cli:** declutter ipe help (soft yellow, no optional-arg overview, bug-report footer) ([#15](https://github.com/arthurmaciel/ipe-lang/issues/15)) ([2f1b6dd](https://github.com/arthurmaciel/ipe-lang/commit/2f1b6dd85434decc6b20518cad82f4b7673c619b))
* **cli:** typed arg parsing — invalid optional-flag combinations unrepresentable + exhaustive tests ([#34](https://github.com/arthurmaciel/ipe-lang/issues/34)) ([783e922](https://github.com/arthurmaciel/ipe-lang/commit/783e92212020b6d6c2bde9dd1c11564be9790af5))
* **install:** fix curl (23), add spinner/percent/ETA + friendly branded messages ([#28](https://github.com/arthurmaciel/ipe-lang/issues/28)) ([b27654d](https://github.com/arthurmaciel/ipe-lang/commit/b27654d0ed7f3bdb72bec2772c23db14245f13ab))


### Bug Fixes

* **cli:** Usage error strings match the redesigned help ([#23](https://github.com/arthurmaciel/ipe-lang/issues/23)) ([c0872ee](https://github.com/arthurmaciel/ipe-lang/commit/c0872ee57b08eae365f4ae14be2fc5a96d7718db))
* examples-sweep 26/29/31 build+run green ([#33](https://github.com/arthurmaciel/ipe-lang/issues/33)) ([26c0c11](https://github.com/arthurmaciel/ipe-lang/commit/26c0c1167d66e5a266307e106783bc45d6ff5fc8))
* **ffi:** [#326](https://github.com/arthurmaciel/ipe-lang/issues/326) admit coercible multi-result tuples for non-borrow-reader methods ([#21](https://github.com/arthurmaciel/ipe-lang/issues/21)) ([f37fe03](https://github.com/arthurmaciel/ipe-lang/commit/f37fe03f8e775b68b5ee5ddfb8dac3c3e167f52c))
* **fmt:** [#338](https://github.com/arthurmaciel/ipe-lang/issues/338) parenthesise negative literals in atom position ([#24](https://github.com/arthurmaciel/ipe-lang/issues/24)) ([3156db5](https://github.com/arthurmaciel/ipe-lang/commit/3156db56ce741dec9c95ec749bc4fdbe101a61df))
* **stdlib:** [#324](https://github.com/arthurmaciel/ipe-lang/issues/324) identify + fix 4 00-standard-libs run-time failures ([#22](https://github.com/arthurmaciel/ipe-lang/issues/22)) ([7dcbf21](https://github.com/arthurmaciel/ipe-lang/commit/7dcbf2160bde4fcdf491012a426dbe3c06d63e05))

## [0.1.2](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.1...ipe-v0.1.2) (2026-07-21)


### Features

* [#337](https://github.com/arthurmaciel/ipe-lang/issues/337) row-polymorphic record annotations { r | f : T } ([#14](https://github.com/arthurmaciel/ipe-lang/issues/14)) ([d0c2514](https://github.com/arthurmaciel/ipe-lang/commit/d0c2514f1aa80ce22161a7fbcdabe3c8ca77eb78))
* **backend:** [#315](https://github.com/arthurmaciel/ipe-lang/issues/315) recursive-Shape combine + chain glue — sweep 9→5 ([#16](https://github.com/arthurmaciel/ipe-lang/issues/16)) ([29ff276](https://github.com/arthurmaciel/ipe-lang/commit/29ff2761462b48145a9794d875287bff9d7c894a))


### Bug Fixes

* **explain:** github issue links + trailing newline ([#18](https://github.com/arthurmaciel/ipe-lang/issues/18)) ([f8fbc6f](https://github.com/arthurmaciel/ipe-lang/commit/f8fbc6fa78359c0461a9739d0a5b41243a739a02))

## [0.1.1](https://github.com/arthurmaciel/ipe-lang/compare/ipe-v0.1.0...ipe-v0.1.1) (2026-07-21)


### Features

* [#337](https://github.com/arthurmaciel/ipe-lang/issues/337) row polymorphism + first-class accessors ([#10](https://github.com/arthurmaciel/ipe-lang/issues/10)) ([90af7a5](https://github.com/arthurmaciel/ipe-lang/commit/90af7a5f16bf10028dd4220aa18a1f212504b38d))
* **#210:** seal Ipe.Email — Email.send + EmailMessage/EmailProvider fold ([e1486e4](https://github.com/arthurmaciel/ipe-lang/commit/e1486e4768ad2737b30f53d9d953dcb15d9763d0))
* **backend:** [#315](https://github.com/arthurmaciel/ipe-lang/issues/315) call-arg combining render primitive + fn_call_width ([#12](https://github.com/arthurmaciel/ipe-lang/issues/12)) ([becfd89](https://github.com/arthurmaciel/ipe-lang/commit/becfd891a6626476e5d4fc2a531da7a3e9636383))
* **backend:** [#315](https://github.com/arthurmaciel/ipe-lang/issues/315) leaf-arm + statement emitters toward cutover ([#9](https://github.com/arthurmaciel/ipe-lang/issues/9)) ([a5bb75e](https://github.com/arthurmaciel/ipe-lang/commit/a5bb75ee22d7ddf5b697b8574a6773f324c295e5))
* **backend:** assignment-RHS-break Doc token for the let-value layout axis ([3d07e66](https://github.com/arthurmaciel/ipe-lang/commit/3d07e66caafd881205f0a486f5017f856db94b69))
* **backend:** native Doc emitter for Expr::Match via MatchArmTail ([0e4b182](https://github.com/arthurmaciel/ipe-lang/commit/0e4b182317cf742dfb1e520d15c16e029f863de5))
* **backend:** native Doc emitters for Lambda/SharedLambda + immediately-applied Apply ([740ba27](https://github.com/arthurmaciel/ipe-lang/commit/740ba2772ef25e38c34b52fcb27f11dd552f2682))
* **backend:** native Rust formatter Doc IR + renderer (P0) ([a675f3f](https://github.com/arthurmaciel/ipe-lang/commit/a675f3f484ab70a6c106dd5a527b7c5eb50aa037))
* **backend:** P1 Doc-building emit path — binop-chain builder + SEAL property test ([f7dbaeb](https://github.com/arthurmaciel/ipe-lang/commit/f7dbaeba919bd41b3155aa8a78047470a049107c))
* **backend:** real flat-vs-break Group in native renderer + structured if builder ([ff902e7](https://github.com/arthurmaciel/ipe-lang/commit/ff902e753ce2dc4d20b2f7d86a0c229c5943be2d))
* **backend:** SEAL-visible BraceBody Doc token for rustfmt brace add/strip ([e562ac9](https://github.com/arthurmaciel/ipe-lang/commit/e562ac9912db8a429bb9d86921b595bae24a9fa7))
* **backend:** structured Ctor Doc builder (payload + runtime-enum) ([aadb94c](https://github.com/arthurmaciel/ipe-lang/commit/aadb94c32ff32ead5790384ec0c5c31786c1f2b4))
* **backend:** structured delimited-list Doc builders + break-conditional trailing comma ([bcdc2c7](https://github.com/arthurmaciel/ipe-lang/commit/bcdc2c7f141b693c0c549f7ecfcde245c49dbb1a))
* **backend:** structured Destructure-block Doc builder ([c8c0e46](https://github.com/arthurmaciel/ipe-lang/commit/c8c0e46ff948a63bc0458b1e37a1ed095b2ca85b))
* **backend:** structured general-apply Doc builder ([059e4e5](https://github.com/arthurmaciel/ipe-lang/commit/059e4e52c16bd93aa5b83429c249c82b24013837))
* **backend:** structured generic call-tail Doc builder ([0fc9554](https://github.com/arthurmaciel/ipe-lang/commit/0fc9554c2a1a91f490e058f534eda6b1bb282d82))
* **backend:** structured let-block Doc builder ([7e7c274](https://github.com/arthurmaciel/ipe-lang/commit/7e7c274ee1ad8966bb7b729f9257b7f5eb8343b0))
* **backend:** structured record-literal Doc builder ([7cd66ca](https://github.com/arthurmaciel/ipe-lang/commit/7cd66cadfd5083030ab13dbfcf0c32ac6d65292f))
* **backend:** structured record-update Doc builder ([fb00c59](https://github.com/arthurmaciel/ipe-lang/commit/fb00c59105e47d565b5be4c2e14a7c026ee342db))
* **backend:** structured sync task-seq Doc builder ([87caa50](https://github.com/arthurmaciel/ipe-lang/commit/87caa50abafbd37590fc3cfafbe99588ac245c32))
* **ci:** examples-sweep bot-commits the refreshed upstream mirror ([5b71393](https://github.com/arthurmaciel/ipe-lang/commit/5b7139328c222d078ac0b0d23f13e4690e59bfd2))
* **ci:** live upstream-Sky parity comparison (retires the cached oracle) ([2404d2e](https://github.com/arthurmaciel/ipe-lang/commit/2404d2ec2de99ff9b985ef6b9353d203196e70cf))
* **cli:** add `ipe version` (also --version / -V) ([f504895](https://github.com/arthurmaciel/ipe-lang/commit/f5048959458057b210c9372c67a341b47464c064))
* **cli:** capabilities acceptance over examples + README ([333a3b4](https://github.com/arthurmaciel/ipe-lang/commit/333a3b42b98f27c66dbf07e2d5cec65e884983e7))
* **cli:** default entry for build/run/watch in project directories ([ebe88c7](https://github.com/arthurmaciel/ipe-lang/commit/ebe88c765479c391a4a467f4d76b12d1e3cc5735))
* **cli:** ipe capabilities report + declared-set verify ([7eb4877](https://github.com/arthurmaciel/ipe-lang/commit/7eb48774be0c008278510ebeb96aa80b2e1ce81c))
* **cli:** ipe fmt — elm-format-compatible source formatter ([8e3cbef](https://github.com/arthurmaciel/ipe-lang/commit/8e3cbefe6969d990dea0dcfa9a3c07d5547986fe))
* **cli:** ipe init scaffolds an Ipe.Live counter project ([60277f6](https://github.com/arthurmaciel/ipe-lang/commit/60277f64e91a8dade4ca8c898740a47e9b2c8ff0))
* **cli:** ipe run --static — shared static-flag parser + plan resolver across build/run; binary located via cargo metadata target_directory (honours CARGO_TARGET_DIR / user target-dir pins) ([5e25b11](https://github.com/arthurmaciel/ipe-lang/commit/5e25b11ddd4b452eed3a97446477b62912915448))
* **cli:** sectioned, coloured top-level help and per-command --help ([976dc92](https://github.com/arthurmaciel/ipe-lang/commit/976dc92030706e38005e358f6083fb5a2177ba41))
* **cli:** SP2 — ipe rust group + ipe.toml schema ([#4](https://github.com/arthurmaciel/ipe-lang/issues/4)) ([364b213](https://github.com/arthurmaciel/ipe-lang/commit/364b213fc5dd69b9a95d17e5db8147ddf0397d69))
* **cli:** SP3 — index resolver + lockfile + ipe add ([#8](https://github.com/arthurmaciel/ipe-lang/issues/8)) ([c358c2a](https://github.com/arthurmaciel/ipe-lang/commit/c358c2af27271ed2b766c0f888eb537fa8251bad))
* **cli:** SP5 — ipe diff + enforced semver ([#11](https://github.com/arthurmaciel/ipe-lang/issues/11)) ([038ad53](https://github.com/arthurmaciel/ipe-lang/commit/038ad534d0b65ab74f57ed80e1c0b030547e7b44))
* **emit:** post-emit rustfmt pass (fail-closed) so emitted Rust is rustfmt-clean; regenerate 73 goldens to canonical form ([3f624bc](https://github.com/arthurmaciel/ipe-lang/commit/3f624bc8a246e2eaf7a2ec541cb4cd050d8aaa7f))
* **examples:** 13-skyshop transpose in progress — Db+Auth de-shimmed onto real SDKs, 8-crate cache checked in ([41aeca9](https://github.com/arthurmaciel/ipe-lang/commit/41aeca91c1920133fda3b629e32eea29526c09e3))
* **examples:** add examples/sky/manifest.toml — Sky→Ipe patch registry ([#299](https://github.com/arthurmaciel/ipe-lang/issues/299)) ([60764be](https://github.com/arthurmaciel/ipe-lang/commit/60764bebbc9d183f054e492f54f46e089dfe1cf0))
* **examples:** track the upstream Sky example mirror (42 examples, source-only) ([ee24e09](https://github.com/arthurmaciel/ipe-lang/commit/ee24e0987162f83520eb1e7f823abda672d546f4))
* **ffi-inspector:** param-shape admission — conversion-bound nominal targets (identity + From&lt;String&gt; preference), enum-level non_exhaustive ctor restoration, Clone-enum field accessors ([0c7e9d2](https://github.com/arthurmaciel/ipe-lang/commit/0c7e9d28594b19b3ac95a9ed72eceded2b9d5dbd))
* **ffi-inspector:** resumable manifest inspection — stable probe root + cross-crate proof-map checkpoint ([989ee3b](https://github.com/arthurmaciel/ipe-lang/commit/989ee3bd35091840062b910f9929e0a3973b9a26))
* **ffi-inspector:** stripe-send — doc-hidden surfacing + cross-crate Send proof (3 of 4 walls) ([8a2f590](https://github.com/arthurmaciel/ipe-lang/commit/8a2f5902ffec29c2b8487934bd9ce842650083c2))
* **ffi-inspector:** stripe-send F2 — cross-crate proven-public Output paths (GLOBAL_XC_PUBLIC_PATHS) ([3146360](https://github.com/arthurmaciel/ipe-lang/commit/314636064522c0e887470a520963df966a1569d2))
* **ffi-inspector:** stripe-send F2 (cont.) — resolve cross-crate send Output in type_to_typeref ([a29b0d3](https://github.com/arthurmaciel/ipe-lang/commit/a29b0d30903717cd3b06f41962ba8a49d4a73c70))
* **ffi-inspector:** stripe-send W4 — return-nameability by defining-type identity (4th wall) ([1fefa83](https://github.com/arthurmaciel/ipe-lang/commit/1fefa83f99f6c129552704695019674120bb0982))
* **ffi:** async wrappers arm AbortOnDrop + route JoinError through ipe_error_from_foreign (Δ1/Δ2) ([cde8092](https://github.com/arthurmaciel/ipe-lang/commit/cde809246b7feeef8acfb5d3d53f28340bfda23f))
* **ffi:** async-SDK consumer path — closed-instance synthesis, alias fold, used-set forwarder DCE; firestore 0.49 bound shim-free E2E ([d5327f2](https://github.com/arthurmaciel/ipe-lang/commit/d5327f276d727792c2ecec4fc2f56e294bcfb4e5))
* **ffi:** borrow-thread &self/&mut self FFI readers through the result ([9b1f4ce](https://github.com/arthurmaciel/ipe-lang/commit/9b1f4ce6bd936b6fb4bb83b2998bcaf38d0f63c2))
* **ffi:** checked fallible setters for narrowing integer fields — try_from + typed Err replaces the setter drop (no silent truncation; f32/containers stay dropped) ([af035d3](https://github.com/arthurmaciel/ipe-lang/commit/af035d3ded91ab211fd177fc287189960363a4ef))
* **ffi:** firebase-bind shim-free — rs-firebase-admin-sdk 4.3 SEAL green (verify chain live) ([06f334b](https://github.com/arthurmaciel/ipe-lang/commit/06f334bd68899f582987da9501ccc458ee406756))
* **ffi:** foreign-type-one-home — defid-keyed nominal unification across the installed-crate catalog ([857eb62](https://github.com/arthurmaciel/ipe-lang/commit/857eb62acf482f1b3c1c38b8a0c8317f41d8fc4c))
* **ffi:** one-shot manifest install + submodule Ipe-head path map + prerelease pin pass-through ([46f4e23](https://github.com/arthurmaciel/ipe-lang/commit/46f4e23af417ed9c06d0382a97859f078311e2bb))
* **ffi:** pkg.json is the sole catalog source — load re-derives the full consumer view ([9154383](https://github.com/arthurmaciel/ipe-lang/commit/915438347af734a8bb9b278b6b9cb76eac08f6bb))
* **ffi:** stripe-send W4 verified end-to-end + multi-crate dep-line unification ([1a20c74](https://github.com/arthurmaciel/ipe-lang/commit/1a20c746b27966b6b453157d715c51864744791d))
* **ffi:** version-pinned crate specs + feature/pin propagation through ipe add/install ([0d9c433](https://github.com/arthurmaciel/ipe-lang/commit/0d9c4336626d1855fce90b513d10d2430f34df32))
* **ipe watch:** SIGTERM-to-shutdown forwarder, run()-only, + 3 proof tests ([a996933](https://github.com/arthurmaciel/ipe-lang/commit/a996933cd8d385589da9dcb20f1578aaf83094e9))
* **ipe_backend_rust:** emit the Model schema tag into Live entry calls (1B.5) ([8331b01](https://github.com/arthurmaciel/ipe-lang/commit/8331b011f545a8428ae048b0a89e88ae6f490a70))
* **ipe_backend_rust:** Model schema structural hash — records (Stage A, 1A.1-1A.2) ([ff7f4c3](https://github.com/arthurmaciel/ipe-lang/commit/ff7f4c3411fd1658672ce42637fb1f8809ce5030))
* **ipe_backend_rust:** schema hash — fuel bound + exhaustiveness (1A.4, Stage A complete) ([ecfca2c](https://github.com/arthurmaciel/ipe-lang/commit/ecfca2c71fba683580258f0a2ac94041e34adb92))
* **ipe_backend_rust:** schema hash enum arm — nominal identity + variant names at position (1A.3) ([a264826](https://github.com/arthurmaciel/ipe-lang/commit/a264826deed73402f9d15b4f3c8bbaf58a815e62))
* **ipe_ir:** carrier_is_clone — single carrier-Clone authority ([3649167](https://github.com/arthurmaciel/ipe-lang/commit/364916715a7d5bdbe11536bc8cc7884e13038371))
* **ipe_lower:** [#221](https://github.com/arthurmaciel/ipe-lang/issues/221) fn-value Arc-carrier promotion on the lowered IR (position-typed, replaces the canon pre-pass) ([cda33ca](https://github.com/arthurmaciel/ipe-lang/commit/cda33ca7954dfb7cc105289cd50150ff394a25e5))
* **ipe_lower:** per-let Arc-promotion look-ahead for depth-1 fn captures ([e113899](https://github.com/arthurmaciel/ipe-lang/commit/e1138991c970821d9ec7e51a4f0774256682609c))
* **ipe_watch:** safe SIGTERM listener module (signal.rs) ([9dbbc9a](https://github.com/arthurmaciel/ipe-lang/commit/9dbbc9a97020a5311637225687d59989f6762b55))
* **kernels:** add Database capability; reclassify Db-family kernels ([5ec4ccd](https://github.com/arthurmaciel/ipe-lang/commit/5ec4ccde5c3c897cf785b84411901b4885146b64))
* **kernels:** per-kernel capability tag + Capability vocabulary ([2fd7401](https://github.com/arthurmaciel/ipe-lang/commit/2fd74017f2b80c97af362cdbd31a6e118d05b20e))
* **lower:** whole-program capability inference ([5a48b73](https://github.com/arthurmaciel/ipe-lang/commit/5a48b734ffcc31015c2caffaf267252db9b6e6d7))
* **lsp,db:** per-module typecheck_module query SEAM + migrate home-keyed handlers ([570760e](https://github.com/arthurmaciel/ipe-lang/commit/570760e20c2568b3acecf783f5eb1723a40175ae))
* **lsp:** [#295](https://github.com/arthurmaciel/ipe-lang/issues/295) document formatting + rangeFormatting ([71f81b6](https://github.com/arthurmaciel/ipe-lang/commit/71f81b6b429e649f5f655d42b56e756b5f571a10))
* **lsp:** [#296](https://github.com/arthurmaciel/ipe-lang/issues/296) code actions — diagnostic-driven quick-fixes ([3177844](https://github.com/arthurmaciel/ipe-lang/commit/3177844f6a33861cd31a0a46ebbc1bd7dedc3a4f))
* **lsp:** [#297](https://github.com/arthurmaciel/ipe-lang/issues/297) semantic tokens full — 10-type legend over the parse AST ([7ef7aa2](https://github.com/arthurmaciel/ipe-lang/commit/7ef7aa24619d6599d558d0a51908044f0e3e0d07))
* **lsp:** [#298](https://github.com/arthurmaciel/ipe-lang/issues/298) signature help + inlay hints ([8e5b3dc](https://github.com/arthurmaciel/ipe-lang/commit/8e5b3dc68619b2696ef9c2175fdb794778b06566))
* **lsp:** completion, go-to-definition, find-references, rename ([926bb34](https://github.com/arthurmaciel/ipe-lang/commit/926bb34f3008e8f2a755243f3688f027432dba4b))
* **lsp:** document links + folding ranges ([62e9141](https://github.com/arthurmaciel/ipe-lang/commit/62e9141e07b49e496153bdec2addf3880098a7ea))
* **lsp:** ipe lsp server — live diagnostics, hover, document symbols over the salsa graph ([64b684e](https://github.com/arthurmaciel/ipe-lang/commit/64b684e7a4a8aa014a7023fe4786626ba494f0a6))
* **lsp:** type-directed completion via additive ExpectedTypes solver sidecar ([d1b475e](https://github.com/arthurmaciel/ipe-lang/commit/d1b475e27066286828d09a79501ef1588065a03a))
* **lsp:** wire [#295](https://github.com/arthurmaciel/ipe-lang/issues/295)-298 into server — capabilities + request handlers ([f0b5046](https://github.com/arthurmaciel/ipe-lang/commit/f0b5046600cbacbf97c65c8462be38fef74b8825))
* **runtime live:** checkpoint wire format -&gt; base64(tag ++ bincode) (Stage C 1C.2-1C.4) ([100994a](https://github.com/arthurmaciel/ipe-lang/commit/100994ad4a66ba77eaed9c237ab73d9af61b7c37))
* **runtime live:** Model schema-tag column gates session-checkpoint reuse (H24, Stage B 1B.1-1B.4) ([e19a723](https://github.com/arthurmaciel/ipe-lang/commit/e19a72321e2afb394ed014c92cc7d0b601bfbdce))
* **runtime live:** proactive event: reload SSE frame on dev shutdown (Problem 2) ([1f77e2c](https://github.com/arthurmaciel/ipe-lang/commit/1f77e2cf785614b567982141fdc993ed8b5ba58e))
* **runtime:** process-global tokio runtime for block_on + AbortOnDrop cancel guard (async-FFI bridge H1/Δ1 primitives) ([e901c2b](https://github.com/arthurmaciel/ipe-lang/commit/e901c2bf2a586ac6e3861231c2ad5e0d6d8cde57))
* **static:** [#244](https://github.com/arthurmaciel/ipe-lang/issues/244) add aarch64-unknown-linux-musl static target (config + CI) ([297927a](https://github.com/arthurmaciel/ipe-lang/commit/297927aef8385db05b66492b15a4c489f90a681b))
* **static:** pin rust-lld self-contained for aarch64-musl — portable static cross-build (no musl-cross-gcc) ([2935170](https://github.com/arthurmaciel/ipe-lang/commit/2935170bb92e1fca5f1917daa5b4a15c44031d38))
* **sweep:** fail loud on unpatched new upstream examples + self-regression docs ([#300](https://github.com/arthurmaciel/ipe-lang/issues/300)) ([f60bdb5](https://github.com/arthurmaciel/ipe-lang/commit/f60bdb50cc045b75664ba10d0b4ab520fc696ebe))
* **sweep:** IPE_SWEEP_STATIC=1 — per-example --static musl build (CWD = emitted crate dir), ldd-asserted static-ness, static-binary RUN, webview typed-refusal assertion ([d177666](https://github.com/arthurmaciel/ipe-lang/commit/d177666721ad4a7c6db89810986498cd5a7b0869))
* **sweep:** Ipê-only upstream-mirror sweep, retire the Go-oracle equivalence infra ([7773a7f](https://github.com/arthurmaciel/ipe-lang/commit/7773a7f9c12a6eed634dfe00251aebcb32933c95))
* **types,db:** per-module scoped typecheck behind typed interfaces ([6991b4c](https://github.com/arthurmaciel/ipe-lang/commit/6991b4c9f79e3b3987e641613020c2005db5f9c8))
* **wasm:** browser TEA sink + target-neutral dom re-home ([4d0a74c](https://github.com/arthurmaciel/ipe-lang/commit/4d0a74c8f28211e8f2f5bb7ba37662bb8fbbc3de))
* **wasm:** compile the Ipê frontend to WASM + browser-native playground ([40587ca](https://github.com/arthurmaciel/ipe-lang/commit/40587ca95b78ab4c6073950e0c092249fc931d3f))
* **wasm:** Ipe.Env.public kernel + build-time publicEnv embedding ([#287](https://github.com/arthurmaciel/ipe-lang/issues/287)) ([6729c68](https://github.com/arthurmaciel/ipe-lang/commit/6729c68081dc9fe9df8ec7231ad1d84e40d4c95a))
* **wasm:** M0 pure-kernel wasm floor — runtime builds to wasm32-unknown-unknown (default + json) as an enforced CI gate ([9a66a2d](https://github.com/arthurmaciel/ipe-lang/commit/9a66a2d2272e1afbca5654729832593c45c6eee6))
* **wasm:** M1 target-keyed kernel gate + M2 emission branch + M3 browser slice — ipe build --target wasm, Ipe.Ui proven in Chromium ([9523e03](https://github.com/arthurmaciel/ipe-lang/commit/9523e03d01b3f724cd56b07153626913ba23c75c))
* **wasm:** M4 Cmd/Sub browser-effects bridge — Log/Random/Http/WebSocket/Task substitutes, timers, in-tab pub/sub ([e95af5a](https://github.com/arthurmaciel/ipe-lang/commit/e95af5ad106fce8ae05eccf3f13e8e3e94429ca0))
* **wasm:** M5 Layer-2 module classification + reachability closure + [wasm] ipe.toml config (IPE-N0030) ([d668b89](https://github.com/arthurmaciel/ipe-lang/commit/d668b897d32cf9e576fedbbca3a56499e9d634b2))
* **wasm:** M6 Target A MVP — pure-client SPA end-to-end ([#240](https://github.com/arthurmaciel/ipe-lang/issues/240)) ([30533d1](https://github.com/arthurmaciel/ipe-lang/commit/30533d1de968f44ed406e121ddc4fea52a4a9d44))
* **wasm:** M7 SSR hydration — island serialiser, adopt path, hydrate export, field-type gate ([0b7f543](https://github.com/arthurmaciel/ipe-lang/commit/0b7f543108a5ffc7e8ef67b126555ef4c01f6012))
* **wasm:** M8 playground B1 — server-compile-then-ship-WASM backend ([0171f27](https://github.com/arthurmaciel/ipe-lang/commit/0171f27dfd023bab77dd56ff616d7e9ef0d1813a))


### Bug Fixes

* **#210:** register Ipe.Config family — Decoder carrier + 16 kernels SEAL ([627afe0](https://github.com/arthurmaciel/ipe-lang/commit/627afe0563141f68355390b4cc5b6ed4eb902cec))
* **#221 defect B:** home-attribute lowering + emit diagnostics to owning module ([1149870](https://github.com/arthurmaciel/ipe-lang/commit/1149870fdc0687ed5e79cf899f09a4ef8ad95327))
* **backend,lower:** SEAL 13-skyshop — cfg-record arg-order hoist, sync-capture param promotion trigger, single-boundary Arc callback ([4c2ac25](https://github.com/arthurmaciel/ipe-lang/commit/4c2ac252c345920f0bcd1ad8682be597926c7860))
* **backend/tests:** pass wasm_hydrate_mode to EmitCtx::build test call sites (WASM M7 arity debt) ([711c725](https://github.com/arthurmaciel/ipe-lang/commit/711c725f151f520a24fdb518908e9234a5e59e5a))
* **backend:** close the module-set SEAL breach class (tea/live/http_stream drift) ([d3d0bd8](https://github.com/arthurmaciel/ipe-lang/commit/d3d0bd806ad128175f728600f522affd312daffb))
* **backend:** emitter emits at most one consecutive blank line ([7e69cb8](https://github.com/arthurmaciel/ipe-lang/commit/7e69cb8dd81798a81601d82de6abcb1923efd803))
* **backend:** FFI shake keep-decision accumulates instead of overwriting ([#283](https://github.com/arthurmaciel/ipe-lang/issues/283)) ([1a08994](https://github.com/arthurmaciel/ipe-lang/commit/1a08994c12097be16306a81e9bb4067e2ce41432))
* **backend:** two emitter fallbacks fail closed instead of emitting invalid Rust ([#281](https://github.com/arthurmaciel/ipe-lang/issues/281)) ([13ae62d](https://github.com/arthurmaciel/ipe-lang/commit/13ae62df0ae42ed3c1003e3c1494046df882df71))
* **canon:** bound type-alias expansion with depth + node-count limits (IPE-N0032) ([2d973e6](https://github.com/arthurmaciel/ipe-lang/commit/2d973e6f6dae10ee6b6322e9736d91cc8d5a0cf9))
* **canon:** canon-arity-gate — reject mis-arity built-in containers (IPE-N0031) ([1089a76](https://github.com/arthurmaciel/ipe-lang/commit/1089a76ae6096bbdc7d0a109ca725ab1e32f0962))
* **canon:** qualified cross-module alias references expand without exposing ([3fe074f](https://github.com/arthurmaciel/ipe-lang/commit/3fe074f073d3df9cdf45a0035269ab741090138d))
* **ci:** clippy duration_suboptimal_units (from_secs-&gt;from_mins, toolchain drift: CI stable was ahead of local rustup) + golden_alias_move_seal stale substring assertions (rustfmt reflow, same class as [#269](https://github.com/arthurmaciel/ipe-lang/issues/269)) + .gitignore drop ../sky ref + point oracle-version comment at its SSOT (tools/oracle/README.md) ([737eb50](https://github.com/arthurmaciel/ipe-lang/commit/737eb5030bb1baed34f24431ea77bcf26ddf4669))
* **ci:** clippy duration_suboptimal_units in lsp_stdio_e2e.rs (from_secs(60)-&gt;from_mins(1)) ([a69d923](https://github.com/arthurmaciel/ipe-lang/commit/a69d9233eb97d28f9973586ab1e461a54d32d8a4))
* **ci:** clippy map_unwrap_or in ipe_watch scope.rs (map_or(0, |d| d.as_nanos())) ([3dea51c](https://github.com/arthurmaciel/ipe-lang/commit/3dea51c8da00fe8a7626588ce09af616620bf0b3))
* **ci:** e2e shards — set IPE_ORACLE_SHARED_TARGET, closing the disk-exhaustion class ([bf61ebb](https://github.com/arthurmaciel/ipe-lang/commit/bf61ebbd555fdba38e8b06657d9ff478738479f6))
* **ci:** nextest ci profile, 6 E2E shards, sccache v0.0.9, --no-fail-fast ([d9adfbe](https://github.com/arthurmaciel/ipe-lang/commit/d9adfbe3f3c8b82d681025ab4522ea66427fb07e))
* **ci:** sky-parity picks the compiler binary, not the FFI inspector ([8239648](https://github.com/arthurmaciel/ipe-lang/commit/82396481cd0ee74fa3c3784862bee6a76266a078))
* **ci:** stale golden-test substring assertions masked by nextest fail-fast ([#191](https://github.com/arthurmaciel/ipe-lang/issues/191), [#193](https://github.com/arthurmaciel/ipe-lang/issues/193), [#195](https://github.com/arthurmaciel/ipe-lang/issues/195), [#190](https://github.com/arthurmaciel/ipe-lang/issues/190), ws-onerror, Ipe.Ui.Animation/Transition) ([facd9a7](https://github.com/arthurmaciel/ipe-lang/commit/facd9a76e7d6920dc0e867588df61742e75ae3b2))
* **ci:** three more E2E failures the disk-exhaustion fix stopped masking (server-clone reflow, webview Linux link gap, watch cold-build headroom) ([193760c](https://github.com/arthurmaciel/ipe-lang/commit/193760ce78a2c4dab6f21912d57e3f855cf64fb5))
* **cli:** clear nightly-clippy debt in wasm bundle step and manifest parsing ([47d89c2](https://github.com/arthurmaciel/ipe-lang/commit/47d89c2f3682ef58f15f165c320c46bf96b4bc7c))
* **clippy+fmt:** ffi.rs map_or + doc-paragraph split; rustfmt resolve.rs/types-lib drift ([89280bf](https://github.com/arthurmaciel/ipe-lang/commit/89280bf30629a99b948792820cfc1d49abbd20d7))
* **clippy:** clear pre-existing --all-targets lint debt in LSP, backend, canon, types, playground ([78d1d6e](https://github.com/arthurmaciel/ipe-lang/commit/78d1d6e07cd8ad3fe66e4c87363f8c5f7c7248f4))
* **cli:** rewrite two test match blocks as let-else (clippy pedantic on --all-targets) ([#3](https://github.com/arthurmaciel/ipe-lang/issues/3)) ([d5a7b37](https://github.com/arthurmaciel/ipe-lang/commit/d5a7b370760e39a4ca3f98eefed386afcea46d99))
* **deps:** regenerate package-lock.json — was stale, missing pixelmatch/pngjs entirely (only had playwright) ([d5d6dcf](https://github.com/arthurmaciel/ipe-lang/commit/d5d6dcf0961c6e3f3afe792dca24e22139e74a55))
* **diagnostics:** drop duplicate unreachable BuiltinTypeArity render arm (merge artifact) ([803d751](https://github.com/arthurmaciel/ipe-lang/commit/803d7515ba588b5fdb73207e0fb912e5940ef56a))
* **docs:** correct stale warm-db-reuse doc — the parity gate already exists ([#277](https://github.com/arthurmaciel/ipe-lang/issues/277)) ([96ece49](https://github.com/arthurmaciel/ipe-lang/commit/96ece49a8517fbaae2131e785e13b7b76d9ffa00))
* **emit:** opaque-type special-cases keyed on old Std home -&gt; Ipe (Cache/Config/Email) ([4a3cb4c](https://github.com/arthurmaciel/ipe-lang/commit/4a3cb4cd2be14f960ea7f37b0e002e8db4dfb8dd))
* **example:** 41-money-allocate-regression — correct main sig (drop Never) + fromMajor takes Int not Decimal; T4's example never compiled as shipped ([375e339](https://github.com/arthurmaciel/ipe-lang/commit/375e339b1ff5b81748415cda0579ccc10f3b905f))
* **examples:** patch 00-standard-libs Money tests for Ipê's Result API ([bdfbca2](https://github.com/arthurmaciel/ipe-lang/commit/bdfbca2ea2a65b11664c51a2ce1c798d9239fc04))
* **examples:** restore native 01-hello-world; untrack sky-out build output ([bab7bc6](https://github.com/arthurmaciel/ipe-lang/commit/bab7bc6d65a94891237defdb9415dbc07ff4f1f4))
* **ffi-inspector:** private-path-admission — drop external trait UFCS qualifiers threading a private module ([b1de3de](https://github.com/arthurmaciel/ipe-lang/commit/b1de3de4569d02b46587afdbfd605dd95138743c))
* **ffi-inspector:** serde-trait identity by raw defining path — restores the firestore serde document surface ([b8afea3](https://github.com/arthurmaciel/ipe-lang/commit/b8afea35b35d6932e9f77d0ce2367e5418f58915))
* **ffi-sandbox:** T1 F2-F6 — two-phase no-egress jail, narrowed ~/.cargo binds, mandatory caps + concurrent drain, bwrap-or-refuse, bounded owned cache root, scratch under ~/.cache/ipe + install prompt ([adf54c3](https://github.com/arthurmaciel/ipe-lang/commit/adf54c328ff444ebe68f74cd5bcefca33c6da5a6))
* **ffi:** compositional OK-lift for generic wrappers + owned pass for bare-str substitutes ([5a04388](https://github.com/arthurmaciel/ipe-lang/commit/5a043886381beabe8edbddbddfdf728f59e207ff))
* **ffi:** fail-closed on reuse of a non-Clone FFI opaque handle (SEAL) ([3b0c86e](https://github.com/arthurmaciel/ipe-lang/commit/3b0c86ef51fd4286ad763cd80c5b6f089e8922df))
* **ffi:** fallible setter surface carries the Result layer the wrapper renders ([92c4905](https://github.com/arthurmaciel/ipe-lang/commit/92c490579d13dbd4418213a843d8b526ab3eba9b))
* **ffi:** gate Cargo feature names at the manifest boundary ([c159a9a](https://github.com/arthurmaciel/ipe-lang/commit/c159a9a914c203db0842042b58c26a69a6a5da1b))
* **ffi:** gate dep features + transitive name at the pkg.json decode boundary ([50f7934](https://github.com/arthurmaciel/ipe-lang/commit/50f793451e6668f9a31e536429cdcd73ab7e7e5b))
* **ffi:** maybe-coercion — IpeMaybe&lt;-&gt;Option at synthesised-instance boundaries ([dfa851c](https://github.com/arthurmaciel/ipe-lang/commit/dfa851ce1db08ad88ea78f83aea4784dd797d25b))
* **ffi:** one-home unification verified E2E — stripe 6-crate SEAL green ([36a4413](https://github.com/arthurmaciel/ipe-lang/commit/36a441383235c92ac7c0e584da566bb4447da748))
* **ffi:** seal the RCE sandbox for SDK-scale installs — chunk per crate + calibrate caps ([#309](https://github.com/arthurmaciel/ipe-lang/issues/309)) ([d2bec5d](https://github.com/arthurmaciel/ipe-lang/commit/d2bec5d87ef571b4894e405e568a84b48e8480f2))
* **ffi:** T1 clippy clean-up + warm-load byte-identity test ([80a5171](https://github.com/arthurmaciel/ipe-lang/commit/80a51714323e126636a5045fefa5b105ab936e38))
* **ffi:** T1 F1 — validated type/path/selector newtypes at the FFI decode boundary + re-derive load_catalog from validated inspection doc ([f1082f5](https://github.com/arthurmaciel/ipe-lang/commit/f1082f516ca619ad9077b3496ef8cab93190981c))
* **ffi:** T1 F1e — graceful legacy fallback for caches without pkg.json ([1a71754](https://github.com/arthurmaciel/ipe-lang/commit/1a717549b6370fae9cefb757033b51ac009207cb))
* **ffi:** validate crate version at decode boundary (CrateVersion newtype) ([6becd88](https://github.com/arthurmaciel/ipe-lang/commit/6becd887652bac03e9fe25ab5cf87c668cc7d327))
* **ffi:** validate pkg_path at the pkginfo decode boundary ([fe0338e](https://github.com/arthurmaciel/ipe-lang/commit/fe0338e3e9088cf8432b00817e3a2674e61cb40b))
* **fmt:** a simple-reference first call arg always hugs the broken head line ([6d095cf](https://github.com/arthurmaciel/ipe-lang/commit/6d095cfc6b308e5dd16a16f54a843ba1ac7c8dbc))
* **fmt:** backward pipe `<|` breaks at the end of the left operand's line ([01a039a](https://github.com/arthurmaciel/ipe-lang/commit/01a039ac8096c6a6e92954ad2e74093a5e872b13))
* **fmt:** elm-format parity — modal layout, paren-safety, let/lambda/signature bugs ([cfa4d0b](https://github.com/arthurmaciel/ipe-lang/commit/cfa4d0bcc80666af9e95213a864ace98fee3570f))
* **fmt:** emit a trailing chain lambda bare, without wrapping parens ([eecf197](https://github.com/arthurmaciel/ipe-lang/commit/eecf197c4047448ffac350ab51a919d4bea642b4))
* **fmt:** FAJoinFirst hugs first call arg only when a block arg is present ([ae118a3](https://github.com/arthurmaciel/ipe-lang/commit/ae118a3dd8b74d7710c7886d5d67271b67aef00e))
* **fmt:** indent record-update fields one level past the brace ([ebed6f8](https://github.com/arthurmaciel/ipe-lang/commit/ebed6f8e3681f1e803d90080506927197e617a6c))
* **fmt:** keep multiline-string call args inline; break modal lambda bodies ([d1830dc](https://github.com/arthurmaciel/ipe-lang/commit/d1830dc91a047e8963ae9aae231f06ac31e26469))
* **fmt:** reflow shake_ffi_by_fn_ident signature — clears pre-existing rustfmt drift (workspace now fmt-clean) ([0b92cb0](https://github.com/arthurmaciel/ipe-lang/commit/0b92cb0df89f2fd9e8567ac04479dcfff0dc7145))
* **fmt:** two blank lines between a pre-header comment block and the module header ([1d31f00](https://github.com/arthurmaciel/ipe-lang/commit/1d31f004b4f6e3a913450c2667bf66f05465490e))
* **gate:** 13 rename-stale test + 2 real bugs surfaced by full-workspace run ([01e6fed](https://github.com/arthurmaciel/ipe-lang/commit/01e6feda1f67432c3e77acbd0bd47318994ff7b1))
* **gate:** clippy --all-targets clean (pedantic + nursery, clippy 1.92) ([53e3740](https://github.com/arthurmaciel/ipe-lang/commit/53e3740787bef25cce042e8b5d3f768bbd61cc21))
* **gate:** recover corrupted stdlib .ipe + reserved-namespace + compiled-source fixes ([6343643](https://github.com/arthurmaciel/ipe-lang/commit/634364358cd59bf905e3cbb73d39e468fa6cd656))
* **gate:** rename stragglers surfaced by full-workspace compile ([e11ced3](https://github.com/arthurmaciel/ipe-lang/commit/e11ced3c1e52d87f0a7f9587025b3f5d6447d54b))
* **gate:** resolve 6 workspace test failures — 4 stale rustfmt snapshots, 1 feature-gated dispatch test, 1 Db.Decode registry drift ([c8041ea](https://github.com/arthurmaciel/ipe-lang/commit/c8041eab1751550dac61274fbb3c412be0267d0a))
* **ipe test:** allow missing_const_for_fn on false_marker ([259b458](https://github.com/arthurmaciel/ipe-lang/commit/259b4589eb748db1f5152b200e3f1fa4df0ad0b4))
* **ipe_backend_rust:** user module named after a kernel namespace collides with the runtime glob ([db862f0](https://github.com/arthurmaciel/ipe-lang/commit/db862f08e0617eea96a605df091d987cb53bb620))
* **ipe_backend:** [#233](https://github.com/arthurmaciel/ipe-lang/issues/233) Stream.stream re-wrap moves captured non-Copy strings (2x E0507) ([bcdfb03](https://github.com/arthurmaciel/ipe-lang/commit/bcdfb03ec53b2c7e4b9174978e8dc80e1a17ffc1))
* **ipe_canon:** register Sub.subscribeWebSocket in QUALIFIERS (anti-drift gap from [#210](https://github.com/arthurmaciel/ipe-lang/issues/210) WebSocket) ([6aaf010](https://github.com/arthurmaciel/ipe-lang/commit/6aaf010833ff96e13f69c0bc6d31573567853b5c))
* **ipe_lower,backend:** [#228](https://github.com/arthurmaciel/ipe-lang/issues/228) type-directed onSubmit handler classification ([3d5c1b9](https://github.com/arthurmaciel/ipe-lang/commit/3d5c1b9c9fb38430cf591a7a78fa4b00e2660fcf))
* **ipe_lower:** [#218](https://github.com/arthurmaciel/ipe-lang/issues/218) clone-relay across intermediate closure boundaries (E0507 SEAL breach) ([976a075](https://github.com/arthurmaciel/ipe-lang/commit/976a075256a2ea7c159f352488881b62b437ece8))
* **ipe_lower:** fold Ipe.Csv `{header,rows}` record to nominal CsvDoc ([#232](https://github.com/arthurmaciel/ipe-lang/issues/232)) ([e320dd9](https://github.com/arthurmaciel/ipe-lang/commit/e320dd939a69e16dcc95e744978c95a42ae98e38))
* **ipe_lower:** unify move-ownership discipline at one entry point, closing the clone-relay class ([#222](https://github.com/arthurmaciel/ipe-lang/issues/222)/[#224](https://github.com/arthurmaciel/ipe-lang/issues/224)/[#225](https://github.com/arthurmaciel/ipe-lang/issues/225)) ([c9b7345](https://github.com/arthurmaciel/ipe-lang/commit/c9b7345f90c2de4e581d72b4363bdb3f651d6fcf))
* **Ipe.Test:** [#219](https://github.com/arthurmaciel/ipe-lang/issues/219) runMain prints pass/fail summary line to stdout ([30ef1b2](https://github.com/arthurmaciel/ipe-lang/commit/30ef1b2151b9aea8b9086ffe9afb14b9749a3538))
* **ipe:** thread on_form on two Expr::Call sites in cache.rs test IR ([889ef36](https://github.com/arthurmaciel/ipe-lang/commit/889ef36a53be23f29d814006b3c458c73d505f29))
* **ir:** bound the IR pretty-printer's recursion depth ([#282](https://github.com/arthurmaciel/ipe-lang/issues/282)) ([bad60bf](https://github.com/arthurmaciel/ipe-lang/commit/bad60bff3a08f2d77e95591efdb11b24a171dae7))
* **jwt:** seal the JWT Algorithm descriptor in Ipe.Secret ([#276](https://github.com/arthurmaciel/ipe-lang/issues/276)) ([5a609ae](https://github.com/arthurmaciel/ipe-lang/commit/5a609ae87afa70b8d752548ae70c28516a17ec22))
* **kernels:** complete required_runtime_module SSOT for PubSub kernels ([1164814](https://github.com/arthurmaciel/ipe-lang/commit/1164814474a122bbc8ae68baba5907558fa94499))
* **lsp:** don't drop the prior project layout on a transient load failure ([#278](https://github.com/arthurmaciel/ipe-lang/issues/278)) ([d7bed12](https://github.com/arthurmaciel/ipe-lang/commit/d7bed12b7ffacfcd14bb00c0a5434aab70e68d95))
* **mirror-parity:** D1 bare Css keyword constants + D2 record-alias-ctor coexistence; advance D3-18 row-poly, file rest ([a7df836](https://github.com/arthurmaciel/ipe-lang/commit/a7df8362dd7272005ce9b96fda5f7eabb707dbb7))
* **money:** kernel-wire Ipe.Money — route currency table / format / FX / allocate through guarded Money_* kernels ([8d45b03](https://github.com/arthurmaciel/ipe-lang/commit/8d45b03cb6208bb97c038ca929aa46e6bbd94c32))
* **parity-matrix:** skip canon-parity for compiled-source Layer-3 qualifiers ([#223](https://github.com/arthurmaciel/ipe-lang/issues/223)) ([acc04a1](https://github.com/arthurmaciel/ipe-lang/commit/acc04a1add9340939024ea92fd3cc57e3647ad2a))
* **parse:** reject space-before-dot instead of misparsing as field access ([9eec146](https://github.com/arthurmaciel/ipe-lang/commit/9eec1467c210e0c7b43471842c78a519ba327a0a))
* **playground:** correct IPE_RUNTIME_DIR path in README + resolver error to src/runtime/rust/src ([5bc57de](https://github.com/arthurmaciel/ipe-lang/commit/5bc57de8e70f58554711bd743a44b4bb22d6a3df))
* **project:** module discovery filtered .sky not .ipe (post-rename regression) ([5678e22](https://github.com/arthurmaciel/ipe-lang/commit/5678e2215522b1d06219719f25070a6a40315ef3))
* **rename:** normalize skyshop config to ipe.toml + fix stray ipe.toml/out in README usage ([#212](https://github.com/arthurmaciel/ipe-lang/issues/212)) ([5488229](https://github.com/arthurmaciel/ipe-lang/commit/54882299554c9ffc7d7f72a26db5787d60a70115))
* **rename:** update base64 expected constant for renamed 'Hello, Ipe!' plaintext ([#212](https://github.com/arthurmaciel/ipe-lang/issues/212)) ([2ffb474](https://github.com/arthurmaciel/ipe-lang/commit/2ffb474eba1736add14bde2abf56598693fa7fb9))
* **rename:** update string_reverse expected constant for renamed 'ipewasm' ([#212](https://github.com/arthurmaciel/ipe-lang/issues/212)) ([aa3c89c](https://github.com/arthurmaciel/ipe-lang/commit/aa3c89c922593d3001bbe506868cf53e7b89dba7))
* **runtime/live:** unrouted GETs no longer wipe a session's handler index ([#170](https://github.com/arthurmaciel/ipe-lang/issues/170) root cause) ([b767c4c](https://github.com/arthurmaciel/ipe-lang/commit/b767c4c53ee8dcaf481caa24fcb2bf7db6f94ddd))
* **runtime:** enforce WS per-message size cap at the framing layer ([#274](https://github.com/arthurmaciel/ipe-lang/issues/274)) ([7a19539](https://github.com/arthurmaciel/ipe-lang/commit/7a1953965172ead483c737562d9c52f5c7e9817d))
* **runtime:** inject dev-console banner into Ipe.Http.Server text/html responses ([#220](https://github.com/arthurmaciel/ipe-lang/issues/220)) ([6df0780](https://github.com/arthurmaciel/ipe-lang/commit/6df0780c6bdef35fd847eab8cb3cf15652987b9a))
* **runtime:** reap abandoned Server.Stream.stream handlers on a TTL ([#273](https://github.com/arthurmaciel/ipe-lang/issues/273)) ([4e730e9](https://github.com/arthurmaciel/ipe-lang/commit/4e730e99d54532d6b01b29f2888a8a1d7978d288))
* **runtime:** refuse to push the ingest token over cleartext HTTP ([#275](https://github.com/arthurmaciel/ipe-lang/issues/275)) ([e3338ec](https://github.com/arthurmaciel/ipe-lang/commit/e3338ec3b7aaced6c72aa0d26d577469096e1972))
* **runtime:** ssrf sibling refs crate::ssrf -&gt; super::ssrf (SEAL: emitted build) ([abb4135](https://github.com/arthurmaciel/ipe-lang/commit/abb41357e5cde0d6e7ff5516ebd6b7e889755c82))
* **runtime:** stop byte-slicing caller-derived JWT descriptor in error messages ([4a98578](https://github.com/arthurmaciel/ipe-lang/commit/4a98578e046d632760581c3bf7a64d53ac63fdb2))
* **seal-006:** route Basics.toString stringify family through IpeStringify ([9d569cf](https://github.com/arthurmaciel/ipe-lang/commit/9d569cfdacc369ab740edb7f798b9b35eab04ae4))
* **stdlib-contracts:** converge Jwt.withClaim / Response / Db.Migration to the reference ([#217](https://github.com/arthurmaciel/ipe-lang/issues/217)) ([7afe3ee](https://github.com/arthurmaciel/ipe-lang/commit/7afe3ee4d0d35f916db6d82ef4653c68fdd292a2))
* **stdlib:** [#261](https://github.com/arthurmaciel/ipe-lang/issues/261) Money.add/sub/sumOf → Result Error Money (currency-mismatch now typed Err) ([969fb19](https://github.com/arthurmaciel/ipe-lang/commit/969fb19d53baabec3cc0183f2856ef415fb7af2e))
* **sweep:** _shape_match strips {- -} block comments, not just -- lines ([0693b9f](https://github.com/arthurmaciel/ipe-lang/commit/0693b9fe52a66b6927d5e177229a7cc6be10ae6c))
* **sweep,ci:** mirror fetches upstream FIRST (local only as offline fallback); ci golden E2E compares against latest installed Sky, retire the cached expected_go oracle ([680edd1](https://github.com/arthurmaciel/ipe-lang/commit/680edd11bad095d109748fdfa67e51530da98c44))
* **sweep:** example_shape classifier -&gt; Ipe.* namespace (Live/Tui/Webview/Http) ([6099d34](https://github.com/arthurmaciel/ipe-lang/commit/6099d347a1b85b0c287aafe19d179234c09019e6))
* **sweep:** FFI-install examples SKIP, not false-RED (13-skyshop) ([ab71e37](https://github.com/arthurmaciel/ipe-lang/commit/ab71e37015f9c9b85a7d7d92e3ccf1201aca1f1c))
* **sweep:** mirror renames sky.toml -&gt; ipe.toml (Ipê's canonical manifest) ([fad2316](https://github.com/arthurmaciel/ipe-lang/commit/fad23166a9dcfc24366abd76f7057419819ca2da))
* **T2:** close SEAL-breach class — exhaustiveness over Prelude builtin ADTs, crate::-qualified top-level calls, live mod-ident gate ([aabbe0d](https://github.com/arthurmaciel/ipe-lang/commit/aabbe0d68974318ba4edbfd0a10c468ac911090e))
* **t3:** bound untrusted recursion/allocation — closes CO-FRONT-001, RT-UI-001, RT-TUI-001, RT-TUI-002 ([17151fe](https://github.com/arthurmaciel/ipe-lang/commit/17151feffa1e9c09e65560a6955df32a9a7c4d51))
* **t4:** JWT-exp NumericDate + Money allocate correctness (CO-INCR-001/002/003, RT-AUTH-001/002/003) ([4d8fc7c](https://github.com/arthurmaciel/ipe-lang/commit/4d8fc7c1f4484733d1c30a95be3aee3823be325f))
* **T5:** data/decode completeness + incremental wiring + SEAL (6 findings) ([8a4ef82](https://github.com/arthurmaciel/ipe-lang/commit/8a4ef82bb2f48ab111223bd815bb129745822465))
* **tests:** repair pre-existing base failures — env_public Module field + kernel-resolution allowlist ([bf3ca58](https://github.com/arthurmaciel/ipe-lang/commit/bf3ca58722998b99b96a5be3b74d710a042161f4))
* **wasm:** M1 gate WebSocket Sub-tier substitute — onOpen/onMessage/onClose/onError live in a browser ([#286](https://github.com/arthurmaciel/ipe-lang/issues/286)) ([bc57e10](https://github.com/arthurmaciel/ipe-lang/commit/bc57e10930cd2f892fbdd8b3bda31d23d685b8e5))
* **watch:** retry the rebuild cycle after a transient resolve failure ([#279](https://github.com/arthurmaciel/ipe-lang/issues/279)) ([3dc1000](https://github.com/arthurmaciel/ipe-lang/commit/3dc100051796b0c3a3a6824ac4fbfc7f05f49b2b))
* **watch:** scope the tests/ watch rule to the root-level directory only ([#280](https://github.com/arthurmaciel/ipe-lang/issues/280)) ([554c90d](https://github.com/arthurmaciel/ipe-lang/commit/554c90d7ca090d26dd243f03cec315c7f373f9d1))

## [0.1.0](https://github.com/arthurmaciel/ipe-lang/releases/tag/v0.1.0)

### Added

- First tagged release of the Ipê compiler, runtime, and CLI.
