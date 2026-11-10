# Review R package and C libraries

> this a frst assigment in a learning course how to build R packages, the course is giving by a senior develper, what would a senior developer expert in c and c++ would say this first R package am building as a junior developer in a big company, mainly topics around the way I have build this R package, about the soundness of out C libraries are vendored, integrated, testted, in particular, which items would he/she flag for me to review further in more detail which may be bugs, and badly implemented, or can be improved?

<details><summary>10 previous messages</summary>

> I’ll review the package as a senior C/C++ developer would, focusing on how the C code is vendored, built, called from R, and tested. I’ll distinguish likely bugs from improvements that are reasonable for a first course assignment, and use the code-review skill to guide the review.
>
> <details><summary>Explored a file, ran 9 commands</summary>
>
> - Ran `pwd; rg --files -g 'AGENTS.md' -g 'DESCRIPTION' -g 'NAMESPACE' -g '*Makevars*' -g 'SKILL.md' -g '!renv/**' -g '!vendor/**' -g '!src/vendor/**'`
>
> <details><summary>Explored a file</summary>
>
> - Read `~/.codex/skills/code-review/SKILL.md`
>
> </details>
>
> - Ran `git status --short; rg --files -g 'AGENTS.md' /Users/pbtz/src /Users/pbtz/.codex 2>/dev/null | head -60; rg --files -g '!renv/**' -g '!*.Rds' -g '!*.rds' -g '!*.pdf' -g '!*.html' -g '!*.o' -g '!*.so' -g '!*.a' | head -220`
>
> - Ran `wc -l src/*.c src/*.h inst/include/* R/* tests/testthat/*.R; cat src/zuc_internal.h src/zuc_live.h inst/include/zucrypt.h inst/include/zucrypt-r.h`
>
> - Ran `for p in /AGENTS.md /Users/AGENTS.md /Users/pbtz/AGENTS.md /Users/pbtz/src/AGENTS.md /Users/pbtz/src/github.com/AGENTS.md /Users/pbtz/src/github.com/pedrobtz/AGENTS.md; do if [ -f "$p" ]; then cat "$p"; fi; done; cat CLAUDE.md; cat DESCRIPTION; cat src/Makevars; cat src/install.libs.R; cat src/zuc_crypto_config.h`
>
> - Ran `cat tools/vendor/manifest.tsv tools/vendor/common.sh tools/vendor/fetch tools/vendor/verify tools/vendor/record; cat tools/patches/tf-psa-crypto/*.patch; rg --files .github; cat .github/workflows/*`
>
> - Ran `cat DESCRIPTION src/Makevars src/install.libs.R src/zuc_crypto_config.h; cat .Rbuildignore; ls .github/workflows; cat tools/vendor/manifest.tsv`
>
> - Ran `cat src/zuc_backend.c src/zuc_hash.c`
>
> - Ran `cat src/zuc_aes.c src/zuc_random.c src/zuc_util.c src/zuc_internal.h`
>
> <details><summary>Explored a file</summary>
>
> - Read `./src/zucrypt_crypt.c`
>
> </details>
>
> - Ran `cat src/zucrypt_r.c src/zucrypt_api.c R/hash.R R/aes.R R/hex.R R/conditions.R R/info.R`
>
> <details><summary>Explored a file</summary>
>
> - Read `./src/zucrypt_crypt.c`
>
> </details>
>
> </details>
>
> The package already has several strong foundations: a pinned backend, recorded patches and checksums, an R-free C adapter, and separate consumer packages that exercise both C interfaces. I’m now checking the harder edges—context lifetime, build reproducibility, symbol isolation, and whether the test gates cover the failures their comments describe.
>
> <details><summary>Explored 8 files, ran 11 commands, searched the web</summary>
>
> - Ran `nl -ba src/zucrypt_crypt.c | sed -n '353,530p'; cat tools/vendor/common.sh tools/vendor/verify`
>
> - Ran `cat tools/vendor/fetch tools/vendor/record .github/workflows/vendor.yaml .github/workflows/vendor-upstream.yaml .github/workflows/native-checks.yaml .github/workflows/aes-paths.yaml`
>
> - Ran `cat tests/testthat/test-adapter.R tests/testthat/test-lifetime.R tests/testthat/test-size.R tests/testthat/helper-kat.R; cat .github/workflows/abi.yaml`
>
> - Ran `command -v R; R --version | head -2; git log -3 --oneline; rg -n '^test_that|^TEST|^SEXP|^static SEXP|^static void' src/zucrypt_test.c tests/testthat/test-kat.R tests/testthat/test-connection.R; cat tools/patches/tf-psa-crypto/*.patch`
>
> - Ran `mktemp -d /tmp/zucrypt-review.XXXXXX`
>
> <details><summary>Explored 3 files</summary>
>
> - Read `./R/hash.R`
> - Read `./tests/testthat/test-kat.R`
> - Read `./src/zucrypt_r.c`
>
> </details>
>
> - Ran `mkdir -p /tmp/zucrypt-review.uZCa8D/source /tmp/zucrypt-review.uZCa8D/lib; git archive HEAD | tar -x -C /tmp/zucrypt-review.uZCa8D/source; R CMD INSTALL --preclean --library=/tmp/zucrypt-review.uZCa8D/lib /tmp/zucrypt-review.uZCa8D/source > /tmp/zucrypt-review.uZCa8D/install.log 2>&1; tail -15 /tmp/zucrypt-review.uZCa8D/install.log`
>
> - Ran `sh tools/vendor/verify; sh tools/check-layering.sh; Rscript -e 'cat("testthat:", requireNamespace("testthat", quietly=TRUE), " openssl:", requireNamespace("openssl", quietly=TRUE), "\n")'`
>
> <details><summary>Explored 3 files</summary>
>
> - Read `./src/zucrypt_test.c`
> - Read `./src/zucrypt_test.c`
> - Read `./tools/check-linking.sh`
>
> </details>
>
> Searched the web for `site.github.com/Mbed-TLS/TF-PSA-Crypto security advisories 1.1.1 ...`
>
> - Ran `cat tests/testthat/test-abi.R tests/testthat/test-linking.R tools/zucryptlink/src/Makevars.in tools/zucryptlink/configure .github/workflows/consumer.yaml`
>
> - Ran `R_LIBS=/tmp/zucrypt-review.uZCa8D/lib NOT_CRAN=true Rscript -e 'r <- as.data.frame(testthat::test_local("/tmp/zucrypt-review.uZCa8D/source", load_package="installed", reporter="summary", stop_on_failure=FALSE)); cat("PASSED", sum(r$passed), "FAILED", sum(r$failed), "ERRORS", sum(r$error), "SKIPS", sum(r$skipped), "\n"); quit(status=as.integer(any(r$failed > 0 | r$error)))' > /tmp/zucrypt-review.uZCa8D/tests.log 2>&1; tail -25 /tmp/zucrypt-review.uZCa8D/tests.log`
>
> - Ran `Rscript -e 'cat(tools::Rd2txt(utils:::.getHelpFile(help("isIncomplete"))))' | tail -75; cat tools/check-layering.sh; cat tests/testthat/test-connection.R`
>
> - Ran `R_LIBS=/tmp/zucrypt-review.uZCa8D/lib Rscript -e 'library(zucrypt); s <- serverSocket(34879L); x <- socketConnection("localhost", port=34879L, blocking=FALSE, open="a+b", timeout=2); y <- socketAccept(s, blocking=FALSE, open="a+b", timeout=2); print(summary(x)); z <- tryCatch(crypt_hash(x),error=identity); print(z); print(isIncomplete(x)); writeBin(charToRaw("later"),y); flush(y); print(readBin(x,"raw",n=5)); close(x);close(y);close(s)'`
>
> <details><summary>Explored 3 files</summary>
>
> - Read `./src/vendor/tf-psa-crypto/lib/platform_util.c`
> - Read `./src/zucrypt_api.c`
> - Read `./tests/testthat/test-interface.R`
>
> </details>
>
> </details>
>
> The clean installation and the vendor and layering checks pass locally. I’m running the installed package’s tests next. One build issue is worth investigating: I don’t see header dependencies in `Makevars`, so a configuration or header edit may leave old C objects in place during a rebuild.
>
> <details><summary>Explored 4 files, ran 6 commands</summary>
>
> - Ran `cat tests/testthat/test-validation.R | tail -125; cat tests/testthat/helper-abi.R; cat tools/ubsan.supp; cat .github/workflows/alloc-failure.yaml .github/workflows/arch.yaml`
>
> - Ran `Rscript -e 'cat(system.file("share", "make", "shlib.mk", package="base")); cat(readLines(file.path(R.home("share"), "make", "shlib.mk")), sep="\n")'; cat tools/vendor/keep/tf-psa-crypto.txt | head -35; nl -ba tools/alloc-exercise.R | sed -n '1,220p'; cat tests/testthat/test-loading.R`
>
> - Ran `touch /tmp/zucrypt-review.uZCa8D/source/src/zuc_crypto_config.h; R CMD INSTALL --library=/tmp/zucrypt-review.uZCa8D/lib /tmp/zucrypt-review.uZCa8D/source > /tmp/zucrypt-review.uZCa8D/rebuild.log 2>&1; head -12 /tmp/zucrypt-review.uZCa8D/rebuild.log`
>
> - Ran `rg -n '^psa_status_t psa_hash_compute|psa_hash_compute\(' src/vendor/tf-psa-crypto/lib/*.c; rg -n '^psa_status_t psa_crypto_init|^void mbedtls_psa_crypto_free' src/vendor/tf-psa-crypto/lib/*.c; nl -ba src/Makevars | tail -35; nl -ba tools/vendor/verify | sed -n '156,186p'; nl -ba src/zuc_random.c | sed -n '111,152p'`
>
> - Ran `bash tools/check-linking.sh > /tmp/zucrypt-review.uZCa8D/consumers.log 2>&1; tail -35 /tmp/zucrypt-review.uZCa8D/consumers.log`
>
> <details><summary>Explored 4 files</summary>
>
> - Read `/tmp/zucrypt-review.uZCa8D/rebuild.log`
> - Read `./src/zuc_random.c`
> - Read `./vignettes/articles/backend.Rmd`
> - Read `./tests/testthat/test-loading.R`
>
> </details>
>
> - Ran `mkdir -p /tmp/zucrypt-review.uZCa8D/vendor-repro; git archive HEAD | tar -x -C /tmp/zucrypt-review.uZCa8D/vendor-repro; sh tools/vendor/fetch > /tmp/zucrypt-review.uZCa8D/fetch.log 2>&1; tail -10 /tmp/zucrypt-review.uZCa8D/fetch.log`
>
> </details>
>
> All 1,076 test expectations pass locally, and the static archive consumer passes its linking, load-order, and unload/reload checks. I also confirmed the rebuild issue: after touching the crypto configuration header, a plain `R CMD INSTALL` reported “Nothing to be done.” I’m separating that confirmed defect from design tradeoffs and test gaps.
>
> <details><summary>Explored 9 files, a search, ran 6 commands</summary>
>
> - Ran `mkdir -p /tmp/zucrypt-review.uZCa8D/vendor-repro; git archive HEAD | tar -x -C /tmp/zucrypt-review.uZCa8D/vendor-repro`
>
> - Ran `sh tools/vendor/fetch > /tmp/zucrypt-review.uZCa8D/fetch.log 2>&1; tail -10 /tmp/zucrypt-review.uZCa8D/fetch.log`
>
> - Ran `R_LIBS=/tmp/zucrypt-review.uZCa8D/lib R CMD INSTALL --preclean --library=/tmp/zucrypt-review.uZCa8D/lib /tmp/zucrypt-review.uZCa8D/source/tools/zucrypttest > /tmp/zucrypt-review.uZCa8D/table-install.log 2>&1; R_LIBS=/tmp/zucrypt-review.uZCa8D/lib Rscript -e 'r <- as.data.frame(testthat::test_local("/tmp/zucrypt-review.uZCa8D/source/tools/zucrypttest", load_package="installed", reporter="summary")); cat("PASSED",sum(r$passed),"FAILED",sum(r$failed),"ERRORS",sum(r$error),"\n")' > /tmp/zucrypt-review.uZCa8D/table-tests.log 2>&1; tail -15 /tmp/zucrypt-review.uZCa8D/table-tests.log`
>
> <details><summary>Explored 7 files</summary>
>
> - Read `./tests/testthat/test-lifetime.R`
> - Read `./tools/alloc-exercise.R`
> - Read `./tests/testthat/test-adapter.R`
> - Read `./tests/testthat/test-loading.R`
> - Read `./.github/workflows/native-checks.yaml`
> - Read `./inst/include/zucrypt-r.h`
> - Read `./tools/check-linking.sh`
>
> </details>
>
> - Ran `diff -qr src/vendor /tmp/zucrypt-review.uZCa8D/vendor-repro/src/vendor; cmp tools/vendor/checksums.sha256 /tmp/zucrypt-review.uZCa8D/vendor-repro/tools/vendor/checksums.sha256; git status --short; nl -ba .github/workflows/vendor.yaml | sed -n '1,22p'; nl -ba src/zuc_hash.c | sed -n '122,174p'; nl -ba inst/include/zucrypt.h | sed -n '140,161p'; rg -n 'MBEDTLS_AES_USE_HARDWARE_ONLY|AES_USE_HARDWARE_ONLY' src/vendor/tf-psa-crypto/lib/aes.c | head`
>
> - Ran `python3 - <<'PY'
> from pathlib import Path
> p = Path('/tmp/zucrypt-review.uZCa8D/source/src/zuc_crypto_config.h')
> s = p.read_text()
> s = s.replace('#if !defined(ZUC_AES_SOFTWARE_ONLY)', '#define ZUC_AES_SOFTWARE_ONLY 1\n#if !defined(ZUC_AES_SOFTWARE_ONLY)')
> p.write_text(s)
> PY
> R CMD INSTALL --library=/tmp/zucrypt-review.uZCa8D/lib /tmp/zucrypt-review.uZCa8D/source > /tmp/zucrypt-review.uZCa8D/config-rebuild.log 2>&1
> R_LIBS=/tmp/zucrypt-review.uZCa8D/lib Rscript -e 'cat("AFTER HEADER CHANGE:", zucrypt::crypt_info()$build_flags$aes_implementation,"\n")'`
>
> - Ran `R CMD INSTALL --preclean --library=/tmp/zucrypt-review.uZCa8D/lib /tmp/zucrypt-review.uZCa8D/source > /tmp/zucrypt-review.uZCa8D/config-clean.log 2>&1; R_LIBS=/tmp/zucrypt-review.uZCa8D/lib Rscript -e 'cat("AFTER CLEAN REBUILD:", zucrypt::crypt_info()$build_flags$aes_implementation,"\n")'`
>
> <details><summary>Explored 4 files, a search</summary>
>
> - Read `./src/zucrypt_test.c`
> - Read `./tools/check-linking.sh`
> - Read `./.github/workflows/native-checks.yaml`
> - Read `./src/Makevars`
> - Searched for `psa_hash_update|psa_mac_update|case ZUC|PSA_ERROR_BAD_STATE` in `zuc_status.c`
>
> </details>
>
> </details>
>
> Re-fetching the pinned upstream archive and applying both patches reproduced all 113 vendored files and their recorded checksums exactly. The registered C-table consumer also passes its 44 expectations. The main remaining concerns are how configuration changes trigger rebuilds and how much the failure and ABI tests actually prove.
>
> <details><summary>Ran 2 commands, called 2 tools</summary>
>
> MCP tool call
>
> codex_apps.github.fetch_file
>
> ```json
> {
>   "repository_full_name": "pedrobtz/r-actions",
>   "path": ".github/workflows/alloc-failure.yml",
>   "ref": "v1"
> }
> ```
>
> ```text
> Action completed.
> ```
>
> ````json
> {
>   "content": "# Allocation-failure injection: run the package repeatedly, failing a\n# different allocation each time.\n#\n# Allocation failure is the least-tested path in any C library, because\n# nothing in an ordinary test run ever makes malloc fail. The handling exists\n# -- a parser returns an error code, the R layer unwinds, frees the stream and\n# raises a condition -- and it is almost certainly executed zero times by the\n# suite.\n#\n# Nothing else here reaches it. ASan and valgrind check what happens to memory\n# that *was* allocated. gctorture forces collections, not failures. rchk\n# reasons about PROTECT, not about a NULL return. The conformance corpus and\n# the fuzzer feed input to a parser that always gets the memory it asks for.\n#\n# This matters most for a parser handed untrusted input. An attacker who can\n# drive allocation volume -- deep nesting, a large alias expansion, a long\n# scalar -- can reach the OOM path on purpose, and if that path double-frees\n# or leaks the stream, the same input is a denial of service. Every other\n# check in this repository would report green.\n#\n# The sweep is the expensive part, so this belongs on a schedule.\non:\n  workflow_call:\n    inputs:\n      skip-docs-only:\n        description: >\n          Skip every job here when a push or pull request changes\n          documentation only: Markdown at the top level or under a dot\n          directory (`.github/`, `.agents/`), `_pkgdown.yml`, and `pkgdown/`.\n          Anything else runs as before, `man/`, `vignettes/` and the `.md`\n          snapshots under `tests/` included. So does every case where the\n          changed files cannot be listed: a new branch, a force-push, an API\n          failure, a manual or scheduled run.\n\n          DESCRIPTION, README.Rmd and README.qmd are skipped here too:\n          r-cmd-check gives such a change its one check. See\n          \"Documentation-only changes\" in the README.\n        type: boolean\n        required: false\n        default: true\n      run:\n        description: >\n          Command that exercises the package, run once per injected failure.\n          Keep it short: it runs once for every allocation in the sweep.\n\n              run: Rscript tools/alloc-exercise.R\n\n          A small driver aimed at the paths that allocate beats the whole\n          suite here, both because the sweep multiplies its cost and because\n          a failure is easier to attribute when less is happening.\n        type: string\n        required: true\n      baseline-run:\n        description: >\n          Command that starts the same interpreter and does nothing, used to\n          measure how many allocations happen before the package is reached.\n\n          This is not optional bookkeeping, it is what makes the results\n          mean anything. Measured on a trivial C program: 193 of its 197\n          allocations happen before `main` runs at all, in the runtime's own\n          startup. Failing those kills the process every time, in a way that\n          has nothing to do with the code under test -- a sweep from N=1\n          would report a wall of crashes and bury the one real finding.\n          Starting above this floor is what isolated the genuine bug in\n          testing.\n\n          The default starts R and evaluates nothing. Override it if `run`\n          uses a different interpreter.\n        type: string\n        required: false\n        default: Rscript -e 'invisible(NULL)'\n      max-allocations:\n        description: >\n          Cap on how many allocations to sweep, counted from the floor. The\n          sweep otherwise runs to the end of what the run actually allocated,\n          which for a real workload can be a very large number of process\n          starts.\n        type: number\n        required: false\n        default: 300\n      expect-pattern:\n        description: >\n          Extended regular expression the output must match when a run with\n          an allocation failed exits non-zero.\n\n          Surviving the failure is necessary and not sufficient: a run that\n          dies of it should say why. Setting this to the error the package is\n          supposed to raise turns the sweep into a check that the failure\n          surfaces as that condition rather than as some unrelated error.\n\n          Runs that exit 0 are not checked against it. Only one allocation is\n          failed per run, and R retries a failed allocation after a garbage\n          collection, so a clean exit usually means the failure was absorbed\n          -- not that the package hid it. A package that swallows the error\n          and returns a truncated result is something only the workload can\n          catch, by checking its own result.\n\n              expect-pattern: \"cannot allocate|memory exhausted\"\n\n          Empty by default, because the right pattern is package-specific and\n          a wrong one would fail every iteration.\n        type: string\n        required: false\n        default: \"\"\n      target-pattern:\n        description: >\n          Extended regular expression marking an injected failure that\n          reached the code this job is for. Every swept run whose output\n          matches it is counted, and the count is reported.\n\n          The sweep fails allocations by position, and most positions in any\n          R workload belong to R itself. A green sweep proves only that\n          whatever it hit was handled -- not that it hit the package at all.\n          Setting this to the error the package's own allocation failures\n          produce turns \"no crashes\" into \"no crashes, and N of the failures\n          were ours\":\n\n              target-pattern: \"ZUC_ERR_MEMORY\"\n\n          Empty by default: nothing is counted.\n        type: string\n        required: false\n        default: \"\"\n      min-target-hits:\n        description: >\n          Fail unless at least this many swept runs matched target-pattern.\n          0, the default, only reports. Set it to 1 or more once the count\n          has been seen, so that a sweep that silently stopped reaching the\n          package goes red instead of staying vacuously green.\n        type: number\n        required: false\n        default: 0\n      timeout-minutes:\n        type: number\n        required: false\n        default: 60\n\nname: alloc-failure\n\n# Nothing here writes through the token, so `contents: read` is enough: the\n# job reads the checkout, and artifact upload, the cache and a public ghcr.io\n# image each need no declared scope.\n#\n# This is not only least privilege. `read-all` is wider than the `read` that a\n# repository hands its GITHUB_TOKEN by default, and a called workflow cannot\n# be granted more than its caller holds -- so requesting it here made every\n# caller that did not declare permissions of its own fail with an unannotated\n# `startup_failure`, two seconds in, before any job was created.\npermissions:\n  contents: read\n\n# Read by the `changes` job, which is identical in every workflow that\n# carries it: the name in its `skip-ci:<name>` label.\nenv:\n  R_ACTIONS_WORKFLOW: alloc-failure\n\njobs:\n  # Skips the jobs below when a push or pull request changes documentation\n  # only; see the `skip-docs-only` input. Every workflow it gates carries an\n  # identical copy -- inline for the reason sanitizers.yml gives for not\n  # factoring out a composite action -- and tests/lint-workflows.py keeps the\n  # copies identical and the wiring complete.\n  #\n  # The gated jobs test `!cancelled()` in place of the implicit `success()`,\n  # so this job failing, or being skipped, runs them rather than dropping\n  # them. Only an explicit `docs-only=true` skips anything.\n  changes:\n    name: docs-only gate\n    # It always runs, because it also resolves `profile` and reads the pull\n    # request's labels. `skip-docs-only: false` turns off the file rules\n    # only; a label on a pull request is a decision someone made about that\n    # pull request, and still applies.\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    outputs:\n      docs-only: ${{ steps.classify.outputs.docs-only }}\n      scope: ${{ steps.classify.outputs.scope }}\n      profile: ${{ steps.classify.outputs.profile }}\n    steps:\n      - name: Classify the changed files and the labels\n        id: classify\n        continue-on-error: true\n        env:\n          GH_TOKEN: ${{ github.token }}\n          REPO: ${{ github.repository }}\n          EVENT: ${{ github.event_name }}\n          PR_BASE: ${{ github.event.pull_request.base.sha }}\n          PR_HEAD: ${{ github.event.pull_request.head.sha }}\n          BEFORE: ${{ github.event.before }}\n          AFTER: ${{ github.event.after }}\n          FORCED: ${{ github.event.forced }}\n          FILE_RULES: ${{ inputs.skip-docs-only }}\n          LABELS: ${{ toJSON(github.event.pull_request.labels.*.name) }}\n          WORKFLOW_REF: ${{ github.workflow_ref }}\n          # R_ACTIONS_WORKFLOW (the name in `skip-ci:<name>`) and\n          # R_ACTIONS_PROFILE (the `profile` input, where there is one) come\n          # from the workflow-level `env`, so that this job stays identical\n          # in every workflow that carries it.\n        run: |\n          # Anything short of a complete list of changed files, every one of\n          # them documentation or package metadata, leaves this false and\n          # every job runs -- unless a label on the pull request says\n          # otherwise.\n          #\n          # `scope` is `docs`, `metadata` or `code`. `docs-only` is true for\n          # the first two: every job gated on it skips both. r-cmd-check\n          # alone reads `scope`, and runs its quick runner legs for\n          # `metadata`, so a DESCRIPTION edit still gets one R CMD check.\n          docs_only=false scope=code profile=full\n          trap '{ echo \"docs-only=$docs_only\"; echo \"scope=$scope\"; echo \"profile=$profile\"; } >> \"$GITHUB_OUTPUT\"' EXIT\n\n          is_pr=false\n          case \"$EVENT\" in pull_request|pull_request_target) is_pr=true ;; esac\n          labels=\"\"\n          if [ \"$is_pr\" = true ]; then\n            labels=$(jq -r '.[]?' <<<\"$LABELS\" 2>/dev/null || true)\n          fi\n          has_label() { grep -qxF -- \"$1\" <<<\"$labels\"; }\n\n          # `auto` is quick by default. A manual dispatch, a schedule and the\n          # `full-ci` label on a pull request make it full; a push to main\n          # stays quick. Any other value keeps its old meaning: `quick` is\n          # quick, anything else is full.\n          case \"${R_ACTIONS_PROFILE:-full}\" in\n            auto)\n              case \"$EVENT\" in\n                workflow_dispatch|schedule) ;;\n                *) has_label full-ci || profile=quick ;;\n              esac ;;\n            quick) profile=quick ;;\n          esac\n          echo \"profile: $profile\"\n\n          # Labels change pull request runs only. The push after merge\n          # carries none and is classified by its files, so anything a label\n          # skips here still runs on the default branch. `full-ci` asks for\n          # more checking, so it overrides every label that asks for less.\n          if [ -n \"$labels\" ] && ! has_label full-ci; then\n            if [ -n \"${R_ACTIONS_WORKFLOW:-}\" ] && has_label \"skip-ci:${R_ACTIONS_WORKFLOW}\"; then\n              docs_only=true scope=docs\n              echo \"Skipped by the \\`skip-ci:${R_ACTIONS_WORKFLOW}\\` label: every job in this workflow is skipped on this pull request.\" \\\n                | tee -a \"$GITHUB_STEP_SUMMARY\"\n              exit 0\n            fi\n            if has_label ci:minimal; then\n              docs_only=true scope=metadata\n              echo \"Reduced by the \\`ci:minimal\\` label: r-cmd-check runs its quick runner legs, and every other gated job is skipped on this pull request.\" \\\n                | tee -a \"$GITHUB_STEP_SUMMARY\"\n              exit 0\n            fi\n          fi\n\n          if [ \"$FILE_RULES\" != true ]; then\n            echo \"skip-docs-only is false, so the changed files are not consulted.\"\n            exit 0\n          fi\n\n          case \"$EVENT\" in\n            pull_request|pull_request_target)\n              base=$PR_BASE head=$PR_HEAD ;;\n            push)\n              # `before` is all zeros for a new branch, and after a\n              # force-push it may no longer exist.\n              if [ \"$FORCED\" = true ] || [ -z \"${BEFORE//0/}\" ]; then\n                echo \"New branch or force-push: no diff to go by, so everything runs.\"\n                exit 0\n              fi\n              base=$BEFORE head=$AFTER ;;\n            *)\n              echo \"A $EVENT run has no changed files to go by, so everything runs.\"\n              exit 0 ;;\n          esac\n\n          # The compare API rather than the pull request's file list, which\n          # would need `pull-requests: read`: a scope the caller may not hold,\n          # and asking for one is a startup_failure. Three dots diff from the\n          # merge base, which for a pull request is exactly what it changes,\n          # from its first commit on.\n          # A rename is listed under its new name, with the old one in\n          # previous_filename; both count, or `git mv R/x.R x.md` reads as a\n          # documentation-only change.\n          if ! files=$(gh api \"repos/$REPO/compare/$base...$head\" \\\n                         --jq '(.files // []) | length, (.[] | .filename, (.previous_filename // empty))'); then\n            echo \"Could not list the changed files, so everything runs.\"\n            exit 0\n          fi\n\n          # compare lists at most 300 files and truncates silently past that.\n          count=$(head -n 1 <<<\"$files\")\n          if ! [[ $count =~ ^[0-9]+$ ]] || [ \"$count\" -eq 0 ] || [ \"$count\" -ge 300 ]; then\n            echo \"Cannot rely on a list of '$count' changed files, so everything runs.\"\n            exit 0\n          fi\n\n          # The caller's own workflow file. In a called workflow\n          # `github.workflow_ref` is the caller's, `<repo>/<path>@<ref>`. An\n          # edit to that file is code -- a CI change has to test itself --\n          # while an edit to any other workflow in the repository changes\n          # nothing this workflow runs. If the ref is not in that shape,\n          # every workflow file counts as code.\n          caller=\"\"\n          case \"$WORKFLOW_REF\" in\n            \"$REPO\"/*@*) caller=${WORKFLOW_REF#\"$REPO\"/}; caller=${caller%%@*} ;;\n          esac\n\n          # Markdown in `tests/` is not documentation -- testthat snapshots\n          # and fixtures are .md -- and neither is Markdown under `fuzz/` or\n          # `inst/`, so .md counts only at the top level or under a dot\n          # directory, which a package does not ship.\n          #\n          # Repository housekeeping counts as documentation too: nothing here\n          # builds, installs or checks it. CRAN-SUBMISSION is\n          # devtools::submit_cran()'s record of the submitted commit, and\n          # .gitignore changes what git tracks, not what R CMD build ships\n          # (that is .Rbuildignore, which is code).\n          #\n          # DESCRIPTION and the README sources are `meta`: a version bump, a\n          # URL or a reworded Description is worth one check, not the\n          # sanitizers. README.Rmd is usually build-ignored, but it is\n          # executed to render README.md, so it is not treated as prose.\n          all_docs=true any_meta=false\n          while IFS= read -r f; do\n            case \"$f\" in\n              _pkgdown.yml|_pkgdown.yaml|pkgdown/*) kind=docs ;;\n              DESCRIPTION|README.Rmd|README.qmd) kind=meta ;;\n              CRAN-SUBMISSION|.gitignore|CODEOWNERS|.github/CODEOWNERS) kind=docs ;;\n              .github/ISSUE_TEMPLATE/*|.github/PULL_REQUEST_TEMPLATE*) kind=docs ;;\n              .github/dependabot.yml|.github/dependabot.yaml|.github/FUNDING.yml) kind=docs ;;\n              .github/workflows/*)\n                if [ -n \"$caller\" ] && [ \"$f\" != \"$caller\" ]; then kind=docs; else kind=code; fi ;;\n              .*/*.md) kind=docs ;;\n              */*) kind=code ;;\n              *.md) kind=docs ;;\n              *) kind=code ;;\n            esac\n            printf '%-5s %s\\n' \"$kind\" \"$f\"\n            case \"$kind\" in\n              docs) ;;\n              meta) any_meta=true ;;\n              *) all_docs=false ;;\n            esac\n          done < <(tail -n +2 <<<\"$files\")\n\n          if [ \"$all_docs\" = true ] && [ \"$any_meta\" = true ]; then\n            docs_only=true scope=metadata\n            echo \"Documentation and package metadata only: r-cmd-check runs its quick runner legs, and every other gated job is skipped.\" \\\n              | tee -a \"$GITHUB_STEP_SUMMARY\"\n          elif [ \"$all_docs\" = true ]; then\n            docs_only=true scope=docs\n            echo \"Documentation only: the jobs in this workflow are skipped.\" \\\n              | tee -a \"$GITHUB_STEP_SUMMARY\"\n          fi\n\n  alloc-failure:\n    needs: changes\n    if: ${{ !cancelled() && needs.changes.outputs.docs-only != 'true' }}\n    runs-on: ubuntu-latest\n    timeout-minutes: ${{ inputs.timeout-minutes }}\n\n    env:\n      GITHUB_PAT: ${{ secrets.GITHUB_TOKEN }}\n      R_KEEP_PKG_SOURCE: yes\n\n    steps:\n      - uses: actions/checkout@v7\n\n      - uses: r-lib/actions/setup-r@v2\n        with:\n          r-version: release\n\n      - uses: r-lib/actions/setup-r-dependencies@v2\n        with:\n          dependencies: '\"all\"'\n\n      - name: Install the package\n        run: R CMD INSTALL --preclean .\n\n      # Written here rather than vendored as a file, so there is one place to\n      # read and nothing to keep in sync.\n      #\n      # The awkward part is bootstrapping. dlsym itself may allocate on some\n      # libcs, and an interposed malloc that calls dlsym to find the real\n      # malloc would recurse forever. Allocations made while resolving are\n      # served from a static arena instead, and realloc has to recognise a\n      # pointer into that arena because the program will hand one back.\n      #\n      # So does free(), which is why it is interposed too. Arena memory is\n      # handed out while dlsym is resolving and to a calloc that arrives\n      # before the first resolution, and the program frees it like any other\n      # pointer. Passed to glibc, that is `free(): invalid pointer` and\n      # SIGABRT -- at exit, whether or not a failure was injected, so every\n      # swept run was reported as a crash and the sweep found nothing but\n      # its own interposer. `perl -e 1` is enough to show it;\n      # tests/check-alloc-interposer.sh does, on every pull request.\n      - name: Build the allocation interposer\n        run: |\n          set -eu\n          cat > failmalloc.c <<'CSRC'\n          #define _GNU_SOURCE\n          #include <dlfcn.h>\n          #include <errno.h>\n          #include <stdio.h>\n          #include <stdlib.h>\n          #include <string.h>\n\n          static void *(*real_malloc)(size_t);\n          static void *(*real_calloc)(size_t, size_t);\n          static void *(*real_realloc)(void *, size_t);\n          static void  (*real_free)(void *);\n\n          static long fail_at = 0;   /* 0 disables injection */\n          static long counter = 0;\n          static int  ready = 0;\n          static int  resolving = 0;\n\n          static char   arena[1 << 16];\n          static size_t arena_used = 0;\n\n          /* Each block carries its size in a 16-byte header, so a realloc\n             out of the arena copies what the block held -- not the new\n             size, which read past it, and past the arena at its end. */\n          static void *arena_alloc(size_t n) {\n            if (n > sizeof arena) return NULL;\n            size_t a = 16u + ((n + 15u) & ~(size_t)15u);\n            if (arena_used + a > sizeof arena) return NULL;\n            char *p = arena + arena_used;\n            arena_used += a;\n            *(size_t *)p = n;\n            return p + 16;\n          }\n\n          static size_t arena_size(void *p) {\n            return *(size_t *)((char *)p - 16);\n          }\n\n          static int from_arena(void *p) {\n            return (char *)p >= arena && (char *)p < arena + sizeof arena;\n          }\n\n          static void init(void) {\n            if (ready || resolving) return;\n            resolving = 1;\n            real_malloc  = (void *(*)(size_t))         dlsym(RTLD_NEXT, \"malloc\");\n            real_calloc  = (void *(*)(size_t, size_t)) dlsym(RTLD_NEXT, \"calloc\");\n            real_realloc = (void *(*)(void *, size_t)) dlsym(RTLD_NEXT, \"realloc\");\n            real_free    = (void (*)(void *))           dlsym(RTLD_NEXT, \"free\");\n            const char *e = getenv(\"ALLOC_FAIL_AT\");\n            fail_at = e ? atol(e) : 0;\n            resolving = 0;\n            ready = 1;\n          }\n\n          /* Counts every allocation whether or not one is being failed, so a\n             pass with injection off reports how many there are to sweep. */\n          static int should_fail(void) {\n            long n = ++counter;\n            return fail_at > 0 && n == fail_at;\n          }\n\n          void *malloc(size_t size) {\n            if (resolving) return arena_alloc(size);\n            init();\n            if (!real_malloc) return arena_alloc(size);\n            if (should_fail()) { errno = ENOMEM; return NULL; }\n            return real_malloc(size);\n          }\n\n          void *calloc(size_t nmemb, size_t size) {\n            if (resolving || !real_calloc) {\n              if (size && nmemb > (size_t)-1 / size) return NULL;\n              void *p = arena_alloc(nmemb * size);\n              if (!resolving) init();\n              if (p) memset(p, 0, nmemb * size);\n              return p;\n            }\n            init();\n            if (should_fail()) { errno = ENOMEM; return NULL; }\n            return real_calloc(nmemb, size);\n          }\n\n          void *realloc(void *ptr, size_t size) {\n            init();\n            if (from_arena(ptr)) {\n              void *p = malloc(size);\n              if (p) {\n                size_t old = arena_size(ptr);\n                memcpy(p, ptr, old < size ? old : size);\n              }\n              return p;\n            }\n            if (!real_realloc) return arena_alloc(size);\n            if (should_fail()) { errno = ENOMEM; return NULL; }\n            return real_realloc(ptr, size);\n          }\n\n          /* Arena memory is never returned: the arena is small, used only\n             during bootstrap, and not worth a free list. */\n          void free(void *ptr) {\n            if (ptr == NULL || from_arena(ptr)) return;\n            init();\n            if (real_free) real_free(ptr);\n          }\n\n          __attribute__((destructor))\n          static void report(void) {\n            const char *path = getenv(\"ALLOC_COUNT_FILE\");\n            if (!path) return;\n            FILE *f = fopen(path, \"w\");\n            if (!f) return;\n            fprintf(f, \"%ld\\n\", counter);\n            fclose(f);\n          }\n          CSRC\n          gcc -shared -fPIC -O1 -o failmalloc.so failmalloc.c -ldl\n          echo \"ok  interposer built\"\n\n      # Two counting passes, no injection. The floor is what the interpreter\n      # spends before the package is reached; the total is everything the\n      # workload allocates. The sweep is the gap between them.\n      - name: Measure the sweep range\n        id: range\n        env:\n          RUN_COMMAND: ${{ inputs.run }}\n          BASELINE_COMMAND: ${{ inputs.baseline-run }}\n          CAP: ${{ inputs.max-allocations }}\n        run: |\n          set -eu\n          export LD_PRELOAD=\"${GITHUB_WORKSPACE}/failmalloc.so\"\n\n          ALLOC_COUNT_FILE=\"${GITHUB_WORKSPACE}/floor.count\" \\\n            sh -c \"$BASELINE_COMMAND\" >/dev/null 2>&1 || true\n          # The uninjected run has to succeed: a typo in `run`, or a package\n          # that does not load, otherwise allocated next to nothing, swept no\n          # positions and reported \"all handled\".\n          status=0\n          ALLOC_COUNT_FILE=\"${GITHUB_WORKSPACE}/total.count\" \\\n            sh -c \"$RUN_COMMAND\" > run.log 2>&1 || status=$?\n          unset LD_PRELOAD\n\n          if [ \"$status\" -ne 0 ]; then\n            echo \"::error::\\`run\\` fails with no allocation failed (exit ${status}); fix the workload first\"\n            sed -n '1,40p' run.log\n            exit 1\n          fi\n\n          floor=$(cat floor.count 2>/dev/null || echo 0)\n          total=$(cat total.count 2>/dev/null || echo 0)\n\n          if [ \"$total\" -le 0 ]; then\n            echo \"::error::the interposer counted no allocations; LD_PRELOAD did not take effect\"\n            exit 1\n          fi\n\n          start=$((floor + 1))\n          end=\"$total\"\n          if [ \"$end\" -gt $((floor + CAP)) ]; then end=$((floor + CAP)); fi\n          if [ \"$start\" -gt \"$end\" ]; then\n            echo \"::error::the workload allocated nothing beyond interpreter startup, so there is nothing to sweep\"\n            exit 1\n          fi\n\n          echo \"floor=${floor}\" >> \"$GITHUB_OUTPUT\"\n          echo \"total=${total}\" >> \"$GITHUB_OUTPUT\"\n          echo \"start=${start}\" >> \"$GITHUB_OUTPUT\"\n          echo \"end=${end}\"     >> \"$GITHUB_OUTPUT\"\n          echo \"startup floor: ${floor}   workload total: ${total}\"\n          echo \"sweeping ${start}..${end}\"\n\n      # An exit status of 128+n is death by signal n, which is the finding\n      # this job exists for: the allocation failed, nothing handled it, and\n      # the process died rather than returning an error. An ordinary non-zero\n      # exit is the opposite -- the error was raised and propagated, which is\n      # what should happen.\n      - name: Sweep\n        id: sweep\n        env:\n          RUN_COMMAND: ${{ inputs.run }}\n          EXPECT: ${{ inputs.expect-pattern }}\n          TARGET: ${{ inputs.target-pattern }}\n          MIN_HITS: ${{ inputs.min-target-hits }}\n          START: ${{ steps.range.outputs.start }}\n          END: ${{ steps.range.outputs.end }}\n        run: |\n          set -eu\n          : > crashes.txt\n          : > silent.txt\n          checked=0\n          hits=0\n\n          n=\"$START\"\n          while [ \"$n\" -le \"$END\" ] && [ \"$END\" -gt 0 ]; do\n            checked=$((checked + 1))\n            set +e\n            LD_PRELOAD=\"${GITHUB_WORKSPACE}/failmalloc.so\" ALLOC_FAIL_AT=\"$n\" \\\n              sh -c \"$RUN_COMMAND\" > \"out.${n}\" 2>&1\n            status=$?\n            set -e\n\n            if [ -n \"$TARGET\" ] && grep -qE \"$TARGET\" \"out.${n}\"; then\n              hits=$((hits + 1))\n            fi\n\n            if [ \"$status\" -ge 128 ]; then\n              echo \"N=${n} died on signal $((status - 128))\"\n              {\n                echo \"### allocation ${n}: signal $((status - 128))\"\n                sed -n '1,20p' \"out.${n}\"\n              } >> crashes.txt\n            elif [ -n \"$EXPECT\" ] && [ \"$status\" -ne 0 ]; then\n              if ! grep -qE \"$EXPECT\" \"out.${n}\"; then\n                echo \"N=${n} failed without matching expect-pattern\"\n                {\n                  echo \"### allocation ${n}: exit ${status}, no match for /${EXPECT}/\"\n                  sed -n '1,20p' \"out.${n}\"\n                } >> silent.txt\n              fi\n            fi\n            rm -f \"out.${n}\"\n            n=$((n + 1))\n          done\n\n          crashes=$(grep -c '^### ' crashes.txt || true)\n          silent=$(grep -c '^### ' silent.txt || true)\n          echo \"checked=${checked}\" >> \"$GITHUB_OUTPUT\"\n          echo \"crashes=${crashes}\" >> \"$GITHUB_OUTPUT\"\n          echo \"silent=${silent}\"   >> \"$GITHUB_OUTPUT\"\n          echo \"hits=${hits}\"       >> \"$GITHUB_OUTPUT\"\n\n          {\n            echo \"## Allocation-failure injection\"\n            echo\n            echo \"| | |\"\n            echo \"|:--|--:|\"\n            echo \"| allocations before the workload | ${{ steps.range.outputs.floor }} |\"\n            echo \"| allocations in the workload | ${{ steps.range.outputs.total }} |\"\n            echo \"| failures injected | ${checked} |\"\n            echo \"| **died on a signal** | ${crashes} |\"\n            [ -z \"$EXPECT\" ] || echo \"| errored without matching the pattern | ${silent} |\"\n            [ -z \"$TARGET\" ] || echo \"| **reached the target** (/${TARGET}/) | ${hits} |\"\n            echo\n            if [ \"$crashes\" -gt 0 ]; then\n              echo '```'\n              cat crashes.txt\n              echo '```'\n            fi\n            if [ \"$silent\" -gt 0 ]; then\n              echo '```'\n              cat silent.txt\n              echo '```'\n            fi\n          } >> \"$GITHUB_STEP_SUMMARY\"\n\n          if [ \"$crashes\" -gt 0 ]; then\n            echo \"::error::${crashes} injected allocation failure(s) killed the process\"\n            exit 1\n          fi\n          if [ \"$silent\" -gt 0 ]; then\n            echo \"::error::${silent} injected failure(s) errored without matching expect-pattern\"\n            exit 1\n          fi\n          if [ -n \"$TARGET\" ]; then\n            echo \"${hits} of ${checked} injected failures reached the target (/${TARGET}/).\"\n            if [ \"$hits\" -lt \"$MIN_HITS\" ]; then\n              echo \"::error::only ${hits} injected failure(s) reached /${TARGET}/; min-target-hits is ${MIN_HITS}. The sweep is not reaching the code it is for.\"\n              exit 1\n            fi\n          fi\n          echo \"all ${checked} injected allocation failures were handled.\"\n\n      - uses: actions/upload-artifact@v7\n        if: always()\n        with:\n          name: alloc-failure\n          path: |\n            crashes.txt\n            silent.txt\n            failmalloc.c\n          if-no-files-found: ignore\n          retention-days: 7\n",
>   "encoding": "utf-8",
>   "sha": "fe9fdccb0e5441c829932eb195de072c73423cf7",
>   "display_url": "https://github.com/pedrobtz/r-actions/blob/v1/.github/workflows/alloc-failure.yml",
>   "display_title": "alloc-failure.yml"
> }
> ````
>
> MCP tool call
>
> codex_apps.github.fetch_file
>
> ```json
> {
>   "repository_full_name": "pedrobtz/r-actions",
>   "path": ".github/workflows/vendor.yml",
>   "ref": "v1"
> }
> ```
>
> ```text
> Action completed.
> ```
>
> ```json
> {
>   "content": "on:\n  workflow_call:\n    inputs:\n      vendor-dir:\n        description: >\n          Path to the vendored third-party sources, relative to the\n          repository root. Changes under here are what the guard watches.\n\n          Use `paths` instead when the vendored files are not a directory of\n          their own.\n        type: string\n        required: false\n        default: src/vendor\n      paths:\n        description: >\n          What counts as vendored, one entry per line, overriding\n          `vendor-dir` when set. An entry with no glob character is a\n          directory prefix; anything else is matched as a shell glob against\n          each changed path.\n\n          This exists because vendored code is not always a directory. A\n          package that bundles a C library and compiles it with its own\n          sources has both in `src/`, on purpose -- R CMD SHLIB builds one\n          flat directory, and a subdirectory costs an OBJECTS list and a\n          GNU-make dependency. A directory prefix cannot say \"the bundled\n          files and not mine\", so the guard either watches nothing or fires\n          on every commit, and a guard that fires on everything is one people\n          learn to ignore.\n\n              paths: |\n                src/cyaml*.c\n                src/cyaml*.h\n        type: string\n        required: false\n        default: \"\"\n      verify:\n        description: >\n          Script that checks the vendored tree against its manifest, run\n          from the repository root. Skipped if the file does not exist, so a\n          package can adopt the PR guard before it has a verifier.\n        type: string\n        required: false\n        default: tools/vendor/verify\n      must-update:\n        description: >\n          Files a PR touching `vendor-dir` must also change, one path per\n          line. The point is that vendored code is only ever updated through\n          the fetch-and-record tooling: a hand edit that skips the manifest\n          leaves a tree nobody can reproduce, and a manifest update that\n          skips the checksums leaves one nobody can verify.\n        type: string\n        required: false\n        default: |\n          tools/vendor/manifest.tsv\n          tools/vendor/checksums.sha256\n\nname: vendor\n\n# Nothing here writes through the token, so `contents: read` is enough: the\n# job reads the checkout, and artifact upload, the cache and a public ghcr.io\n# image each need no declared scope.\n#\n# This is not only least privilege. `read-all` is wider than the `read` that a\n# repository hands its GITHUB_TOKEN by default, and a called workflow cannot\n# be granted more than its caller holds -- so requesting it here made every\n# caller that did not declare permissions of its own fail with an unannotated\n# `startup_failure`, two seconds in, before any job was created.\npermissions:\n  contents: read\n\njobs:\n  vendor:\n    runs-on: ubuntu-latest\n    name: vendored sources match manifest\n    steps:\n      # Full history: the guard diffs against the PR's base.\n      - uses: actions/checkout@v7\n        with:\n          fetch-depth: 0\n\n      # Inputs reach the scripts below through `env:`, never pasted into\n      # them: a quote, `$` or backtick in a pasted value is shell syntax.\n      - name: Verify the vendored tree\n        env:\n          VERIFY: ${{ inputs.verify }}\n        run: |\n          set -eu\n          if [ ! -e \"$VERIFY\" ]; then\n            echo \"No ${VERIFY}; skipping tree verification.\"\n            exit 0\n          fi\n          chmod +x \"$VERIFY\" 2>/dev/null || true\n          \"./${VERIFY}\"\n\n      # Reproducibility is the property being defended, and it is a property\n      # of the commit, not of the working tree -- so it has to be checked on\n      # the diff. A verifier alone passes happily on a hand-edited file whose\n      # checksum was re-recorded to match it.\n      - name: Vendored changes must update the manifest\n        if: github.event_name == 'pull_request'\n        env:\n          BASE_REF: ${{ github.base_ref }}\n          PATHS: ${{ inputs.paths }}\n          VENDOR_DIR: ${{ inputs.vendor-dir }}\n          MUST_UPDATE: ${{ inputs.must-update }}\n        run: |\n          set -eu\n          base=\"origin/${BASE_REF}\"\n          # Not --depth=1. A shallow fetch writes .git/shallow and grafts\n          # the base ref, so its ancestry cannot be walked and `$base...HEAD`\n          # has no merge base to resolve:\n          #\n          #   fatal: origin/main...HEAD: no merge base\n          #\n          # which is exit 128, and set -e fails the step before the guard has\n          # looked at a single path. It is intermittent, which is worse than\n          # being broken: it passes whenever the fork point happens to be at\n          # or after the graft, and fails as soon as the base has moved ahead\n          # of where the branch forked -- exactly what happens while a stack\n          # of pull requests is being merged one at a time.\n          #\n          # The checkout above is already fetch-depth: 0, so a full fetch\n          # costs nothing here. The unshallow branch is for a caller whose\n          # checkout was shallow before this step ran: once .git/shallow\n          # exists, an ordinary fetch does not remove it.\n          if [ -f \"$(git rev-parse --git-dir)/shallow\" ]; then\n            git fetch --no-tags --unshallow origin \"$BASE_REF\"\n          else\n            git fetch --no-tags origin \"$BASE_REF\"\n          fi\n          # Three dots, deliberately: the guard asks what this pull request\n          # changed, not how it differs from a base that may have moved\n          # underneath it. Two dots would blame a branch for vendored changes\n          # someone else landed on the base while it was open.\n          changed=$(git diff --name-only \"$base\"...HEAD)\n          printf '%s\\n' \"$changed\" > /tmp/vendor-changed-all\n\n          # `paths` wins when set; otherwise the directory, as a prefix.\n          if [ -n \"$PATHS\" ]; then\n            printf '%s\\n' \"$PATHS\" > /tmp/vendor-patterns\n            what='the vendored paths'\n          else\n            dir=\"$VENDOR_DIR\"\n            printf '%s\\n' \"${dir%/}\" > /tmp/vendor-patterns\n            what=\"$(printf '%s/' \"${dir%/}\")\"\n          fi\n\n          # An entry with no glob character is a directory prefix; anything\n          # else is a glob. `case` does the matching, so the pattern must stay\n          # unquoted on the right -- quoting it would compare literals and the\n          # guard would silently match nothing.\n          : > /tmp/vendor-touched\n          while IFS= read -r file; do\n            [ -n \"$file\" ] || continue\n            while IFS= read -r pat; do\n              [ -n \"$pat\" ] || continue\n              hit=\"\"\n              case \"$pat\" in\n                *[*?[]*) case \"$file\" in $pat) hit=1 ;; esac ;;\n                *)       case \"$file\" in \"${pat%/}\"/*) hit=1 ;; esac ;;\n              esac\n              if [ -n \"$hit\" ]; then\n                printf '%s\\n' \"$file\" >> /tmp/vendor-touched\n                break\n              fi\n            done < /tmp/vendor-patterns\n          done < /tmp/vendor-changed-all\n\n          if [ ! -s /tmp/vendor-touched ]; then\n            echo \"ok  no changes to $what in this PR\"\n            exit 0\n          fi\n\n          echo \"This PR changes $what:\"\n          sed 's/^/  /' /tmp/vendor-touched\n\n          # Read from a file, not a pipe: a `while` on the right of a pipe\n          # runs in a subshell, so a failure recorded inside it is lost\n          # unless it is propagated by hand -- and a guard that cannot fail\n          # is the thing this workflow exists to avoid.\n          printf '%s\\n' \"$MUST_UPDATE\" > /tmp/vendor-required\n          printf '%s\\n' \"$changed\" > /tmp/vendor-changed\n          missing=0\n          while IFS= read -r want; do\n            [ -n \"$want\" ] || continue\n            if ! grep -qxF -- \"$want\" /tmp/vendor-changed; then\n              echo\n              echo \"FAIL vendored sources changed without updating $want.\"\n              missing=1\n            fi\n          done < /tmp/vendor-required\n          if [ \"$missing\" -ne 0 ]; then\n            echo\n            echo \"     Vendored code is only ever updated through the fetch\"\n            echo \"     and record tooling, so the tree stays reproducible.\"\n            exit 1\n          fi\n          echo \"ok  every required file was updated alongside\"\n",
>   "encoding": "utf-8",
>   "sha": "db55b8607d0339f260ebb200fd61648f10969960",
>   "display_url": "https://github.com/pedrobtz/r-actions/blob/v1/.github/workflows/vendor.yml",
>   "display_title": "vendor.yml"
> }
> ```
>
> - Ran `cat > /tmp/zucrypt-review.uZCa8D/link-collision.c <<'C'
> #include <zucrypt.h>
> /* Represents another backend linked into the same consumer. */
> int psa_crypto_init(void) { return 0; }
> int main(void) {
>     unsigned char out[32];
>     size_t n = 0;
>     if (zuc_init() != ZUC_OK) return 1;
>     return (int) zuc_hash_compute(ZUC_ALG_SHA256, 0, 0, out, sizeof out, &n);
> }
> C
> cc -Iinst/include /tmp/zucrypt-review.uZCa8D/link-collision.c /tmp/zucrypt-review.uZCa8D/lib/zucrypt/lib/libzucrypt.a -o /tmp/zucrypt-review.uZCa8D/link-collision > /tmp/zucrypt-review.uZCa8D/collision.log 2>&1
> cat /tmp/zucrypt-review.uZCa8D/collision.log`
>
> - Ran `git status --short; python3 - <<'PY'
> from pathlib import Path
> base = Path('src/vendor')
> copy = Path('/tmp/zucrypt-review.uZCa8D/vendor-repro/src/vendor')
> files = [p for p in base.rglob('*') if p.is_file() and p.suffix not in ('.o', '.so', '.dll')]
> changed = [str(p) for p in files if not (copy/p.relative_to(base)).is_file() or p.read_bytes() != (copy/p.relative_to(base)).read_bytes()]
> print('Re-fetched vendored source files:', len(files), 'Differences:', changed)
> PY`
>
> </details>
</details>

A senior reviewer would likely say: **the overall architecture is thoughtful, but some build and testing guarantees are stronger in the comments than in the evidence.** I would request changes to rebuild correctness, then strengthen the tests around the published C interface.

I reviewed the current checkout without changing tracked files. Locally:

- The package installed cleanly; **1,076 expectations passed**.
- Both C consumer fixtures passed.
- Vendor and layering checks passed.
- Downloading the pinned upstream archive and applying your patches reproduced **all 113 vendored files exactly**.

These are the items I would flag, in priority order.

1. **Confirmed build bug: header changes do not reliably rebuild the native code.**
   See [src/Makevars](./src/Makevars:125).

   The objects have no declared dependencies on the configuration and other headers. I reproduced the consequence in a temporary copy: after changing the configuration to force software AES, an ordinary `R CMD INSTALL` reused the existing objects and still reported `aesce`. Installing with `--preclean` correctly produced `software`.

   This can make you test or ship code that does not match the configuration you just reviewed. Configuration changes can also become dangerous if only some objects rebuild, because backend structures depend on those settings.

   **Review further:** add header dependencies and ensure relevant `Makevars` changes trigger recompilation. Until then, require clean builds after native configuration changes.

2. **Integration limitation: hidden symbols do not fully isolate the static archive.**
   See [src/Makevars](./src/Makevars:32).

   Your visibility settings successfully isolate backend copies in separate shared libraries. However, `libzucrypt.a` still contains ordinary upstream names such as `psa_crypto_init`. If a downstream package links another PSA/Mbed TLS implementation into the **same shared library**, the symbols can conflict.

   I confirmed a duplicate-symbol link failure with a small consumer supplying another `psa_crypto_init` definition. Your existing separate-library coexistence tests do not cover this case.

   **Review further:** decide whether this combination is unsupported and document it, or namespace the vendored symbols. Treat this as a limitation of the provider interface, rather than assuming visibility solves every collision.

3. **The allocation-failure tests do not establish everything they claim.**
   See [tools/alloc-exercise.R](./tools/alloc-exercise.R:54).

   The digest checks accept any nonempty raw vector; HMAC checks only the length. A wrong result of the expected length can pass. AES is checked through a round trip, which can miss matching mistakes in encryption and decryption.

   Also, an injected failure normally terminates that process. That checks error reporting and crashes, but does not prove that partial initialization released every allocation or that another operation succeeds afterward.

   **Review further:** use fixed expected bytes in this workload. Add targeted tests that catch an injected failure, collect finalizers, check resource ownership, and perform a known-good operation in the same process. I found a testing gap here, not a demonstrated leak.

4. **The ABI size test cannot detect the overwrite it is meant to prevent.**
   See [src/zucrypt_test.c](./src/zucrypt_test.c:444).

   `zucrypt_test_info_size()` always allocates a complete current `zuc_info`, changes its `struct_size`, and checks the returned status. If the implementation accidentally wrote newer fields beyond the advertised prefix, those writes would still land inside the allocated object and the test could pass.

   **Review further:** verify that bytes beyond the advertised size remain unchanged, and retain a consumer compiled against a frozen older header. The implementation currently appears to respect the size checks; the concern is protecting that promise against future regressions.

5. **Vendor CI checks consistency, but does not prove reproduction from upstream.**
   See [vendor.yaml](./.github/workflows/vendor.yaml:4).

   The offline verifier is useful. Requiring a vendor change to also modify the manifest and checksums is useful too. But those conditions can still pass when a handwritten change was never captured in a patch: changing a manifest field does not establish that `fetch` reconstructs the committed tree.

   **Review further:** add a clean-directory reproduction job that downloads the pinned archive, applies the declared patches, and compares the resulting tree and checksums with the checkout.

   Your **current tree passed this exact reproduction check** when I ran it. This is about making that evidence an enforced property.

6. **Several lifecycle tests can pass without exercising the intended failure point.**
   See [test-lifetime.R](./tests/testthat/test-lifetime.R:41).

   The “native failure leaves no live context” test supplies an invalid AES key length. That fails before the context is allocated, so it does not test cleanup after partial construction.

   The interruption tests establish that a time limit fired and the context count eventually returned to baseline. They do not establish that the interruption happened while a native context existed; on a slow or instrumented build, it could happen earlier.

   Similarly, the coexistence script describes both libraries holding live key state, but its wrapper calls complete and free their contexts sequentially. See [check-linking.sh](./tools/check-linking.sh:139).

   **Review further:** introduce deterministic failure points after context creation or a selected update. For coexistence, hold contexts from both providers simultaneously and exercise one while the other is live.

7. **The Linux RNG path needs explicit failure-path testing before it becomes active functionality.**
   See [src/zuc_random.c](./src/zuc_random.c:86).

   The loop handles short reads, but returns an entropy error on `EINTR` instead of retrying. This fails safely, but can turn an interrupted system call into an unnecessary operation failure.

   **Review further:** test interrupted reads, short reads, and permanent errors through an injectable system-call wrapper. This is lower priority today because the current public operations do not consume randomness.

There is also a **production policy decision**, already documented well: the software AES fallback uses secret-dependent table accesses. Upstream explicitly warns about timing attacks and possible key recovery. A company might require an option that refuses AES when hardware acceleration is unavailable. That is an acceptance decision for the intended environment, not evidence that your wrapper computes AES incorrectly. [Upstream security policy](https://github.com/Mbed-TLS/TF-PSA-Crypto/security)

What I would positively call out is the separation between the R glue and the R-free adapter, opaque handles, explicit ownership, independent known-answer vectors, small documented patches, and honest documentation about static consumers needing rebuilds for security updates. Those are sound engineering choices.

For your next learning iteration, I would prioritize **rebuild correctness, deterministic failure tests, and ABI overwrite tests**. They would improve confidence more than adding another algorithm or another broad CI job.

> make suggestions on these points: For your next learning iteration, I would prioritize **rebuild correctness, deterministic failure tests, and ABI overwrite tests**.

<details><summary>2 previous messages</summary>

> I’ll suggest concrete changes and acceptance checks for each priority, using your existing build rules and test harness.
>
> <details><summary>Explored 10 files, a search, searched the web</summary>
>
> <details><summary>Explored 8 files</summary>
>
> - Read `./src/Makevars`
> - Read `./src/zuc_backend.c`
> - Read `./src/zuc_live.h`
> - Read `./src/zucrypt_crypt.c`
> - Read `./src/zucrypt_test.c`
> - Read `./tests/testthat/test-adapter.R`
> - Read `./.github/workflows/abi.yaml`
> - Read `./inst/include/zucrypt.h`
>
> </details>
>
> Searched the web for `https://stat.ethz.ch/R-manual/R-devel/doc/manual/R-exts.html#Using-Makevars`
>
> <details><summary>Explored 3 files, a search</summary>
>
> - Read `./src/zuc_hash.c`
> - Read `./src/zuc_aes.c`
> - Read `./inst/include/zucrypt.h`
> - Searched for `upstream|dependencies|Makevars|Unwind` in `stage-1-spike.md`
>
> </details>
>
> </details>
</details>

I would make these **three small pull requests**, each with a clear acceptance test.

1. **Rebuild correctness: make the compiled code follow its inputs.**

   In [src/Makevars](./src/Makevars:125), add explicit dependencies for:

   - All objects → `Makevars` and the public header.
   - Adapter and vendor objects → `zuc_crypto_config.h` and the vendored headers.
   - Adapter objects → their internal headers.
   - R glue → the additional headers each file includes.
   - `libzucrypt.a` → its adapter objects and `Makevars`.

   For this package, I would initially use **conservative dependencies**: rebuilding all backend objects when any vendored header changes is acceptable. Optimizing rebuild speed can come later. Keep an explicit header list, generated by maintainer tooling and committed alongside the vendor file list. This preserves your portable-make approach. R’s manual also emphasizes declaring the necessary build dependencies. [Writing R Extensions](https://stat.ethz.ch/R-manual/R-devel/doc/manual/R-exts.html#Using-Makevars)

   **Acceptance test:** in a temporary checkout, install normally, edit the configuration to force software AES, then reinstall **without `--preclean`**. Assert that `crypt_info()` reports `"software"`. Restore the configuration, reinstall again, and verify the original implementation returns. Check the static archive consumer too.

   Changing compiler flags through environment variables still needs a clean build unless you explicitly track those changes; document that distinction.

2. **Deterministic failure tests: choose exactly where an operation fails.**

   Extend the existing harness around [zucrypt_crypt.c](./src/zucrypt_crypt.c:127) and the adapter constructors. Start with a few private failure points:

   | Failure point | What it verifies |
   |---|---|
   | Adapter allocation fails | Returns `ZUC_ERR_MEMORY`; output handle remains `NULL` |
   | Backend setup fails after adapter allocation | Partially constructed context is released |
   | HMAC setup fails after key import | Imported key and context are released |
   | R error occurs after context ownership is established | External-pointer finalizer releases the context |
   | Error occurs after the first processed chunk | Cleanup works after actual processing |

   Use test-build hooks that are disabled in ordinary builds. Keep them outside the public ABI and avoid editing the vendored cryptographic implementation.

   For each case, require **the expected error, cleanup, and successful reuse afterward**. Catch the failure, disable injection, run `gc()` where finalizers are involved, and perform another operation against fixed expected bytes.

   One important detail: your current live-context counter increments only after successful construction. It cannot detect every leak during partial construction. Supplement it with allocation/key ownership accounting or run these targeted cases under leak detection.

   **Acceptance test:** each named failure point is demonstrably reached, resources return to baseline, and the next operation produces the correct result. Keep the existing allocation sweep and timing-based interruption tests as additional coverage.

3. **ABI overwrite tests: inspect the bytes the library must leave alone.**

   Strengthen [zucrypt_test_info_size()](./src/zucrypt_test.c:444). Continue allocating a properly aligned `zuc_info`, but:

   - Fill it with a recognizable byte pattern.
   - Set `struct_size` and snapshot the bytes.
   - Call `zuc_get_info()`.
   - Check the status and every field fully covered by the advertised size.
   - Verify every byte beyond that size remains unchanged.

   Exercise these boundaries:

   | Advertised size | Expected behavior |
   |---|---|
   | Below `ZUC_INFO_REQUIRED_SIZE` | `ZUC_ERR_ABI`, with no writes |
   | Exactly the required prefix | Success; trailing bytes unchanged |
   | One byte short of an optional field’s end | That field remains untouched |
   | Exactly an optional field’s end | That field is populated |
   | Current structure size | All current fields are populated |

   Also surround the structure with guard bytes to catch writes beyond the complete object.

   **Acceptance test:** temporarily remove one size guard from `zuc_get_info()` in a disposable checkout. The new test must fail. That demonstrates the test detects the regression you care about.

   After this, add a consumer fixture containing a frozen older header. Compile it separately against the current provider so compatibility checks do not depend entirely on today’s shared declarations.

I would implement them in that order: the build fix first ensures subsequent tests actually execute the code you changed.

> any other soundess and correctness issues the senior developer may find reviewing this toy project?

<details><summary>4 previous messages</summary>

> I’ll take another pass through the native API and integration boundaries, looking for additional correctness issues. I’ll separate reproducible problems from design limitations and avoid repeating the earlier findings.
>
> <details><summary>Explored 5 files, a search, ran 3 commands</summary>
>
> - Ran `git status --short; cat src/zuc_status.c; sed -n '1,230p' src/zuc_hash.c; sed -n '230,460p' src/zuc_hash.c`
>
> <details><summary>Explored 5 files, a search</summary>
>
> - Read `./R/conditions.R`
> - Read `./R/aes.R`
> - Read `./R/hex.R`
> - Read `./R/hash.R`
> - Searched for `TYPEOF|XLENGTH|Rf_asLogical|RAW\(` in `zucrypt_crypt.c`
> - Read `./tools/zucryptlink/src/link.c`
>
> </details>
>
> - Ran `R_LIBS=/tmp/zucrypt-review.uZCa8D/lib Rscript --vanilla - <<'RS'
> library(zucrypt)
> length.review_raw <- function(x) 1L
> x <- structure(raw(0), class = "review_raw")
> y <- as.raw(1)
> cat("is.raw(x):", is.raw(x), "reported length:", length(x), "actual length:", length(unclass(x)), "\n")
> cat("crypt_equal(x, y):", crypt_equal(x, y), "\n")
> cat("crypt_equal(y, x):", crypt_equal(y, x), "\n")
> RS`
>
> - Ran `cat tools/zucryptlink/configure tools/zucryptlink/configure.win; nl -ba inst/include/zucrypt-r.h | sed -n '185,211p'; cat .github/workflows/R-CMD-check.yaml | tail -35; cat NAMESPACE`
>
> </details>
>
> I found a more serious issue: a classed raw vector can override R’s `length()`, while the C code uses its actual length. In a disposable R process, this made `crypt_equal()` return `TRUE` for unequal vectors; reversing the arguments crashed R. I’m checking the other places that rely on R-side length validation.
>
> <details><summary>Explored 3 files, 5 searches, ran 7 commands, searched the web</summary>
>
> - Ran `rg -n '^psa_status_t psa_hash_update|^psa_status_t psa_mac_update|psa_hash_abort\(operation\)|psa_mac_abort\(operation\)' src/vendor/tf-psa-crypto/lib/psa_crypto.c; sed -n '2240,2372p' src/vendor/tf-psa-crypto/lib/psa_crypto.c; sed -n '2715,2805p' src/vendor/tf-psa-crypto/lib/psa_crypto.c; rg -n '^SEXP|R_alloc|PROTECT|UNPROTECT|stop_on|Rf_error' src/zucrypt_test.c | tail -110; cat tools/make-kat.R | head -110; git status --short`
>
> <details><summary>Explored 5 files, 5 searches</summary>
>
> - Read `./src/vendor/tf-psa-crypto/lib/psa_crypto.c`
> - Searched for `LOCAL_OUTPUT_ALLOC|LOCAL_INPUT_ALLOC|LOCAL_OUTPUT_FREE` in `psa_crypto_core.h`
> - Searched for `hash_setup|calloc|malloc|hash_abort` in `psa_crypto_hash.c`
> - Read `./src/vendor/tf-psa-crypto/lib/psa_crypto_hash.c`
> - Searched for `define LOCAL_OUTPUT_ALLOC` in `psa_crypto_core_common.h`
> - Searched for `psa_mac_sign_finish|psa_mac_finish_internal` in `psa_crypto.c`
> - Searched for `define LOCAL_OUTPUT_ALLOC|define LOCAL_INPUT_ALLOC|define LOCAL_OUTPUT_FREE|define LOCAL_INPUT_FREE|MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS` in `tf-psa-crypto`
> - Read `./src/vendor/tf-psa-crypto/lib/psa_crypto.c`
> - Read `./src/vendor/tf-psa-crypto/lib/psa_crypto_hash.c`
> - Read `./src/vendor/tf-psa-crypto/lib/psa_crypto_mac.c`
>
> </details>
>
> - Ran `python3 - <<'PY'
> s='sixteen bytes!! and sixteen more'
> print(len(s))
> PY
> rg -n 'PKG_LIBS|sed -e|configure|ZUCRYPT_LIB' vignettes/articles/c-api.Rmd; sed -n '185,304p' src/vendor/tf-psa-crypto/lib/psa_crypto.c; sed -n '335,383p' src/zucrypt_test.c; cat tests/testthat/test-hex.R; rg -n 'psa_hash_operation_init|PSA_HASH_OPERATION_INIT' src/vendor/tf-psa-crypto/inc/psa/crypto_struct.h`
>
> Searched the web for `site.gcc.gnu.org "Even with" "C++" "type-punning" union ...`
>
> - Ran `nl -ba src/zucrypt_crypt.c | sed -n '353,376p;411,433p'; nl -ba R/hash.R | sed -n '157,175p'; nl -ba tools/zucryptlink/configure | tail -14; nl -ba tests/testthat/test-size.R | sed -n '47,87p'; nl -ba src/zuc_hash.c | sed -n '123,137p;345,363p'; rg -n 'local_input_alloc|local_output_alloc|mbedtls_calloc' src/vendor/tf-psa-crypto/lib/psa_util_internal.c | head -25; nl -ba src/zuc_hash.c | sed -n '203,232p'; git status --short`
>
> - Ran `ZUCRYPT_LIB='/tmp/r&lib/zucrypt/lib'
> printf "PKG_LIBS = '@ZUCRYPT_LIB@/libzucrypt.a'\n" | sed -e "s|@ZUCRYPT_LIB@|${ZUCRYPT_LIB}|g"
> ZUCRYPT_LIB="/tmp/O'Connor/zucrypt/lib"
> printf "PKG_LIBS = '@ZUCRYPT_LIB@/libzucrypt.a'\n" | sed -e "s|@ZUCRYPT_LIB@|${ZUCRYPT_LIB}|g"`
>
> - Ran `rg -n 'psa_crypto_local_input_alloc|psa_crypto_local_output_alloc' src/vendor/tf-psa-crypto/lib/*.c; sed -n '80,150p' src/vendor/tf-psa-crypto/lib/psa_util.c; sed -n '1470,1550p' src/vendor/tf-psa-crypto/lib/psa_crypto.c; cat src/zuc_util.c | tail -42; nl -ba vignettes/articles/c-api.Rmd | sed -n '62,86p'`
>
> Searched the web for `https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html`
>
> - Ran `cat > /tmp/zucrypt-review.uZCa8D/update-failure.c <<'C'
> #include <zucrypt.h>
> #include <stdio.h>
> #include <stdlib.h>
> #include <string.h>
> static int fail_next_calloc = 0;
> void *calloc(size_t count, size_t size) {
>     if (fail_next_calloc) { fail_next_calloc = 0; return NULL; }
>     if (size && count > (size_t)-1 / size) return NULL;
>     size_t n = count * size;
>     void *p = malloc(n);
>     if (p) memset(p, 0, n);
>     return p;
> }
> int main(void) {
>     zuc_hash *h = NULL;
>     unsigned char input = 42;
>     if (zuc_init() != ZUC_OK || zuc_hash_new(ZUC_ALG_SHA256, &h) != ZUC_OK) return 2;
>     fail_next_calloc = 1;
>     printf("failed update: %s\n", zuc_status_name(zuc_hash_update(h, &input, 1)));
>     printf("next empty update: %s\n", zuc_status_name(zuc_hash_update(h, NULL, 0)));
>     printf("next byte update: %s\n", zuc_status_name(zuc_hash_update(h, &input, 1)));
>     printf("reset: %s\n", zuc_status_name(zuc_hash_reset(h)));
>     zuc_hash_free(h);
>     zuc_shutdown();
>     return 0;
> }
> C
> cc -std=c99 -fno-builtin-calloc -Iinst/include /tmp/zucrypt-review.uZCa8D/update-failure.c /tmp/zucrypt-review.uZCa8D/lib/zucrypt/lib/libzucrypt.a -o /tmp/zucrypt-review.uZCa8D/update-failure
> /tmp/zucrypt-review.uZCa8D/update-failure`
>
> - Ran `sed -n '9731,9814p' src/vendor/tf-psa-crypto/lib/psa_crypto.c; git status --short`
>
> </details>
</details>

Yes. A second pass found **one important memory-safety bug**, plus several smaller correctness and portability issues. These are additional to the earlier build and testing findings.

1. **High priority — R-side length checks can be bypassed, causing incorrect comparisons or a crash.**

   [crypt_equal()](./R/hash.R:162) compares lengths in R, but [its native implementation](./src/zucrypt_crypt.c:411) uses `XLENGTH(x)` without checking `XLENGTH(y)`.

   R’s `length()` can dispatch a class method, so its answer need not equal the underlying vector length. This is documented behavior. [R internal generics](https://www.stat.ethz.ch/R-manual/R-devel/library/base/html/InternalMethods.html)

   I reproduced this through the exported function:

   ```r
   length.review_raw <- function(x) 1L

   x <- structure(raw(0), class = "review_raw")
   y <- as.raw(1)

   zucrypt::crypt_equal(x, y)
   # TRUE — incorrect: the underlying vectors have different lengths
   ```

   **Reversing the arguments crashed an isolated R process**, because C attempted to read beyond the empty vector.

   The same underlying assumption appears in AES: [the native wrapper](./src/zucrypt_crypt.c:373) copies 16 IV bytes without checking the IV’s actual native length. The hex string limit is also checked only through R’s `length()`.

   **Suggested fix:** enforce every memory-safety precondition in C using `TYPEOF()` and `XLENGTH()`, before accessing buffers or calculating allocation sizes. Keep R validation for helpful diagnostics. Add regression tests with classed raw vectors.

   This is the next issue I would fix.

2. **Medium priority — context state becomes inconsistent after a backend update failure.**

   In [zuc_hash_update()](./src/zuc_hash.c:123), the adapter returns the backend error but leaves `hash->active` unchanged. The backend can abort its operation on failure.

   Using a standalone C probe that deliberately failed the next allocation, I obtained:

   ```text
   failed update:     ZUC_ERR_MEMORY
   next empty update: ZUC_OK
   next byte update:  ZUC_ERR_INTERNAL
   reset:             ZUC_OK
   ```

   The adapter reports success for an update on an operation the backend has already invalidated.

   **Suggested fix:** define the error-state contract explicitly. A straightforward policy is: a backend update failure aborts the operation and marks the handle inactive; callers must reset or free it. Apply a consistent policy to hashes and HMAC.

   Test this sequence directly. I did not establish a leak here; the confirmed issue is inconsistent state and error reporting.

3. **Medium priority — the documented static-linking recipe mishandles valid library paths.**

   [The consumer’s configure script](./tools/zucryptlink/configure:38) inserts the archive path into a `sed` replacement without escaping it. The generated linker argument then surrounds the path with single quotes.

   I confirmed that a path containing `&` produces a corrupted substitution:

   ```text
   Input:  /tmp/r&lib/zucrypt/lib
   Output: /tmp/r@ZUCRYPT_LIB@lib/zucrypt/lib/libzucrypt.a
   ```

   An apostrophe, such as in `O'Connor`, breaks the generated shell quoting.

   This affects the fixture and [the integration recipe you publish](./vignettes/articles/c-api.Rmd:72), rather than ordinary calls to the R functions.

   **Suggested fix:** handle template replacement, make syntax, and shell quoting as separate escaping problems. Extend the consumer installation tests beyond spaces to include `&` and apostrophes.

4. **Portability concern — the registered-table header relies on a C++ extension.**

   [zucrypt-r.h](./inst/include/zucrypt-r.h:199) writes one union member containing a function pointer, then reads another member with a different function-pointer type.

   GCC supports this technique as an extension, but its documentation explicitly identifies union type-punning as undefined behavior in ISO C++. This is a portability concern; I did not reproduce a failure on your current compiler. [GCC documentation](https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html#index-fstrict-aliasing)

   **Suggested fix:** use a language-appropriate function-pointer conversion and address any compiler diagnostic narrowly. Add a C++ consumer that actually resolves and calls the table. Your current C++ check only includes the standalone `zucrypt.h` header.

5. **Testing limitation — the memory-allocation test cannot see backend allocations.**

   [test-size.R](./tests/testthat/test-size.R:59) uses `Rprofmem()` to reason about allocations during processing. That profiler observes R-managed allocations, rather than arbitrary allocations inside the backend. [Rprofmem documentation](https://stat.ethz.ch/R-manual/R-devel/library/utils/html/Rprofmem.html)

   Your configured PSA implementation allocates and copies input buffers during updates; see [psa_crypto_local_input_alloc()](./src/vendor/tf-psa-crypto/lib/psa_crypto.c:9731). Those allocations are invisible to this test.

   **Suggested fix:** describe the existing test as checking R allocation behavior. If native allocation frequency matters, measure it with allocator instrumentation. Investigate the backend’s copying policy before changing it, since it serves a security purpose.

The main lesson from the newly reproduced crash is concrete: **R validation improves the interface, but C must independently verify the lengths that govern memory access.** All tracked files remain unchanged.

> write all the findings (and include all previous details and information) into a new file 'review-codex.md' as itemized list, with a number B1,B2,... with title and description, in the description include all relevant details you found and possible examples how to test verify the issue/bug.

<details><summary>3 previous messages</summary>

> Stream error
>
> Reconnecting 5/5
> stream disconnected before completion: failed to lookup address information: nodename nor servname provided, or not known
>
> Stream error
>
> Reconnecting... waiting for network
> Connection failed: error sending request
>
> Stream error
>
> Reconnecting... waiting for network
> Connection failed: error sending request
</details>
