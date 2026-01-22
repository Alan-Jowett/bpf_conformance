# Copilot instructions for bpf_conformance

## Big picture
- The core runner is `src/bpf_conformance_runner` (see `src/runner.cc`) which:
  - reads `.data` test files,
  - assembles `-- asm` into eBPF instructions (or uses `-- raw` 64-bit instruction words),
  - invokes an external **plugin process** to execute the program,
  - compares the plugin’s final `%r0` (stdout) or expected error (stderr).
- The conformance library entry point is `bpf_conformance_options()` in `src/bpf_conformance.cc` (public API in `include/bpf_conformance.h`).
- Plugins implement the execution contract described in `README.md` (notably: program is provided via stdin; plugin prints `%r0` in hex and exits 0 on success).

## Build & CI workflow
- Configure/build (all platforms):
  - `cmake -S . -B build`
  - `cmake --build build`
- Repo uses git submodules (e.g., `external/elfio`); CI checks out with `submodules: recursive`.
- Windows builds fetch Boost via `nuget` during CMake configure (see `src/CMakeLists.txt`).
- CI runs tests only on Ubuntu via `cmake --build build --target test --` (see `.github/workflows/Build.yml`).

## Running tests locally
- Typical (Linux kernel + libbpf plugin; requires sudo/BPF permissions):
  - `sudo build/bin/bpf_conformance_runner --test_file_directory build/tests --plugin_path build/bin/libbpf_plugin --xdp_prolog true --cpu_version v3`
- The runner’s directory scan is **non-recursive** (see `_get_test_files()` in `src/runner.cc`). Point `--test_file_directory` directly at a folder of `.data` files (e.g., `tests/rfc9669`).
- CPU gating + feature groups:
  - Tests are skipped if they require a higher `--cpu_version` (v1–v4) or excluded groups.
  - Default groups exclude `callx` and `packet`; use `--include_groups` / `--exclude_groups` as needed.

## `.data` test file format (parser behavior)
- Parsed by `parse_test_file()` in `src/bpf_test_parser.cc`.
- Supported directives:
  - `-- asm` (assembly lines)
  - `-- raw` (space-separated 64-bit instruction words)
  - `-- result` (expected `%r0`, decimal or `0x...`)
  - `-- mem` (space-separated hex bytes passed to plugin)
  - `-- error` (expected stderr substring when plugin exits non-zero)
- Lines may include `#` comments; CRLF is tolerated.

## Writing/maintaining tests
- Prefer self-checking tests that set `%r0` to `0x1` on pass and `0x0` on failure.
- If a test uses packet memory via `%r1` (e.g., loads from `[%r1+off]`), it must supply `-- mem ...` and run with `--xdp_prolog true` (see `_generate_xdp_prolog()` in `src/bpf_conformance.cc`).
- If a mnemonic isn’t supported by the assembler, encode the instruction via `-- raw` instead.

## Project conventions that matter in PRs
- Formatting: run `./scripts/format-code` (clang-format v11+; see `docs/DevelopmentGuide.md`).
- License headers are required on code files; verify with `./scripts/check-license`.
