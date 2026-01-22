# RFC 9669 conformance corpus (generated)

This folder contains an *RFC 9669-oriented* conformance corpus in the same `.data` format as the rest of this repo.

Naming convention:

- `sec_<section>_<mnemonic>.data`
- Example: `sec_4_3_jeq.data` tests JEQ variants described in RFC section 4.3.

Notes:

- The runner only enumerates `.data` files in a single directory (non-recursive). To run this corpus, point the runner directly at this folder.
- Memory tests that use `[%r1+off]` assume `--xdp_prolog true` and `-- mem ...` so `%r1` is initialized by the prolog.

Example:

`bpf_conformance_runner --test_file_directory ./tests/rfc9669 --plugin_path ./bin/libbpf_plugin --xdp_prolog true --cpu_version v3 --plugin_options "--debug"`
