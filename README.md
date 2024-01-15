# BPF Conformance
[![CI/CD](https://github.com/Alan-Jowett/bpf_conformance/actions/workflows/CICD.yml/badge.svg?branch=main)](https://github.com/Alan-Jowett/bpf_conformance/actions/workflows/CICD.yml)
[![Coverage Status](https://coveralls.io/repos/github/Alan-Jowett/bpf_conformance/badge.png?branch=main)](https://coveralls.io/github/Alan-Jowett/bpf_conformance?branch=main)

This project measures the conformance of a BPF runtime to the ISA. To measure conformance the BPF runtime under test is built into a plugin process that does:
1) Accept both BPF byte code an initial memory.
2) Execute the byte code.
3) Return the value in %r0 at the end of the execution.

## eBPF runtime implementations that are currently measured using this project
1) [Linux Kernel via libbpf](https://github.com/Alan-Jowett/bpf_conformance/tree/main/libbpf_plugin)
2) [uBPF](https://github.com/iovisor/ubpf/tree/main/ubpf_plugin)
3) [eBPF for Windows / bpf2c](https://github.com/microsoft/ebpf-for-windows/tree/main/tests/bpf2c_plugin)
4) [rbpf](https://github.com/qmonnet/rbpf/blob/master/examples/rbpf_plugin.rs)
5) [Prevail Verifier](https://github.com/vbpf/ebpf-verifier/blob/main/src/test/test_conformance.cpp)

Note:
Linux Kernel is treated as the authorative eBPF implementation.

## Prerequisites

### Ubuntu

```
sudo apt-get install -y libboost-dev libboost-filesystem-dev libboost-program-options-dev libelf-dev lcov libbpf-dev
```

### MacOS

```
brew install cmake ninja ccache boost
```

## Building

Run ```cmake -S . -B build``` to configure the project, then run ```cmake --build build``` to build the project.

## Usage

```
Options:
  --help                         Print help messages
  --test_file_path arg           Path to test file
  --test_file_directory arg      Path to test file directory
  --plugin_path arg              Path to plugin
  --plugin_options arg           Options to pass to plugin
  --list_instructions arg        List instructions used and not used in tests
  --list_used_instructions arg   List instructions used in tests
  --list_unused_instructions arg List instructions not used in tests
  --debug (true|false)           Print debug information
  --xdp_prolog (true|false)      XDP prolog
  --elf (true|false)             ELF format
  --cpu_version arg              CPU version
  --include_regex arg            Include regex
  --exclude_regex arg            Exclude regex
```

`--xdp_prolog true` should *only* be used with the `libbpf_plugin`.

## Using a published package
Select the desired version from [bpf_conformance](https://github.com/Alan-Jowett/bpf_conformance/pkgs/container/bpf_conformance)

Assume the package is named: "ghcr.io/alan-jowett/bpf_conformance:main"
```
docker run --privileged -it --rm ghcr.io/alan-jowett/bpf_conformance:main src/bpf_conformance_runner --test_file_directory tests --plugin_path libbpf_plugin/libbpf_plugin --cpu_version v3
```

## Running the test
Linux (test require Linux kernel BPF support):
```
cmake --build build --target test --
```

Note: The libbpf_plugin requires root or BPF permissions.

## Using bpf_conformance as a static lib
The BPF Conformance tests can also be used as a static library as part of another tests.
1) Include include/bpf_conformance.h
2) Link against libbpf_conformance.a and boost_filesystem (depending on platform).
3) Invoke bpf_conformance, passing it a list of test files.

## Interpreting results
On completion of the test the bpf_conformance tools prints the list of tests that passes/failed and a summary count.

```
sudo build/src/bpf_conformance --test_file_directory tests --plugin_path build/libbpf_plugin/libbpf_plugin
Test results:
PASS: "tests/add.data"
PASS: "tests/add64.data"
PASS: "tests/alu-arith.data"
PASS: "tests/alu-bit.data"
PASS: "tests/alu64-arith.data"
PASS: "tests/alu64-bit.data"
PASS: "tests/arsh-reg.data"
PASS: "tests/arsh.data"
PASS: "tests/arsh32-high-shift.data"
PASS: "tests/arsh64.data"
PASS: "tests/be16-high.data"
PASS: "tests/be16.data"
PASS: "tests/be32-high.data"
PASS: "tests/be32.data"
PASS: "tests/be64.data"
PASS: "tests/call_unwind_fail.data"
PASS: "tests/div-by-zero-reg.data"
PASS: "tests/div32-high-divisor.data"
PASS: "tests/div32-imm.data"
PASS: "tests/div32-reg.data"
PASS: "tests/div64-by-zero-reg.data"
PASS: "tests/div64-imm.data"
PASS: "tests/div64-reg.data"
PASS: "tests/exit-not-last.data"
PASS: "tests/exit.data"
PASS: "tests/jeq-imm.data"
PASS: "tests/jeq-reg.data"
PASS: "tests/jge-imm.data"
PASS: "tests/jgt-imm.data"
PASS: "tests/jgt-reg.data"
PASS: "tests/jit-bounce.data"
PASS: "tests/jle-imm.data"
PASS: "tests/jle-reg.data"
PASS: "tests/jlt-imm.data"
PASS: "tests/jlt-reg.data"
PASS: "tests/jne-reg.data"
PASS: "tests/jset-imm.data"
PASS: "tests/jset-reg.data"
PASS: "tests/jsge-imm.data"
PASS: "tests/jsge-reg.data"
PASS: "tests/jsgt-imm.data"
PASS: "tests/jsgt-reg.data"
PASS: "tests/jsle-imm.data"
PASS: "tests/jsle-reg.data"
PASS: "tests/jslt-imm.data"
PASS: "tests/jslt-reg.data"
PASS: "tests/lddw.data"
PASS: "tests/lddw2.data"
PASS: "tests/ldxb-all.data"
PASS: "tests/ldxb.data"
PASS: "tests/ldxdw.data"
PASS: "tests/ldxh-all.data"
PASS: "tests/ldxh-all2.data"
PASS: "tests/ldxh-same-reg.data"
PASS: "tests/ldxh.data"
PASS: "tests/ldxw-all.data"
PASS: "tests/ldxw.data"
PASS: "tests/le16.data"
PASS: "tests/le32.data"
PASS: "tests/le64.data"
PASS: "tests/lsh-reg.data"
PASS: "tests/mem-len.data"
PASS: "tests/mod-by-zero-reg.data"
PASS: "tests/mod.data"
PASS: "tests/mod32.data"
PASS: "tests/mod64-by-zero-reg.data"
PASS: "tests/mod64.data"
PASS: "tests/mov.data"
PASS: "tests/mul32-imm.data"
PASS: "tests/mul32-reg-overflow.data"
PASS: "tests/mul32-reg.data"
PASS: "tests/mul64-imm.data"
PASS: "tests/mul64-reg.data"
PASS: "tests/neg.data"
PASS: "tests/neg64.data"
PASS: "tests/prime.data"
PASS: "tests/rsh-reg.data"
PASS: "tests/rsh32.data"
PASS: "tests/stack.data"
PASS: "tests/stb.data"
PASS: "tests/stdw.data"
PASS: "tests/sth.data"
PASS: "tests/stw.data"
PASS: "tests/stxb-all.data"
PASS: "tests/stxb-all2.data"
PASS: "tests/stxb-chain.data"
PASS: "tests/stxb.data"
PASS: "tests/stxdw.data"
PASS: "tests/stxh.data"
PASS: "tests/stxw.data"
PASS: "tests/subnet.data"
Passed 91 out of 91 tests.
```

## bpf_conformance_runner plugins

bpf_conformance_runner invokes plugins using command-line execution, and uses stdin, stdout, and stderr to
exchange additional information as follows:

```
<plugin name> [<base16 memory bytes>] [<plugin options>] [--elf]
```

where:
* `<plugin name>`: the plugin executable name
* `<base16 memory bytes>`: if present, the contents of the `mem` section of a test data file
* `<plugin options>`: any additional options to pass to the plugin
* `--elf`: if present, indicates that the data passed to stdin will be in ELF format

The program is then passed to the plugin via stdin, either as raw bytecode or (if `--elf` is specified) in ELF format.
The plugin must then either:
* compute a successful result and output the final contents of `r0` in hex (either with or without a leading "0x")
  to stdout and exit with a status of 0, OR
* output an error message to stderr and exit with a non-zero status.

Additional plugins can be created based on the above specification.
