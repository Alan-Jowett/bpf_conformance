# BPF Conformance
[![CI/CD](https://github.com/Alan-Jowett/bpf_conformance/actions/workflows/CICD.yml/badge.svg)](https://github.com/Alan-Jowett/bpf_conformance/actions/workflows/CICD.yml)

This project measures the conformance of a BPF runtime to the ISA. To measure conformance the BPF runtime under test is built into a plugin process that does:
1) Accept both BPF byte code an initial memory.
2) Execute the byte code.
3) Return the value in r0 at the end of the execution.

## Building

Run ```cmake -S . -B build``` to configure the project, then run ```cmake --build build``` to build the project.

## Running the test

Start bpf_conformance, passing it the path to tests to execute and the path to the runtime under test.

Example using the libbpf_plugin (which uses the Linux BPF runtime)
```build/src/bpf_conformance --test_file_path tests --plugin_path build/libbpf_plugin/libbpf_plugin```

Note: The libbpf_plugin requires root or BPF permissions.

## Interpeting results
On completion of the test the bpf_conformance tools prints the list of tests that passes/failed and a summary count.

```
sudo build/src/bpf_conformance --test_file_path tests --plugin_path bui
ld/libbpf_plugin/libbpf_plugin
Test results:
"tests/add.data": Passed
"tests/add64.data": Passed
"tests/alu-arith.data": Passed
"tests/alu-bit.data": Passed
"tests/alu64-arith.data": Passed
"tests/alu64-bit.data": Passed
"tests/arsh-reg.data": Passed
"tests/arsh.data": Passed
"tests/arsh32-high-shift.data": Passed
"tests/arsh64.data": Passed
"tests/be16-high.data": Passed
"tests/be16.data": Passed
"tests/be32-high.data": Passed
"tests/be32.data": Passed
"tests/be64.data": Passed
"tests/call_unwind_fail.data": Passed
"tests/div-by-zero-reg.data": Passed
"tests/div32-high-divisor.data": Passed
"tests/div32-imm.data": Passed
"tests/div32-reg.data": Passed
"tests/div64-by-zero-reg.data": Passed
"tests/div64-imm.data": Passed
"tests/div64-reg.data": Passed
"tests/exit-not-last.data": Passed
"tests/exit.data": Passed
"tests/jeq-imm.data": Passed
"tests/jeq-reg.data": Passed
"tests/jge-imm.data": Passed
"tests/jgt-imm.data": Passed
"tests/jgt-reg.data": Passed
"tests/jit-bounce.data": Passed
"tests/jle-imm.data": Passed
"tests/jle-reg.data": Passed
"tests/jlt-imm.data": Passed
"tests/jlt-reg.data": Passed
"tests/jne-reg.data": Passed
"tests/jset-imm.data": Passed
"tests/jset-reg.data": Passed
"tests/jsge-imm.data": Passed
"tests/jsge-reg.data": Passed
"tests/jsgt-imm.data": Passed
"tests/jsgt-reg.data": Passed
"tests/jsle-imm.data": Passed
"tests/jsle-reg.data": Passed
"tests/jslt-imm.data": Passed
"tests/jslt-reg.data": Passed
"tests/lddw.data": Passed
"tests/lddw2.data": Passed
"tests/ldxb-all.data": Passed
"tests/ldxb.data": Passed
"tests/ldxdw.data": Passed
"tests/ldxh-all.data": Passed
"tests/ldxh-all2.data": Passed
"tests/ldxh-same-reg.data": Passed
"tests/ldxh.data": Passed
"tests/ldxw-all.data": Passed
"tests/ldxw.data": Passed
"tests/le16.data": Passed
"tests/le32.data": Passed
"tests/le64.data": Passed
"tests/lsh-reg.data": Passed
"tests/mem-len.data": Passed
"tests/mod-by-zero-reg.data": Passed
"tests/mod.data": Passed
"tests/mod32.data": Passed
"tests/mod64-by-zero-reg.data": Passed
"tests/mod64.data": Passed
"tests/mov.data": Passed
"tests/mul32-imm.data": Passed
"tests/mul32-reg-overflow.data": Passed
"tests/mul32-reg.data": Passed
"tests/mul64-imm.data": Passed
"tests/mul64-reg.data": Passed
"tests/neg.data": Passed
"tests/neg64.data": Passed
"tests/prime.data": Passed
"tests/rsh-reg.data": Passed
"tests/rsh32.data": Passed
"tests/stack.data": Passed
"tests/stb.data": Passed
"tests/stdw.data": Passed
"tests/sth.data": Passed
"tests/stw.data": Passed
"tests/stxb-all.data": Passed
"tests/stxb-all2.data": Passed
"tests/stxb-chain.data": Passed
"tests/stxb.data": Passed
"tests/stxdw.data": Passed
"tests/stxh.data": Passed
"tests/stxw.data": Passed
"tests/subnet.data": Passed
Passed 91 out of 91 tests.
```

