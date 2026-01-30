# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT
#
# Round-trip test for BPF assembler/disassembler using CLI tools.
# Usage: roundtrip_test.ps1 -BpfDisasm <path> -BpfAsm <path> -TestDirectory <path>

param(
    [Parameter(Mandatory=$true)]
    [string]$BpfDisasm,

    [Parameter(Mandatory=$true)]
    [string]$BpfAsm,

    [Parameter(Mandatory=$true)]
    [string]$TestDirectory
)

$ErrorActionPreference = "Stop"

$passed = 0
$failed = 0
$skipped = 0
$failures = @()

# Get all .data files
$testFiles = Get-ChildItem -Path $TestDirectory -Filter "*.data"

foreach ($testFile in $testFiles) {
    try {
        # Step 1: Disassemble the .data file
        $disasmOutput = & $BpfDisasm --file $testFile.FullName 2>$null

        if (-not $disasmOutput) {
            $skipped++
            continue
        }

        # Step 2: Strip line numbers to get pure assembly
        $assembly = ($disasmOutput | ForEach-Object {
            if ($_ -match '^\s*\d+:\s*(.*)$') {
                $Matches[1]
            }
        }) -join "`n"

        # Step 3: Re-assemble via bpf_asm
        $reassembledHex = $assembly | & $BpfAsm --stdin 2>$null

        if (-not $reassembledHex) {
            $failed++
            $failures += "FAIL (reassembly error): $($testFile.Name)"
            continue
        }

        # Step 4: Disassemble the reassembled bytecode
        $reassembledOutput = & $BpfDisasm --program $reassembledHex 2>$null

        # Step 5: Strip line numbers from reassembled output
        $reassembledAsm = ($reassembledOutput | ForEach-Object {
            if ($_ -match '^\s*\d+:\s*(.*)$') {
                $Matches[1]
            }
        }) -join "`n"

        # Step 6: Compare
        if ($assembly -eq $reassembledAsm) {
            $passed++
        } else {
            $failed++
            $failures += "FAIL (mismatch): $($testFile.Name)"
        }
    }
    catch {
        $failed++
        $failures += "FAIL (exception): $($testFile.Name): $_"
    }
}

Write-Host ""
Write-Host "Results: $passed passed, $failed failed, $skipped skipped"

if ($failures.Count -gt 0) {
    Write-Host ""
    Write-Host "Failures:"
    foreach ($f in $failures) {
        Write-Host "  $f"
    }
}

if ($failed -gt 0) {
    exit 1
}
exit 0