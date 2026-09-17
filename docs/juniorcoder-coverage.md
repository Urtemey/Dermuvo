> Subsequent exception-region support increases basic eligibility to 14,501 and includes the real bracket analyzer and license cipher in compatibility probes. See [exception-regions.md](exception-regions.md). VM eligibility remains 10.

> Historical integer-only baseline. The subsequent string/scalar extension and current 10-method eligibility are documented in [string-vm.md](string-vm.md). The tables below intentionally retain the earlier snapshot results.

# JuniorCoder coverage audit — 2026-09-17

## Critical finding

The integer-only VM currently does not cover JuniorCoder's own game logic in the inspected snapshot. Across 21 runtime assembly definitions under Assets/JuniorCoder, 14,922 method bodies were found. Exactly one method is VM-eligible:

System.Int32 WebSocketSharp.Net.Cookie::hash(System.Int32,System.Int32,System.Int32,System.Int32,System.Int32)

The matching source lives in ClientServer/ClientServer/WebSocketLib/Net/Cookie.cs and carries third-party Mono/WebSocket MIT attribution. It is not a proprietary gameplay algorithm. Counting it as meaningful game protection would be misleading.

These assemblies also contain vendored libraries and Unity/compiler-generated code. The 14,922 count is not a count of exclusively authored business methods.

## Snapshot scope

Input: C:/Users/servak/Documents/JunCod/JuniorCoder/Library/ScriptAssemblies.
Assembly names come from asmdefs under Assets/JuniorCoder, excluding Editor/Test/Debug modules.
DLL timestamps are August 2026; no fresh Unity build was performed. Configured Editor is 6000.3.23f1.

The audit copies source bytes into a new artifact directory, records SHA-256/MVID and checks source hashes after each copy. It does not load or execute assemblies while analyzing. Cached DLLs may differ from current source or a release Player. Do not apply results to a newer release without rerunning.

Evidence:
- artifacts/juniorcoder-coverage-20260917/summary.json
- artifacts/juniorcoder-coverage-20260917/input/
- artifacts/juniorcoder-coverage-20260917/analysis/

## Eligibility, not acceptance

| Assembly | Method bodies | Basic obfuscation eligible | Integer VM eligible |
|---|---:|---:|---:|
| JuniorCoder.Scratch | 3617 | 3311 | 0 |
| JuniorCoder.ClientServer | 3798 | 3299 | 1 (third-party hash) |
| JuniorCoder.GameScene | 2904 | 2648 | 0 |
| JuniorCoder.Common | 1435 | 1341 | 0 |
| JuniorCoder.MLAgents | 485 | 439 | 0 |
| JuniorCoder.Interpreter | 126 | 99 | 0 |
| JuniorCoder.LicenseKey | 105 | 86 | 0 |
| JuniorCoder.UpdateClient | 200 | 169 | 0 |
| CodeAnalyzer | 12 | 11 | 0 |
| All 21 assemblies | 14922 | 13423 | 1 |

Basic eligibility only means passing current body/module restrictions for string/integer concealment and block permutation. It does not establish safe Unity execution, worthwhile protection, or hard reverse engineering. Constructors, accessors and generated methods contribute to these counts.

The VM currently excludes instance methods, non-int32 signatures/locals, calls, fields, objects/arrays and exception regions. This excludes the valuable Python/Scratch/ML/network workflows. Merely adding more integer arithmetic opcodes or refining native key storage will not make those workflows eligible.

## Implemented tooling

CLI:
~~~powershell
dotnet run --project src/Durevo.Cli -c Release -- analyze path/to/module.dll
./scripts/analyze-juniorcoder.ps1 -ProjectPath C:/Users/servak/Documents/JunCod/JuniorCoder -OutputDirectory C:/Users/servak/Documents/JunCod/Durevo/artifacts/NEW-audit
~~~

The JSON includes per-method blockers and aggregate eligibility, source hash and module ID. Assembly-level blockers override aggregate eligibility. Per-method flags describe the body; a blocked assembly cannot be transformed even if a body is individually eligible.

ProtectionAnalysis shares body checks with Protector and VM checks with IntegerVirtualizer. The regression verifies that eligible fixture methods actually transform, unsupported EH/string methods are rejected, repeated transformations are marked blocked, input is unchanged and CLI JSON contains the correct hash. This avoids maintaining a separate approximate opcode whitelist.

## Actual-module differential check

JuniorCoderAnalyzerProbe transformed 9 eligible methods in the actual cached CodeAnalyzer.dll into 8 independently randomized outputs. Each output was compared with the original at 514 inputs, including known bracket failures, null/empty input, CRLF, Unicode and deterministic random bracket/text cases. All results matched on Windows and Ubuntu .NET: 4,115 checks per platform.

The substantive CheckRoundBrackets.RunAnalysis method has a finally region and remains untransformed. The transformed methods include PythonCodeChecker.RunAnalyzer, constructors and result accessors. This is a basic-obfuscation compatibility pilot; it is not VM protection of the analyzer or acceptance of the whole game.

Reproduce:
~~~powershell
dotnet run --project tests/Durevo.Tests -c Release -- --probe-juniorcoder-analyzer path/to/CodeAnalyzer.dll path/to/NEW-evidence
~~~

Evidence:
- artifacts/juniorcoder-analyzer-probe-20260917/evidence.json
- artifacts/juniorcoder-analyzer-linux-20260917/result/evidence.json

The test loads the supplied known application module and executes its analyzer; unlike the static analyze command, it must not be used on arbitrary untrusted assemblies.

Full regression after sharing compiler preflight: Windows 121,064 checks; Ubuntu 121,067; existing native sanitizer/interposition checks also passed. The actual-module probe is separate from those totals. No new Unity Player acceptance is claimed for these actual product DLLs.

## Required next direction

Prioritize a real method family from the product before extending the VM. For CodeAnalyzer, that requires strings, objects, instance dispatch and exception/finally behavior; Scratch/ML bring broader Unity object and numeric requirements. Preserve names, serialization/reflection/Python contracts and test actual workflows.

A larger VM or a selective managed/native bridge must have explicit semantics, GC/exception lifetime rules and performance limits. Falling back silently to ordinary managed IL would not satisfy stronger protection. Current ordinary obfuscation can be evaluated as one layer, but must not be described as equivalent to the missing VM coverage.

Native key extraction and the other documented attacker paths remain open independently of coverage. The overall protection goal is incomplete.
