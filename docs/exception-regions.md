# Exception-region transformation — 2026-09-17

## Change and protection boundary

Basic obfuscation now supports methods with catch, finally, filter and fault regions. Integer/string VM virtualization still rejects exception handlers. This is broader coverage of the existing IL obfuscation layer, not encrypted execution of these methods and not a fix for native key extraction.

Protector retains all original EH instruction anchors. It divides the instruction stream at every try/handler/filter boundary and permutes blocks only inside each resulting interval. Each interval's first and last blocks stay fixed; interior fallthrough becomes explicit branches inside that interval. No new branch is synthesized across a region boundary, so legal fallthrough into a nested try remains physical fallthrough. Handler order, exclusive range ends, nesting and filter entry points are retained. String/integer rewrites retain the original instruction object and insert their continuation before the next original instruction.

No branch permutation occurs when an interval has too few blocks. The report's Blocks value counts processed blocks, not a guarantee that every block moved. Runtime literal decoding still adds allocation/call cost; full-game performance and allocation-failure behavior are unmeasured.

Mixed-mode, strong-name, prefix/calli/jmp bodies and repeated transformation remain rejected. The transformer assumes valid input IL; metadata re-reading and these tests are not a complete IL verifier.

## Verification

Windows full native/CLI regression: 141,486 assertions.
Ubuntu full native/CLI regression: 141,489 assertions.
Logs: artifacts/exception-regions-windows.log and artifacts/exception-regions-linux.log.

The exception suite checks 16 randomized assemblies, handler order and interval validity, early returns, nested finally, catch selection, rethrow, replacement exceptions, filter side effects and a filter that itself throws: 9,968 checks. A portable harness adds 816 comparisons over four randomized copies, including a Cecil-generated fault clause (C# has no fault syntax), checking exceptional and successful exits. Existing native sanitizers and interposition positive/negative controls passed unchanged.

## Actual cached product modules

Four StringCipher methods in JuniorCoder.LicenseKey.dll are transformed, including EncryptStringAES and DecryptStringAES with nested disposal/finally:
- SHA-256: 6147D846628D86E0A64AF2E7BF3D94BE16D4BDBAF2ED79BA5BE34130B04436AF
- MVID: a5e01644-6cbe-49ca-8346-ddbba6318010
- Four randomized outputs; original encrypt -> protected decrypt and protected encrypt -> original decrypt.
- Synthetic secrets only. Cases include Unicode, NUL, long strings, wrong secrets, missing inputs, malformed/truncated ciphertext and a mutated ciphertext.
- 196 cipher checks, plus 816 portable EH checks, per latest .NET probe.
- Windows: artifacts/juniorcoder-cipher-eh-windows-20260917-v2/
- Ubuntu: artifacts/juniorcoder-eh-linux-20260917/cipher/

This preserves the existing cipher format and behavior. It does not improve the cipher's cryptographic design or test the license server/activation policy.

CodeAnalyzer now includes CheckRoundBrackets.RunAnalysis in the transformed selection: 10 selected methods, eight randomized outputs, 514 inputs and 4,115 checks on both Windows and Ubuntu. Evidence:
- artifacts/juniorcoder-analyzer-eh-windows-20260917/
- artifacts/juniorcoder-eh-linux-20260917/analyzer/

Both modules are cached August DLL snapshots, not fresh game builds. Original game assembly hashes stayed unchanged.

## Unity scope

An isolated Unity 6000.3.22f1 Windows x64 Development Player passed the portable EH/fault checks and the real cipher cross-decryption/error checks. The existing encrypted cooperative-parser tests also passed.
- artifacts/player-fixtures-60d5c9ab1b164ea7ae74a1ec7fa7cfcf/player.log

These are headless harness checks. They do not establish full game, license activation, cooperative, ML, Scratch or update workflow acceptance. The product is configured for 6000.3.23f1. Distro packaging and Astra/RED OS/ALT compatibility remain unverified.

## Static coverage, not security acceptance

The same 21 cached assemblies contain 14,922 bodies. Basic eligibility increases from 13,423 to 14,501 (+1,078). This includes generated and vendored code; it does not mean those methods have all been transformed and executed.

Examples: LicenseKey 86 -> 105; UpdateClient 169 -> 194; CodeAnalyzer 11 -> 12. VM eligibility remains 10 overall, including six vendored methods. The principal virtualized workflow coverage gap remains open.

Evidence: artifacts/juniorcoder-eh-coverage-20260917/summary.json.

## Reproduce

~~~powershell
dotnet run --project tests/Durevo.Tests -c Release -- --native --release-cli src/Durevo.Cli/bin/Release/net10.0/Durevo.Cli.dll
dotnet run --project tests/Durevo.Tests -c Release --no-build -- --probe-juniorcoder-cipher path/to/JuniorCoder.LicenseKey.dll path/to/NEW-output
./scripts/build-unity-player.ps1 -Target Windows
./scripts/test-unity-player-windows.ps1 -LicenseAssembly path/to/JuniorCoder.LicenseKey.dll
./scripts/build-unity-player.ps1 -Target Linux
./scripts/test-unity-player-linux.ps1 -LicenseAssembly path/to/JuniorCoder.LicenseKey.dll
~~~

The actual-module probes execute their input. Use trusted product snapshots only. Generated test directories include original assemblies and synthetic keys for comparison; never ship them as protected releases.


## Linux Player completion

The rebuilt Unity 6000.3.22f1 Linux x64 Development Player passed all 816 portable EH/fault comparisons, the actual cipher cross-decryption/error checks and existing encrypted parser/grant tests under the Ubuntu container. Evidence:
artifacts/linux-player-fixtures-b7050a8089d44c28ac909ace60f74abc/player.log

Both Player processes returned DUREVO_PLAYER_RESULT exitCode=0. This completes this isolated compatibility increment, not whole-game acceptance or the overall protection goal.
