# Baseline evaluation — 2026-09-16

## Actual evidence
- Windows .NET SDK 10.0.400.
- Mono.Cecil 0.11.6 restored from official NuGet, lock files generated.
- 80,728 assertions passed on the .NET Standard 2.1 fixture under Windows .NET 10.
- 64 randomized obfuscation outputs and 16 virtualized outputs loaded and executed under .NET 10.
- Cases cover signed boundaries, loops, checked overflow, division-by-zero, UTF-16 including NUL/unpaired surrogates and string interning. Not every implemented VM opcode has independent coverage yet.
- ILSpy 11.0.0.9375 decompiled the transformed .NET Standard VM wrapper. It exposes IntegerMachine.Run, the encoded program and its key; the original loop is no longer directly displayed in the selected method.
- RecoveryProbe statically recovered the embedded program from all 16 VM outputs without executing the target. The current VM encoding is concealment, not confidentiality.

## Defects found and fixed
Random block relocation exposed a Cecil max-stack underestimation on backward edges with live stack values. Preserve original max-stack plus a transformation bound in emitted fat headers. Regression varies block order across 64 builds.
Windows collectible assembly loads sometimes retain temporary files. Tests report retained test-only paths rather than treating cleanup as a semantic failure.

## Unresolved attacks and required follow-up
1. Current integer XOR pairs are locally foldable.
2. String decoding helper and keys are visible and recoverable.
3. Managed VM has a uniform dispatch model and statically recoverable payload.
4. Offline license signature verification is implemented and cross-platform tested; release verification is implemented as a separate signed-inventory step; integrated anti-tamper enforcement is still absent.
5. No application-specific contract inventory, actual JuniorCoder release processing or runtime acceptance.
6. No Unity Player or Debian/Astra/RED OS/ALT execution; no measured overhead yet.

Next protection work: build-specific VM instruction mappings and layout, selective native execution, integrity binding to actual protected operations, and signed offline licensing. Evaluate against adaptive analysis, not only whether this fixed probe fails. A failed probe by itself does not prove strong protection.

## Linux result
The same 80,728 assertions passed in Ubuntu 24.04.4 LTS x86_64 with .NET SDK 10.0.400. Official image digest: sha256:4beef5b8919dcaa2dc924233bd069257e883cc7a061e09088a97d152d6a48510. Source mount was read-only; compilation and execution occurred in disposable container storage. This is runtime-library evidence, not Unity/game/distribution acceptance. Repeat with scripts/test-linux.ps1. The GitHub workflow is authored but has not been dispatched.

## Offline licensing increment
82,165 total checks passed on Windows and the same pinned Ubuntu SDK image. This adds 1,436 license checks and a Windows-issued signature interoperability vector. Details and remaining policy limitations are in offline-licenses.md. The existing static VM recovery probe still succeeds: the resistance gap is unchanged by this cryptographic API alone.

## Native backend increment
118,735 project checks passed on Windows x64/MSVC and Ubuntu x64/GCC 13.3.0. Linux additionally ran 100,000 malformed-program cases under ASan/UBSan with bounded execution. Static payload recovery still succeeds against native wrappers. Native execution improves implementation options but does not close that attack. See native-vm.md for ABI constraints and pending acceptance.

## Signed-release increment (2026-09-17)
Windows: 118,995 checks, including 251 release checks and 9 CLI subprocess checks. Ubuntu: 118,998 including three additional filesystem tests; native sanitizer smoke also passed 100,000 cases. Signed manifests detect changed/missing/extra files and enforce caller-selected product/revision. This is still point-in-time verification, not a protected loader or verifier-patching resistance. See signed-releases.md.

## Verified-image increment (2026-09-17)
Windows: 119,008 checks; Ubuntu: 119,011; native sanitizer smoke: 100,000 cases. Twelve new checks verify that the image passed to Assembly.Load is the signed byte snapshot even after the source DLL is deleted. Fixed the test rejection helper to recognize InvalidDataException explicitly; the unsafe path was already rejected by production code.

A new DependencyBoundaryProbe successfully reproduces execution of an unsigned dependency from a signed entry through host resolution on both platforms. This is a demonstrated remaining attack, not evidence of a secure dependency loader. Static VM recovery remains unresolved. See verified-managed-images.md for the exact guarantee and missing Unity/dependency/native integration.

## Unity bundled Mono compatibility increment (2026-09-17)
The installed Unity 6000.3.22f1 Mono 6.13.0 x86 executable reproduced NotImplementedException in ECDsa.Create(ECParameters). Replaced runtime P-256 verification with BouncyCastle.Cryptography 2.7.0 while retaining the v1 wire formats and build-time signing. A repeatable Mono harness verifies positive/negative license cases, signed release snapshots and the unsigned dependency attack. This is not Unity Player/x64 acceptance.

After the fix: Windows .NET 10 passed 119,014 checks; Ubuntu passed 119,017, plus 100,000 malformed native programs under sanitizers. New regression checks reject invalid curve points, zero r and out-of-range s, and inspect the CLI-distributed netstandard2.0 crypto dependency and license. See unity-mono-compatibility.md.

## Signed dependency preflight increment (2026-09-17)
Added VerifiedManagedGraph with signed byte snapshots, explicit host identities, bounded metadata inspection and complete static-reference matching across selected application DLLs. Fifteen graph tests pass on Windows/Ubuntu. Unity bundled Mono x86 also rejects the demonstrated missing dependency during preflight.

Final regression totals: Windows 119,030; Ubuntu 119,033; native sanitizer smoke 100,000. CLI now includes Mono.Cecil netstandard2.0 and its upstream license. This is NOT exclusive dependency binding: ordinary host resolution and the original dependency attack remain available. See managed-dependency-graph.md.

## Mono startup binding and real Player increment (2026-09-17)
VerifiedMonoSession now refuses preloaded application identities, preloads captured signed graph bytes and checks subsequent identity collisions. Module initializers are rejected. This closes the earlier-resolver substitution case under the explicit trusted/quiescent Mono startup assumptions; it is not a sandbox or an answer to arbitrary in-process modification.

Actual Unity 6000.3.22f1 Windows x64 and Linux x64 Development Players both passed the signature/snapshot/preflight harness and three session checks (earlier foreign resolver, preloaded foreign DLL, later foreign DLL). Baseline attacks without the session still reproduce, including a same-MVID foreign assembly. Linux Player ran headless in Ubuntu 24.04.4. The configured JuniorCoder 6000.3.23f1 and the real game remain untested. Full limitations and reproduction: verified-mono-sessions.md.

Windows .NET 10: 119,032 checks. Linux managed-only .NET 10: 92,388 checks. No claim that these counts prove resistance or that the managed-only run includes native checks.

## Encrypted VM increment (2026-09-17)
Added AES-256-GCM envelopes for selected integer VM programs, an explicit external-key runtime lease and compiler/CLI modes for both managed/native VM execution. The key is not emitted into the transformed wrapper or CLI publication. Missing keys, modified envelopes, method-context substitution and disposed leases are rejected. Key issuance is separate from license verification and not yet integrated.

An adaptive static probe extracts the encrypted envelope and context; it decrypts successfully when given the external program key. Thus ciphertext-only build analysis and licensed/key-holder analysis are distinct threats; no claim of resistance to key extraction or memory dumping is made. Legacy non-encrypted VM modes remain statically recoverable.

Final results: Windows 120,762 checks; Ubuntu 120,765; 100,000 malformed native programs under sanitizers. Actual Unity 6000.3.22f1 Windows/Linux x64 Players pass the encrypted managed-wrapper smoke before/during/after key provisioning. Native encrypted VM was tested under .NET, not Player. Format, commands, threat boundary and outstanding activation/game integration are in encrypted-vm.md.

## Program-key grant increment (2026-09-17)

Added signed 144-byte grants binding an exact license ticket, program key hash and issuer-required feature bits. Activation verifies both signatures and expected identities/rights; each encrypted call checks validity. Observed expiry removes the lease, and clock rollback cannot revive that same lease. A reentrant clock revocation is caught before taking the key snapshot. This is not persistent anti-rollback or resistance to verifier patching.

Verified: Windows .NET 120,932 checks; Ubuntu .NET 120,935 checks; 100,000 bounded malformed native programs under sanitizers. Both actual Unity 6000.3.22f1 Windows/Linux x64 Development Players passed grant activation, expiry and in-session rollback rejection for the managed encrypted VM. Standalone bundled Mono passed too.

Evidence:
- artifacts/player-fixtures-e1d4469ab7834b9ea1f14abc7f2aef1d/player.log
- artifacts/linux-player-fixtures-bd3394e7bd8e4ae9ad69526d45a74d66/player.log

Confidential delivery, persistent trusted time, key-extraction resistance, native encrypted Player testing and real JuniorCoder integration remain pending. The raw-key RegisterKey API bypasses licensing by design for key holders; offline decryption with that key also remains possible. See program-key-grants.md.

## Licensed-process adversarial probe (2026-09-17)

LicensedRecoveryProbe demonstrates live managed key extraction and execution of two recovered encrypted methods after license expiry, without activation. Build-side key storage is disposed and the caller key buffer wiped before the attack. Windows managed-only regression passed 93,429 assertions; Ubuntu managed-only passed 93,432. A passing probe records the known vulnerability, not resistance. See licensed-recovery-assessment.md for assumptions, reproduction and the required native execution boundary.

## Native-owned encrypted execution (2026-09-17)

Added native AES-GCM key ownership, authenticated parsing and execution via SafeHandle. New encrypted-native wrappers require this backend; managed fallback is rejected. Signed ActivateNative uses the existing grant/license checks. The registry retains no managed key byte array for native leases; import still accepts one from the host.

Windows regression: 121,027 assertions. Ubuntu: 121,030. Linux ASan/UBSan passed 100,000 legacy VM cases and 10,000 authenticated/mutated encrypted cases. Actual Unity 6000.3.22f1 Windows/Linux x64 Development Players both passed the native encrypted-wrapper/grant/expiry smoke. Full logs and limits: native-encrypted-execution.md.

This prevents the normal API from returning decrypted VM programs to C#, but does not establish resistance to native memory inspection, key import interception or library substitution. No production game integration or independent cracking evaluation is claimed.

## Native extraction and dispatch hardening (2026-09-17)

Extended the licensed recovery probe to native handles. It recovers the synthetic root key and runs two recovered methods after expiry on Windows/Linux. This attack remains open. Separately, a Linux interposer decoded plaintext VM words and changed encrypted execution via the public durevo_run export. Encrypted execution now uses a static internal core; the regression includes a vulnerable positive control and confirms that only the explicit legacy control call remains intercepted.

Windows full native/CLI: 121,048 assertions. Ubuntu: 121,051. Both sanitizer harnesses pass; both existing Unity x64 Players pass with freshly rebuilt native plugins. Details and exact scope: native-adversarial-assessment.md.

## Actual JuniorCoder coverage and compatibility pilot (2026-09-17)

Added shared static eligibility analysis and CLI analyze command. A snapshot of 21 cached product assemblies contains 14,922 method bodies; only one is currently integer-VM eligible, and it is a vendored WebSocket hash routine. No own game logic in this snapshot qualifies for the current VM. Basic obfuscation eligibility is 13,423 bodies; this is not runtime/protection acceptance.

The actual cached CodeAnalyzer assembly passed differential basic-obfuscation testing on Windows/Ubuntu: 9 selected methods, 8 randomized assemblies, 514 inputs, 4,115 checks per platform. Its EH bracket-analysis implementation remained untouched. Full regression after shared preflight: Windows 121,064; Ubuntu 121,067, plus existing native sanitizer/interposition checks. Snapshot age, hashes, commands, selected methods and limits are in juniorcoder-coverage.md.


## Actual string/scalar method increment — 2026-09-17

See [string-vm.md](string-vm.md) for the restricted string-reference model, actual cached cooperative parser differential evidence, sanitizer counts and Player scope. Latest general regressions: Windows 130,702; Ubuntu 130,705. Native key extraction remains open. Compatibility counts are not a measure of protection strength.


## Exception-region coverage increment — 2026-09-17

Basic IL transformations now preserve EH interval boundaries while permuting interior blocks. Catch/filter/finally/fault regressions pass; actual cached license cipher and bracket analyzer pass Windows/Ubuntu comparisons. Full native/CLI totals: Windows 141,486; Ubuntu 141,489. Basic eligibility rises to 14,501; VM eligibility stays 10. Exact Player evidence and remaining limits: [exception-regions.md](exception-regions.md). This increment does not fix key extraction or establish cracking resistance.


## Signed protected release staging — 2026-09-17

The new protect-release command transforms before signing, includes bundled dependencies and the build report in the signature, and publishes a fresh tree only after verification. Packaged managed/native execution and rejection tests passed on Windows/Ubuntu. An actual three-module JuniorCoder pilot passed 25 focused checks per platform. Details: [protected-release-staging.md](protected-release-staging.md). This closes a build-order gap; it does not install runtime enforcement, change update manifests or fix key extraction.


## Native package input validation — 2026-09-17

The build pipeline now rejects wrong native container/architecture and missing or invalid required function exports before signing, using static inspection only. Windows full regression: 143,595; Ubuntu: 143,607. The actual three-module package pilot passed again on both platforms. See [native-artifact-inspection.md](native-artifact-inspection.md) for tests and limits. Correct metadata does not prove authenticity or solve runtime substitution/key extraction.


## Verified native snapshot binding — 2026-09-17

New encrypted wrappers can require an explicit verified native backend, loaded from captured signed bytes with module/key lifetime ownership. Default native-name poisoning, compiled scalar/string calls, license expiry and disposal tests passed on Windows/Ubuntu and isolated Unity Players. The actual cooperative parser package also passed. Native key extraction was reproduced against this new mode and remains open. Exact evidence and trusted-host/OS dependency limitations: [verified-native-binding.md](verified-native-binding.md).
