Current objective: [docs/GOALS-RU.md](docs/GOALS-RU.md) — conceal architecture and hinder commercial cloning; anti-piracy is secondary.

# Durevo

Experimental protection system for JuniorCoder (.NET/Unity Mono, Windows/Linux).

**Status: functioning prototype, not production protection and not Denuvo-equivalent.**

Current evidence-based Russian status and tested demo: [docs/STATUS-RU.md](docs/STATUS-RU.md).

## Implemented
- Build-time .NET 10 CLI using Mono.Cecil 0.11.6; exact signature selection; never overwrite source.
- Basic-block relocation within preserved exception-region boundaries, string concealment preserving UTF-16/interning, integer masking; see docs/exception-regions.md.
- Selective virtualization of static scalar methods: arithmetic, locals, loops, comparisons, checked overflow and a limited string-parameter subset; see docs/string-vm.md.
- Optional AES-256-GCM encrypted VM programs with a separately provisioned key; compiler and CLI exclude the key from output. Signed license-to-key grants gate activation and per-call expiry; confidential delivery remains unfinished. See docs/encrypted-vm.md and docs/program-key-grants.md.
- Native C integer VM backend with Windows/Linux execution and sanitizer checks; see docs/native-vm.md. Native-encrypted mode now owns key storage/decryption/execution behind a SafeHandle, with no plaintext VM array returned to C#; see docs/native-encrypted-execution.md.
- Opt-in verified native snapshot binding bypasses default library-name resolution and retains module/key lifetimes; Windows/Linux Unity Player smoke passed. Key extraction remains open. See docs/verified-native-binding.md.
- .NET Standard 2.1 managed VM runtime. Virtualized outputs include runtime and portable crypto dependencies with third-party license.
- P-256 verification compatible with Unity bundled Mono via BouncyCastle.Cryptography 2.7.0; see docs/unity-mono-compatibility.md for the tested x86 scope and remaining Player checks.
- Offline P-256 signed license API with bounded strict parsing and explicit product/device/time/feature/seat checks; Windows-issued interoperability vector verified on Ubuntu.
- Signed release inventories and sign-release/verify-release CLI commands; see docs/signed-releases.md.
- Verified managed byte snapshots avoid reopening a changed entry DLL; dependencies remain untrusted. See docs/verified-managed-images.md for the reproduced dependency attack.
- Signed dependency-graph preflight with explicit host identities; see docs/managed-dependency-graph.md.
- Mono startup sessions bind signed images before execution and reject identity collisions. Verified in separate Windows/Linux x64 Unity Players under limited startup assumptions; see docs/verified-mono-sessions.md.
- CLI publishes a fresh directory with assembly, runtime when needed, and hash report.
- protect-release stages an immutable tree, checks exact source hashes, transforms selected DLLs, bundles VM dependencies, signs and verifies before publishing; see docs/protected-release-staging.md. Native PE/ELF x64 format and required exports are checked before publication; see docs/native-artifact-inspection.md.
- Differential execution of 64 randomized obfuscated and 16 virtualized assemblies.
- Recovery probes: legacy VM plaintext is statically recoverable; the encrypted mode exposes ciphertext and requires the external key to recover plaintext. Possession of the key still defeats confidentiality. A licensed-process reflection probe now demonstrates live key recovery and execution after expiry; see docs/licensed-recovery-assessment.md.

## Build and test
Requires .NET SDK 10.0.400 (see global.json).

```powershell
dotnet run --project tests/Durevo.Tests -c Release
dotnet run --project src/Durevo.Cli -c Release -- inspect path/to/input.dll
dotnet run --project src/Durevo.Cli -c Release -- protect path/to/input.dll artifacts/new-output methods.txt
dotnet run --project src/Durevo.Cli -c Release -- virtualize path/to/input.dll artifacts/new-vm-output methods.txt
```

methods.txt contains one exact Cecil signature per line, copied from inspect. No wildcards or implicit all-method selection. Output directory must not exist. The output is not a complete Unity installation: other application dependencies remain the integrator's responsibility.

## Actual product coverage
The string/scalar extension covers one actual cooperative Python parser, checked against its original cached DLL and in isolated Windows and Ubuntu Linux Unity Players. Static eligibility is still only 10 of 14,922 bodies, including six vendored methods. See docs/string-vm.md for current evidence and limits; docs/juniorcoder-coverage.md retains the earlier integer-only baseline. This is far short of whole-game protection. The basic layer now admits 14,501 bodies and has isolated Windows/Linux Player evidence for the real license cipher; see docs/exception-regions.md. Static eligibility is not runtime or security acceptance.

## Current restrictions
No strong-name rewriting, mixed-mode modules, repeated processing, or prefix/calli/jmp bodies in the basic obfuscation pass. Basic obfuscation supports exception regions; VM virtualization still rejects them. VM additionally excludes general objects, string locals/results, int64, generics and calls other than three exact string intrinsics. Unsupported selections fail before an output assembly is published. These are initial implementation limits, not the final objective.

The hashes in report.json are **not signatures or authentication**. Release signing/verifying exists as a separate step. License key-management/issuance tooling, anti-tamper runtime integration and Unity/update integration remain to be built. The native backend exists but is not a completed protection boundary. The license API does not prevent patching or clock rollback; see docs/offline-licenses.md.

## Security evidence
See docs/evaluation.md and docs/architecture.md. Test counts measure repeated semantic comparisons, not resistance. Do not protect production releases until Unity runtime tests and adversarial evaluation pass. The differential suite passed on Windows and an Ubuntu 24.04.4 x86_64 container. A separate Unity 6000.3.22f1 Windows/Linux x64 Player harness now passes selected signature and binding checks. The actual game, version 6000.3.23f1, Debian/Astra/RED OS/ALT, graphics and ML integration remain unverified.
