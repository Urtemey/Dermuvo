# Unity bundled Mono compatibility (2026-09-17)

Historical first smoke result. Subsequent Windows/Linux x64 Unity Player evidence and startup binding are documented in verified-mono-sessions.md; the limitations below describe this initial standalone smoke.

## Reproduced incompatibility and fix

Unity 6000.3.22f1's bundled Mono 6.13.0 executable throws NotImplementedException from ECDsa.Create(ECParameters). Both offline license and release signature verification previously used this API. Passing .NET 10 tests did not prove they worked on Mono.

Runtime verification now uses the official BouncyCastle.Cryptography 2.7.0 package for P-256 public-point validation and ECDSA verification, with SHA-256 and fixed 64-byte IEEE P1363 signatures. Signing remains in build-time .NET tooling. Existing license and release wire formats and public-key encoding are unchanged. No private keys are shipped.

Package source: https://www.nuget.org/packages/BouncyCastle.Cryptography/2.7.0
Publisher: https://www.bouncycastle.org/download/bouncy-castle-c/
NuGet lock files record package version and content hash. The CLI stages the netstandard2.0 library and its LICENSE.md with virtualized outputs, rather than copying its own .NET-specific package asset. Packaging tests inspect the shipped assembly target framework.

## Reproduce

After installing the .NET SDK from global.json:

~~~powershell
./scripts/test-unity-mono.ps1 -UnityEditorData 'C:/Program Files/Unity/Hub/Editor/6000.3.22f1/Editor/Data'
~~~

The script uses a new artifacts directory per run, compiles against Unity's .NET Standard 2.1 references with its bundled C# compiler, then runs its bundled mono.exe. Synthetic signatures are generated with ephemeral keys. Production JuniorCoder files are not touched.

Validated:
- Windows-issued P-256 license accepted.
- Mutated and all-zero signatures rejected.
- Signed release inventory verified.
- Same-length image tampering rejected by snapshot capture.
- Previously captured signed bytes loaded after source deletion.
- Unsigned host-resolved dependency executed: the existing dependency-boundary attack is reproduced on Mono, not fixed.

## Limits

This executable reports x86 and a 4-byte pointer size. It is a standalone bundled Mono process, NOT the 64-bit Unity Editor or Player. The project's configured 6000.3.23f1 was not present in the inspected Hub editor directory. Unity Player behavior, 64-bit integration, AOT, asset stripping, dependency conflicts in the game, and Linux Unity runtimes remain unverified.

The production game still must integrate trust anchors, verified application dependencies and native libraries. Cryptographic portability does not prevent patching, dumping or the demonstrated dependency substitution.
