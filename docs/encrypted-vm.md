# Encrypted integer VM programs (DUR-EVM1)

Status: implemented compiler/runtime/CLI path; activation policy and production game integration are unfinished.

## Security boundary

The encrypted mode stores VM ciphertext, a public key identifier and method context in the wrapper. The 32-byte AES program key is supplied separately. Ordinary changes to a license-check branch cannot supply the missing key needed to decrypt an unknown program.

This protects selected method payloads against an adversary who has only the distributed output and no program key. It does not prevent copying visible behavior, substituting a known simple function, or analysis by someone who obtains an activation key or process memory. The test probe deliberately recovers the ciphertext statically and decrypts it when supplied the external key. String concealment is not counted as a cryptographic barrier.

A release-wide key is shared by all programs encrypted with it. Disclosure compromises those programs in every copy using that key. Per-customer wrapping of the same underlying key would not make that fact disappear.

## Format and implementation

AES-256-GCM, 96-bit random nonce per program, 128-bit authentication tag:
- 8 bytes ASCII domain DUR-EVM1.
- 12 bytes nonce.
- Ciphertext.
- 16 bytes authentication tag.

Plaintext is six little-endian int32 fields (native flag, local count, stack bound, argument count, legacy XOR word key, word count), followed by the encoded int32 program words. Legacy XOR is retained for interpreter compatibility; confidentiality comes from AES-GCM.

Associated data consists of the domain, SHA-256(program key), and length-prefixed strict UTF-8 method context. The compiler context is the assembly full identity plus the exact method signature. Context and backend metadata are authenticated. Altering ciphertext, context, nonce or tag is rejected before parsing or executing instructions.

Limits: 262,144 program words; 65,536 locals, stack slots and arguments; context at most 4,096 UTF-8 bytes. The runtime bounds encoded input before decoding. The public key identifier is base64 SHA-256 of the random program key, not the key itself.

Build-side encryption uses .NET AesGcm. Runtime decryption uses the existing BouncyCastle.Cryptography 2.7.0 dependency because Unity Mono does not provide all modern system crypto APIs. Interoperability tests use these different implementations.

Use a fresh random key for each release. Nonces come from RandomNumberGenerator; there is no persistent cross-process nonce ledger for unlimited reuse of an imported key. The cryptographic construction follows [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final). No FIPS validation or custom cryptographic algorithm is claimed.

## Commands

~~~powershell
dotnet run --project src/Durevo.Cli -c Release -- new-program-key keys/release.vmkey
dotnet run --project src/Durevo.Cli -c Release -- virtualize-encrypted input.dll artifacts/encrypted-release methods.txt keys/release.vmkey
dotnet run --project src/Durevo.Cli -c Release -- virtualize-encrypted-native input.dll artifacts/encrypted-native methods.txt keys/release.vmkey artifacts/native-win-x64/durevo_vm.dll
~~~

On Linux the native argument is libdurevo_vm.so. Input methods have the existing static int32-only VM restrictions. Existing protect/virtualize/virtualize-native commands are unchanged and do not gain encryption automatically.

new-program-key creates a new raw 32-byte key file, refuses overwrite, and prints only its public identifier. Unix creation requests mode 0600; Windows inherits directory permissions. Choose protected operator storage. The compiler reads this separate file and does not copy it into the output directory. Reports contain only its public identifier. Key files are ignored by git through *.vmkey.

Publish only the fresh output directory; sign that release using the existing release-signing workflow. Keep the key storage directory separate from the game and public update storage. Authentication of the publisher remains the signed-release layer: someone who possesses a symmetric program key can generate valid GCM ciphertext.

## Runtime provisioning

The trusted host calls EncryptedIntegerMachine.RegisterKey after its own activation policy succeeds, retains the returned KeyLease while authorized execution is allowed, and disposes it when finished. It never embeds a key literal in the game. RegisterKey itself does not verify a license, device, expiry or signature. Signed license-to-key binding is now available through ProgramKeyGrant.Activate; see program-key-grants.md. Confidential key delivery and production integration remain unfinished.

Every invocation authenticates/decrypts the program before executing it. There is no plaintext program cache. Missing or disposed keys cause UnauthorizedAccessException on new calls. An invocation already holding a private key snapshot may finish after Dispose; this is not instantaneous revocation.

Owned plaintext/key/program arrays are cleared when finished, but the managed crypto implementation and marshaler may retain other copies. This is not proof of complete memory erasure or resistance to dumping. Performance has not been measured in actual gameplay; repeated per-call decryption has a cost.

## Tests and remaining work

EncryptedVmSuite executes real transformed assemblies through both managed and native interpreters, compares results/exceptions with the original fixture, mutates every envelope byte, checks truncation/context substitution/wrong keys/metadata bounds, and verifies denied execution before provisioning and after disposal. An adaptive Cecil-only extraction probe recovers ciphertext without running target code; with the external key, standard AES-GCM recovers the plaintext. Tests also check raw key absence in output artifacts and CLI refusal to overwrite keys.

The standalone Mono/Player harness provisions a synthetic key from a test-only file outside encrypted-release. That fixture is not a production activation design.

Pending: confidential key delivery, production device/time trust, release key lifecycle, real JuniorCoder protected modules, broader VM types/instructions, dynamic-analysis resistance, and production performance/distribution acceptance. A ciphertext-only static extraction failure is not evidence of Denuvo-equivalent protection.

## Verified results — 2026-09-17

- Windows .NET 10: 120,762 project checks, including 858 encrypted managed checks, 858 encrypted native checks and 27 CLI checks.
- Ubuntu 24.04.4 x64 .NET 10: 120,765 project checks; native sanitizer smoke also passed 100,000 bounded malformed programs.
- Unity 6000.3.22f1 Windows x64 Development Player and Linux x64 Development Player: actual encrypted Arithmetic wrapper rejects absent/disposed keys and matches original arithmetic with a separately provisioned synthetic key.
- Standalone Unity-bundled Mono x86 also passed the encrypted-wrapper smoke.

The Unity Player check uses the managed encrypted backend. Native encrypted execution is verified under .NET on Windows/Linux, not yet under Unity Player. The actual JuniorCoder release and configured Unity 6000.3.23f1 remain untested.

Player logs:
- artifacts/player-fixtures-0c373537ef1746a4bd5af2609c218c4a/player.log
- artifacts/linux-player-fixtures-564c4197ec7742ec9699d0f0d8ef445d/player.log

Regenerate with the existing build-unity-player/test-unity-player scripts. Source-of-truth smoke code is tests/Durevo.MonoSmoke/EncryptedProbe.cs. The build helper copies it into the isolated Unity project. These tests establish functionality and the missing-key boundary, not resistance to licensed dynamic analysis.

## Native-owned execution update

New native-encrypted wrappers now call RunNative and require RegisterNativeKey or ProgramKeyGrant.ActivateNative. AES-GCM decryption and program execution happen inside the native library; the managed lease does not retain a key byte array. Earlier verification totals above are historical. See native-encrypted-execution.md for the new API, native crypto dependencies, current Player evidence and remaining memory-extraction risk.
