# Native-owned encrypted execution

## Implemented boundary

New virtualize-encrypted-native output calls EncryptedIntegerMachine.RunNative. This entry requires a native key lease and never silently uses the managed decryptor. ProgramKeyGrant.ActivateNative applies the existing signed grant/license policy and imports the key into the native library. RegisterNativeKey is the explicitly unlicensed low-level alternative.

The runtime registry retains a SafeHandle and an empty managed Bytes array for native leases. Ciphertext, authenticated context and integer arguments cross the native call boundary; only an integer result or status comes back. AES-GCM authentication, payload parsing and execution occur in native code. No decrypted program is returned to managed code by this path. Existing managed modes and previously built wrappers are not retroactively protected by this change; rebuild selected native-encrypted wrappers.

Key import still starts with a managed byte array. The caller must clear its provisioning buffer. ActivateNative clears its own temporary copy. Moving execution does not make provisioning interception or native memory inspection impossible.

## ABI and providers

native/durevo_encrypted.c includes the integer VM and exports:
- durevo_key_create: copy a 32-byte key into an owned native allocation; return opaque handle.
- durevo_key_destroy: wipe and release that allocation.
- durevo_run_encrypted: authenticate a DUR-EVM1 native envelope, execute, and return status/result.
- Existing durevo_run remains for legacy unencrypted native VM compatibility.

The ABI requires valid caller-owned buffers and a live handle; arbitrary forged pointers are not a supported input contract. The C# SafeHandle marshaller holds a reference during calls to prevent disposal freeing an in-use handle. Calls already authorized may complete during concurrent revocation; later calls are rejected. There is no plaintext cache.

Status codes 0..5 retain the VM meanings; 6 indicates failed envelope authentication and 7 crypto-provider failure. Result is zero on failure. Lengths/metadata are bounded; no metadata or instruction executes before tag verification. Owned plaintext/program/key buffers are wiped before release. VM locals/stack are also wiped. This is best-effort cleanup, not a claim that provider-internal copies or debugger snapshots disappear.

Windows uses system CNG BCrypt AES-256-GCM; Linux uses OpenSSL EVP AES-256-GCM. Runtime Linux linking depends on the crypto library used by the build environment (currently Ubuntu 24.04 / libcrypto.so.3). Distro packaging and ABI compatibility across Debian/Astra/RED OS/ALT are unverified.

Provider references:
- [BCrypt authenticated cipher parameters](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_authenticated_cipher_mode_info)
- [BCryptDecrypt](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdecrypt)
- [OpenSSL EVP authenticated decryption](https://docs.openssl.org/3.4/man3/EVP_EncryptInit/)

## Build and verification

scripts/build-native-windows.ps1 builds the combined library with MSVC and bcrypt.lib.
scripts/build-native-linux.ps1 builds it in the native test container, exports the artifact and reports dynamic dependencies.
scripts/test-native-linux.ps1 runs differential/crypto/lifecycle suites and both sanitizer harnesses.

NativeEncryptedSuite verifies signed activation, forged-grant rejection, absence of a persistent managed lease key buffer, rejection of managed-backend payloads and authenticated invalid instructions, expiry/disposal, no managed fallback, caller-buffer independence and concurrent disposal/execution.

EncryptedVmSuite now uses native key ownership when testing the native backend. It mutates every envelope byte and runs actual transformed methods, including overflow and division exceptions. encrypted_fuzz_smoke.c exercises 10,000 bounded authenticated malformed or tampered envelopes under ASan/UBSan, including parser paths after successful tag verification.

Full regression before final Player checks: Windows 121,027 assertions; Ubuntu 121,030 assertions. Native VM sanitizer smoke: 100,000 cases; native encrypted sanitizer smoke: 10,000 cases. These are semantic/lifetime tests, not reverse-engineering resistance scores.

Unity fixture generation includes both managed and native encrypted modules. The isolated Player runner requires both to pass; build scripts configure platform-specific native plugins using Unity importer APIs. Actual Player results are recorded after execution.

## Remaining security work

This closes the normal API path that delivered a complete decrypted VM array through C# to native. It does not yet close the licensed-attacker threat:
- The opaque handle references readable native memory; arbitrary in-process code or a debugger can inspect it.
- Import still passes a key through managed memory. Confidential delivery and a production activation service are unfinished.
- License verification/time/device policy remains in the managed host and can be patched by a local adversary.
- Native library substitution, exported call interception, root key reuse across methods and plaintext observation during execution remain concerns.
- No independent debugger-based evaluation, code diversification, real JuniorCoder integration or game performance acceptance is claimed.

The next acceptance gate must attempt native key/plaintext recovery, not merely observe that the previous reflection-only byte-array probe no longer applies to a native lease.

## Verified Player results — 2026-09-17

Actual Unity 6000.3.22f1 x64 Development Players passed both managed and native encrypted-wrapper activation, expected arithmetic results, missing-key denial, expiry and subsequent in-session rollback denial:
- Windows: artifacts/player-fixtures-e14c349c243743b1b9d3d73342482da7/player.log
- Linux (Ubuntu 24.04 container): artifacts/linux-player-fixtures-41835986568245eaad264c5f893cb22f/player.log

Both logs contain PASS: native signed key grant enables encrypted VM and DUREVO_PLAYER_RESULT exitCode=0. Native plugin import is restricted to the matching standalone x64 platform and excluded from the Editor. The test scripts reject stale Players that omit the native success marker.

Final Windows regression after native scratch-buffer wiping: 121,027 assertions. Final Ubuntu regression: 121,030; both sanitizer harnesses passed (100,000 legacy VM and 10,000 encrypted cases). CI steps were authored for these checks but have not been run remotely.

The actual JuniorCoder project, its configured Unity 6000.3.23f1, release/non-development builds, graphics/gameplay performance and other Linux distributions remain unverified.

## Adversarial follow-up

Native key extraction through the current opaque handle has now been reproduced on Windows/Linux .NET; it remains open. A separate ELF interposition attack against the internal call to durevo_run was reproduced and fixed by using a static internal interpreter core. Full controls, newer test results and updated Player logs: native-adversarial-assessment.md.
