# Verified native binding — 2026-09-17

## Implemented boundary

Encrypted wrappers can now require a native backend captured from a verified release. Calls use function pointers from that exact module handle instead of the default durevo_vm name resolver. Ordinary managed and legacy native key leases do not satisfy this entry point.

This closes the tested default-name substitution path under trusted-host startup assumptions. It does not authenticate the host verifier or operating-system dependencies and does not prevent arbitrary in-process modification.

New interfaces:
- VerifiedNativeImage.Capture(verifiedRelease, root, relativePath): captures at most 64 MiB and checks the exact signed entry length/hash; rejects static links and paths absent from the inventory.
- image.Load(): creates a platform-specific loaded copy from the captured buffer. The original path is not reopened.
- ProgramKeyGrant.ActivateVerifiedNative(..., backend): validates the grant/license and requires the backend product to match. Existing time/device/features/seat rules remain.
- EncryptedIntegerMachine.RegisterVerifiedNativeKey(key, backend): low-level test/provisioning API; no license policy is claimed.
- RunVerifiedNative / RunVerifiedNativeStrings: require the verified-backend lease; no legacy fallback.

Compiler: Protector.Protect(..., virtualize: true, native: true, encryption: key, verifiedNative: true).
Direct CLI: virtualize-encrypted-verified-native uses the same arguments as virtualize-encrypted-native.
protect-release plan mode: vm-encrypted-verified-native. The existing modes retain their prior behavior; protection is not retroactively enabled for old wrappers.

## Loading and lifetime

Windows writes the captured bytes into a unique temporary directory/file, opens that copy with sharing that denies writes/deletion, rechecks its hash, rejects an already loaded copy at that path and calls LoadLibraryExW by absolute path. Dependency search is limited to System32. The file handle stays alive until module release. Temporary DLL cleanup is best effort. These decisions use the documented [LoadLibraryExW behavior](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw); this is not a proof against hostile directory races, loader hooks or process injection.

Linux copies bytes into a memfd, applies WRITE/GROW/SHRINK/SEAL seals, verifies the seal bits, and loads /proc/self/fd/N using RTLD_NOW|RTLD_LOCAL. The descriptor stays open with the module. There is no writable-path fallback. This requires accessible procfs and suitable libc/libdl support; memfd_create was introduced in Linux 3.17/glibc 2.27. See the [Linux memfd_create documentation](https://man7.org/linux/man-pages/man2/memfd_create.2.html). Executable-memfd policies and older distributions may reject loading; those environments remain unverified.

Each imported key retains the specific module. Each execution retains its key handle through the call. Disposing the backend factory prevents new imports but lets existing key leases finish and retain their module until disposal. The first test exposed that SafeHandle references alone did not enforce factory disposal; an explicit synchronized disposed state now provides that rule.

Required encrypted exports are resolved once from the loaded module, before importing keys. Missing exports fail without falling back to name resolution. Native library initializers may execute on load: only use genuinely trusted publisher signatures, never a public key supplied by an untrusted package.

## Evidence

Focused .NET tests check:
- Signed native capture; modified or absent entries rejected.
- Source deletion after capture does not change which bytes are loaded.
- Compiler-generated scalar/string wrappers execute only with the verified native lease.
- Managed/legacy native leases rejected; forged grant rejected; expiry revokes the lease and clock rollback does not revive it.
- Factory disposal, active lease retention, concurrent execution/disposal and snapshot reload.
- A fresh-process poisoned durevo_vm resolver breaks the legacy positive control but is not consulted by verified dispatch.

Latest poisoned-resolver probes: 27 checks each on Windows and Ubuntu:
- artifacts/verified-native-windows-probe.log
- artifacts/verified-native-linux-probe.log

Full Windows native/CLI suite: 143,630 assertions.
Full Ubuntu native/CLI suite: 143,641 assertions (before adding one further key-recovery assertion to the focused suite; that assertion subsequently passed in the separate Linux probe).
- artifacts/verified-native-windows.log
- artifacts/verified-native-linux.log

The package CLI executes the new mode using the published managed runtime and a verified native snapshot, with its ordinary native-name loading path forbidden. Existing native sanitizer/interposition checks passed. The fresh-process poison test is also added to CI, but remote CI was not dispatched.

Unity 6000.3.22f1 Windows/Linux x64 Development Players passed compiled scalar/string calls, legacy-lease rejection, source deletion, backend lifetime and signed-grant expiry:
- artifacts/player-fixtures-27f3ce9934a740309e31f1942da2e5cf/player.log
- artifacts/linux-player-fixtures-0a6dc2d162f642bf90b1a45568c898f8/player.log

Actual cached JuniorCoder package pilot now selects this mode for the cooperative parser. The cipher/analyzer remain basic-obfuscated. Each platform passed 25 focused package/method checks with default native-name loading prohibited:
- artifacts/juniorcoder-verified-release-win-20260917/execution.json
- artifacts/juniorcoder-verified-release-linux-20260917/result/execution.json

These are isolated harnesses and cached August game modules, not current full-game startup acceptance. No production JuniorCoder files were changed.

## Remaining attacks and integration work

Key extraction was reproduced specifically against this new backend on Windows and Ubuntu. Reading the native key handle recovers the synthetic key; after license expiry, low-level registration of the recovered key executes the encrypted program again. Binding the library does not make its key memory secret.

The trusted host must pin release/license public keys and a suitable revision floor, activate the verified backend before protected calls, and own the lease lifetime. A caller can choose its own trust anchor or patch the managed gate if the host itself is untrusted. Native/managed code patching, root-key import observation, native OS dependency interposition, cryptographic-provider compromise and arbitrary memory access remain outside this increment.

There is no general private-dependency loader: Windows private dependencies are excluded by search policy; Linux dependencies still use the host dynamic linker and environment. The new API does not authenticate them.

Full Unity bootstrap integration, confidential key delivery, decompilation-resistance measurement, performance budgets, deb/rpm and Astra/RED OS/ALT compatibility remain open. This is not Denuvo-equivalent protection.
