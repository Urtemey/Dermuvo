# Native adversarial assessment and dispatch hardening — 2026-09-17

## Two distinct findings

1. **Open: native key extraction.** LicensedRecoveryProbe now covers both managed and native leases. With arbitrary managed code inside our licensed test process, the probe reflects the native SafeHandle, holds a lifetime reference, reads its 32-byte synthetic key allocation, and decrypts two protected methods. The original wrapper denies execution after expiry; recovered methods still execute directly without activation. The probe knows this prototype's key allocation layout. It reads no external process or production keys.

SafeHandle prevents premature freeing during a call; it is not memory access control. The current native allocation still contains a reusable root key. Moving it into native memory did not close the licensed in-process attacker threat. The new variant adds 21 assertions and intentionally records this remaining attack.

2. **Closed for encrypted internal dispatch: ELF interposition of durevo_run.** The encrypted native path previously passed decrypted program words to the public legacy interpreter export. A test interposer decoded the synthetic program and substituted -999 for its result. Encrypted dispatch now calls the static durevo_run_core directly. The public durevo_run ABI remains compatible for legacy callers, but it is no longer used for this internal transition.

This change does not prevent interposition of crypto imports, key import interception, native library substitution, binary patching or debugger access. It does not make the public legacy API tamper-resistant.

## Regression evidence

scripts/test-native-interposition.sh builds:
- The current library.
- A deliberately vulnerable positive control in a private temporary directory, changing only the internal call back to the public export.
- A test interposer and a synthetic encrypted constant-returning program driver.

The driver first calls the legacy export directly, proving the interposer was loaded and can decode/substitute a VM program. It then invokes the encrypted entry. Both variants use the same compiler flags and test data.

Observed:
~~~text
DISPATCH exposed: result=-999, intercepted=2, decoded=2
DISPATCH closed: result=73, intercepted=1, decoded=1
~~~

The single remaining interception in the closed case is the deliberate direct legacy control call. The encrypted call is not intercepted. The driver also asserts that durevo_run_core cannot be resolved as a dynamic symbol. LD_PRELOAD/LD_LIBRARY_PATH apply only to isolated test child processes inside the container.

## Validation

- Windows .NET full native/CLI regression: 121,048 assertions.
- Ubuntu .NET full native/CLI regression: 121,051 assertions.
- Linux ASan/UBSan: 100,000 legacy VM cases and 10,000 authenticated/mutated encrypted cases.
- Linux positive-control/current-library interposition test: passed.
- Existing Unity 6000.3.22f1 x64 Development Players retested with freshly rebuilt replacement native plugins: both Windows/Linux passed encrypted activation/results/expiry. The Editor/managed Player was not rebuilt for this native-only change.
- The key-extraction attack itself was executed under .NET Windows/Linux, not in Unity Player. No claim of a debugger-based independent assessment.

Evidence:
- artifacts/native-dispatch-windows.log
- artifacts/native-dispatch-linux.log
- artifacts/player-fixtures-c9bf050ac04f43cf9d65b3e659f4fc4c/player.log
- artifacts/linux-player-fixtures-1764986d4f5f4b518f69716348b12fcc/player.log

The Linux regression script and CI workflow now include the interposition test. Remote CI was not dispatched.

## Next acceptance work

Eliminate persistent raw root-key exposure where possible, assess provisioning and crypto-provider interception, and bind native module loading to signed release identity. None of these changes should be credited with general resistance until an adapted extraction probe is attempted. Merely hiding field names or changing pointer offsets does not address the demonstrated threat. Real JuniorCoder integration and performance/distribution acceptance remain separate required workstreams.

API/linker background:
- [Microsoft SafeHandle documentation](https://learn.microsoft.com/en-us/dotnet/fundamentals/runtime-libraries/system-runtime-interopservices-safehandle)
- [GNU C Library dynamic linker hardening](https://sourceware.org/glibc/manual/2.40/html_node/Dynamic-Linker-Hardening.html)
