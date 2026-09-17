# Native integer VM — initial backend

## Implemented
native/durevo_vm.c provides an exported C ABI, durevo_run. Durevo.Runtime.NativeIntegerMachine maps native status codes into managed exceptions. No managed fallback occurs when the native library is missing.
The compiler selects this backend explicitly; the CLI command is:

```powershell
dotnet run --project src/Durevo.Cli -c Release -- virtualize-native input.dll new-output methods.txt artifacts/native-win-x64/durevo_vm.dll
```

Windows package contains durevo_vm.dll; Linux package uses libdurevo_vm.so. Both require Durevo.Runtime.dll. This is not a complete Unity deployment.
Rebuild/test with scripts/build-native-windows.ps1 and scripts/test-native-linux.ps1.

## ABI and defensive behavior
Arguments: encoded int32 program and word count; int32 argument array and count; local and stack capacities; 32-bit encoding key; unsigned 64-bit instruction budget; output pointer.
Return codes: 0 success, 1 invalid program, 2 division by zero, 3 arithmetic overflow, 4 allocation failure, 5 exhausted budget.
Pointer buffers must belong to the caller for the duration. Arbitrary invalid native pointers are outside this ABI's contract.
Limits: 2,000,000 program words, 65,536 arguments/locals/stack slots. The normal compiler-generated wrapper uses the maximum uint64 instruction budget; explicit bounded execution is available for tools/tests.
All memory access indices and branch alignment/ranges are checked; invalid output stays zero. No global mutable state or platform process APIs are used.

Signed unchecked arithmetic is implemented through uint32 operations to avoid C signed overflow UB. Arithmetic shift handles the sign explicitly. Checked signed operations use int64 intermediates; unsigned operations use uint64.

## Verified
- Windows x64: MSVC supplied by Visual Studio 18 Community, /O2 /W4 /WX /MT /guard:cf.
- Ubuntu 24.04 x64: GCC 13.3.0, /O2 equivalent, -Wall -Wextra -Werror.
- 118,735 project checks on each platform; 64 obfuscated, 16 managed VM and 16 native VM assemblies executed.
- 3,432 native differential/boundary checks included in that count.
- 100,000 malformed generated programs under AddressSanitizer and UBSan on Linux, each with a finite step budget.
- Comparison exposed a preexisting managed-VM defect in unsigned checked arithmetic: checked uint conversions incorrectly rejected negative int bit patterns. Fixed and compared with original C# fixture methods.
- Native CLI packaging produced assembly, managed runtime, Windows DLL and a hash report.

## Unresolved
The VM payload remains statically recoverable; RecoveryProbe succeeds on native wrappers too. Native execution is not equivalent to strong anti-tamper protection.
The managed VM backend still ships in the shared runtime; no license enforcement or signed native-library binding is integrated yet.
Local attacker patching/replacing the native library remains possible. Hashes in report.json are not authentication.
Resource limits need build-time compatibility validation for large selected methods.
No actual Unity Mono/IL2CPP Player, Debian/Astra/RED OS/ALT packages, performance or independent reversing resistance evidence yet.

## Native encrypted path update

The Windows/Linux build scripts now compile durevo_encrypted.c, which includes the existing VM and adds opaque-key import/destruction plus authenticated encrypted execution. Windows links bcrypt.lib; Linux links libcrypto. The legacy durevo_run ABI is retained. New encrypted-native wrappers require the native path and do not return decrypted programs to C#. See native-encrypted-execution.md for verification and unresolved local-attacker risks. Historical observations above apply to their stated earlier increment.
