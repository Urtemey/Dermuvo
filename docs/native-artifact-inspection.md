# Native artifact inspection — 2026-09-17

protect-release now inspects its native input before staging/transformation/signing. Previously any nonempty byte file with the accepted filename could be packaged and signed. The new check rejects obvious format, architecture and export mismatches without executing the image.

CLI:
~~~text
inspect-native path/to/durevo_vm.dll
inspect-native path/to/libdurevo_vm.so
~~~

The command returns format, x86_64 architecture and the required exported function names. The same result is included in the signed durevo.build.json report.

Supported subset:
- PE32+ AMD64 DLL, no CLR header; required exports must resolve directly into file-backed executable sections. Forwarded required exports are rejected.
- Little-endian ELF64 x86_64 shared object with a bounded section table and dynamic symbol table; required symbols must be defined, visible global/weak functions in file-backed executable sections. Undefined imports, local/hidden symbols and static-symbol-only matches do not qualify.
- Required names: durevo_run, durevo_run_strings, durevo_key_create, durevo_key_destroy, durevo_run_encrypted, durevo_run_encrypted_strings.
- Image size 64 bytes through 64 MiB, bounded tables and names. Extended ELF section numbering, ELF IFUNC and forwarded PE backend functions are outside the supported packaging subset.

The field layouts follow [Microsoft PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format), [ELF symbol tables](https://gabi.xinuos.com/elf/05-symtab.html) and [ELF sections](https://gabi.xinuos.com/elf/03-sheader.html). .NET PEReader supplies the PE header parser; remaining table reads are bounded.

## Evidence

Windows: 2,010 focused format/export/rejection/parser-stability checks; full native/CLI regression 143,595 assertions.
Ubuntu: 2,014 focused checks; full regression 143,607 assertions.
Each platform includes 2,000 deterministic random/mutated images. A mutation need not be rejected if it changes bytes outside the inspected contract; these iterations check bounded parser behavior, not executable authenticity.

Specific rejection cases cover wrong filename/container/processor, truncation, absent required export, corrupt offsets, PE forwarders and ELF undefined/local/hidden function symbols. CLI tests verify that a zero-filled file and a managed assembly renamed as the native backend produce no release directory. Valid native packages still execute through their published runtime and native library.

Logs:
- artifacts/native-inspection-windows.log
- artifacts/native-inspection-linux.log

The three-module actual JuniorCoder pilot was repeated with inspection enabled on Windows and Ubuntu: 25 focused checks each, with the native inspection result included in the signed report:
- artifacts/juniorcoder-release-native-check-win-20260917/execution.json
- artifacts/juniorcoder-release-native-check-linux-20260917/result/execution.json

Existing native sanitizers and ELF dispatch interposition controls passed.

## Limits

This is not a complete PE/ELF loader validator, dynamic-linker simulation, ABI-version handshake, dependency/CPU-instruction compatibility test or proof of code authenticity. ELF section information is inspected, not a full correspondence between every loader program-header/dynamic-table entry and the section table. A deliberately forged implementation can retain the expected headers and exports. A function name does not prove its calling convention or behavior.

The release signature authenticates bytes against the chosen signing authority only after publication. Runtime substitution, verifier patching, native key extraction, confidential key delivery, full Unity startup enforcement and the target distro/package matrix remain open. No new runtime or native-code behavior was changed in this increment.
