# Protected release staging — 2026-09-17

## Purpose

protect-release combines exact method selection, immutable input hashes, DLL transformation, runtime dependency placement, removal of selected DLL debug sidecars, release signing and signature verification before publishing a new directory. It closes a build-order gap: the signed inventory describes transformed bytes and includes the transformation report and shipped dependencies.

This is a build pipeline for a trusted, quiescent raw release tree. It does not install a verifier into Unity startup, prevent verifier patching, fix native key extraction, issue licenses or deliver program keys. It does not rebuild JuniorCoder update manifests or installers.

## CLI

~~~text
protect-release <source-root> <NEW-output-root> <plan.json> <encrypted-issuer.pem> [program.vmkey [native-library]]
~~~

Invoke through the built Durevo.Cli.dll with dotnet. Signing uses the existing P-256 encrypted PEM contract and DUREVO_KEY_PASSWORD environment variable. The plan, signing key, program key and native input must be outside both source and output roots. The CLI also rejects exact copies of the active signing-key file or program-key file found under any source filename. This is not a general secret scanner; unrelated or re-encoded secrets in an input tree remain the build owner's responsibility.

Plan v1 example (replace the SHA-256 with the exact inspected input):
~~~json
{
  "Version": 1,
  "Product": "JuniorCoder",
  "Revision": 1,
  "RuntimeDirectory": "JuniorCoder_Data/Managed",
  "NativePath": "JuniorCoder_Data/Plugins/x86_64/durevo_vm.dll",
  "Modules": [
    {
      "Path": "JuniorCoder_Data/Managed/JuniorCoder.GameScene.dll",
      "InputSha256": "<64 hexadecimal characters from the exact input DLL>",
      "Mode": "vm-encrypted-native",
      "Methods": [
        "System.Boolean JuniorCoder.Scripts.Game.LogicLua.PythonCodeHandlerBeforeLaunch::HasMultipleTopLevelArguments(System.String)"
      ]
    }
  ]
}
~~~

Modes: obfuscate, vm-encrypted, vm-encrypted-native, vm-encrypted-verified-native. The verified variant requires the host to activate VerifiedNativeBackend; see [verified-native-binding.md](verified-native-binding.md). Different assemblies can use different modes; one assembly has one mode per build. There is no wildcard selection, repeated processing or implicit fallback to weaker protection. Unknown JSON properties fail. Static method eligibility uses the same compiler preflight as direct transforms.

For obfuscation-only plans, RuntimeDirectory and NativePath must be null and no program key is accepted. Managed encrypted VM requires RuntimeDirectory and a key; NativePath stays null. Native encrypted VM additionally requires the matching named native library. Linux uses libdurevo_vm.so. All selected VM DLLs must share RuntimeDirectory. The build copies the bundled runtime, compatible managed dependencies and their license files there.

The builder now checks the supported x86_64 PE/ELF format and required defined function exports before signing; see [native-artifact-inspection.md](native-artifact-inspection.md). It does not establish ABI semantics, dependency compatibility or native authenticity, and does not execute arbitrary user-selected methods. Use platform/runtime tests before shipping.

## Publication and file policy

1. Capture the input inventory; validate portable paths, source DLL hashes and exact selections.
2. Copy into a unique sibling staging directory, preserving file bytes, empty directories and Unix file mode bits.
3. Compare copy/source inventories; transform only selected DLLs in the staged tree.
4. Remove .pdb and .dll.mdb sidecars for selected DLLs. Leave unselected files unchanged.
5. Add runtime/native assets. Existing files at dependency destinations cause rejection; there is no silent runtime replacement.
6. Write durevo.build.json with input/output hashes, modes, methods, key ID (not key), dependency hashes and removed-symbol paths.
7. Sign all resulting files, including the report; verify the signature and inventory; recheck source hashes.
8. Rename the complete staged tree to the new output directory. Failures remove only this invocation's staging directory.

Source and output must be disjoint. Existing output, existing source signature/build report, hash mismatches, unsupported methods, path traversal/collisions and static symlinks/reparse points are rejected. A wrong signing curve fails without publishing even after staging work.

This is atomic directory visibility on the same filesystem, not a claim of power-loss durability or a race-free hostile-filesystem sandbox. It inherits ReleaseInventory limits (10,000 files, portable paths, no symlinks). Empty directories and Unix permissions are preserved but not authenticated by the current inventory format. Windows ACLs, alternate streams and special filesystem objects are not a supported distribution contract.

A source tree with an existing code/update manifest may contain hashes that become stale after DLL transformation. Use this step before generating those manifests. Do not treat the output as an accepted JuniorCoder update feed.

## Evidence

Core builder tests: 50 Windows and 55 Ubuntu checks. They cover no-overwrite/no-input-mutation, stale hash/invalid plans, encrypted-mode dependencies, active secret-copy rejection, failed staging cleanup, signed reports, runtime collisions, selected debug sidecar removal, executable file mode preservation and Linux symlink refusal. CLI checks add 47 package publication/runtime comparisons per platform.

The CLI test loads Durevo.Runtime and BouncyCastle from the published package in an isolated .NET context. The native variant explicitly loads the published native library. The protected function is denied without a key, matches the original with a synthetic registered key, and is denied after key disposal. This deliberately uses the low-level test registration API, not confidential key provisioning or full license acceptance.

Full native/CLI regression:
- Windows: 141,583 assertions, artifacts/release-builder-windows.log.
- Ubuntu: 141,591 assertions, artifacts/release-builder-linux.log.
- Existing sanitizer and native interposition controls passed.

The Windows DLL-tamper test uses a separate package copy because unloaded collectible .NET contexts can still retain mapped file handles. Ubuntu's recorded full suite exercised direct tamper; the later Windows test adjustment changes test isolation, not builder behavior.

## Actual three-module pilot

The same builder produced and signed a package of cached actual JuniorCoder modules:
- JuniorCoder.LicenseKey.dll: four StringCipher methods, basic obfuscation.
- CodeAnalyzer.dll: ten methods including bracket analysis, basic obfuscation.
- JuniorCoder.GameScene.dll: one cooperative Python parser, native encrypted VM.
- Bundled runtime/dependencies, native library, licenses and signed build report.

Windows and Ubuntu each passed 25 focused publication/execution checks: signature, exact package runtime/native loading, parser behavior and key lifecycle, cipher interoperability, known analyzer outcomes and unchanged source hashes. These complement, rather than replace, prior detailed module differential tests.

Evidence:
- artifacts/juniorcoder-release-win-20260917/execution.json
- artifacts/juniorcoder-release-linux-20260917/result/execution.json

Each evidence directory contains the original snapshot copies, package and public verification key. Synthetic signing/program private keys were held in memory and discarded. These are three-module test bundles, not full game installations. Do not distribute their input/evidence trees. The cached DLLs date from August and are not freshly built current production assemblies.

No full Unity Player release, activation/update integration, deb/rpm, target distro matrix, performance or cracking-resistance acceptance is claimed by this increment.

Independent method groups are supported by protect-release-keyring; see [keyring-release.md](keyring-release.md) for exact assignment and secret-file rules.
