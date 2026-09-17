# String/scalar VM pilot — 2026-09-17

## Supported subset

Static methods may accept int32, bool, char and string parameters and return int32, bool or char. Locals remain scalar int32/bool/char; string locals and string results are unsupported. Supported string intrinsics are exact core-library String.Length, String.get_Chars(Int32), and String.IndexOf(Char) callvirt signatures. This is not a general object/call bridge. Instance methods, fields, general calls, exception regions, int64 and floating-point operations remain outside the subset.

String parameters use per-invocation reference tokens: zero means null; the same object has the same nonzero token; equal text in separate objects keeps distinct tokens. The wrapper builds the table before passing arguments. ldnull, null branching and reference equality therefore preserve their original meaning. conv.u2 and narrow char/bool local stores preserve scalar width. Tests include null/empty text, separate equal strings, identical references, embedded NUL, unpaired surrogates and invalid indexes.

Managed and native interpreters share the appended string opcodes. Existing integer ABI exports remain; new string exports accept UTF-16 pointers and lengths. The encrypted native path decrypts and executes internally without returning plaintext program arrays or using a general managed callback. Input strings are pinned only for the native call and released on disposal. Null dereference and invalid character index become the corresponding managed exceptions.

The DUR-EVM1 envelope stays unchanged, but programs using new opcodes require the updated runtime and native library together. Old runtimes are not compatible with these new programs. Pinning, token-table allocation and full-game performance are not yet measured. The instruction budget counts VM operations, not characters traversed inside IndexOf.

## Actual product method

System.Boolean JuniorCoder.Scripts.Game.LogicLua.PythonCodeHandlerBeforeLaunch::HasMultipleTopLevelArguments(System.String)

The function distinguishes top-level commas from nested/quoted commas in Python calls used by cooperative timed say/think handling. Protecting it does not protect the whole cooperative subsystem.

Input is the cached August DLL snapshot, not a newly built current game:
- Assembly: JuniorCoder.GameScene.dll
- SHA-256: C750151521D8673BBA699ACC612D202A4E5E0F3ED5667CA61DC838A3C10736DF
- MVID: c983b792-d1af-482b-9c39-361a1f38994f
- Configured game Editor: 6000.3.23f1

The four managed/native and plaintext/encrypted modes matched the original on 1,018 inputs: 4,083 checks on each of Windows and Ubuntu .NET. Evidence:
- artifacts/juniorcoder-string-probe-20260917-v2/evidence.json
- artifacts/juniorcoder-string-linux-20260917-v2/result/evidence.json

Full regression: Windows 130,702 assertions; Ubuntu 130,705. Each backend includes 4,815 string/scalar checks. Sanitizers passed 100,000 malformed scalar, 100,000 malformed string and 10,000 encrypted cases. The ELF interposition positive control still intercepts the exposed dispatch while the closed internal dispatch retains its result. These counts measure compatibility and bounded error handling, not cracking resistance.

An isolated Unity 6000.3.22f1 Windows x64 Development Player passed original/protected comparisons and signed-grant expiry for both managed and native encrypted variants:
artifacts/player-fixtures-9911131a48fd4bff9ce2a52364b9b0c7/player.log

## Coverage and remaining risk

The updated static audit of 21 cached assemblies finds 10 eligible methods out of 14,922 bodies:
- Six vendored WebSocket methods.
- Three Common methods (two constant accessors and a character predicate).
- One GameScene parser above.

Evidence: artifacts/juniorcoder-string-coverage-20260917-v2/summary.json.
Eligibility does not prove runtime acceptance of every eligible method. Scratch, ML, licensing and update modules still have zero VM-eligible methods in this snapshot. Original game files were not transformed.

Native handle memory extraction remains reproduced: a process-memory reader can recover the key and execute recovered methods after expiry. This increment does not fix confidential provisioning, native-library substitution, hostile process control or complete game startup enforcement. It is not Denuvo-equivalent or production protection.

## Reproduction

Run the ordinary --native regression, then:
~~~powershell
dotnet run --project tests/Durevo.Tests -c Release --no-build -- --probe-juniorcoder-strings path/to/JuniorCoder.GameScene.dll path/to/NEW-evidence
./scripts/build-unity-player.ps1 -Target Windows
./scripts/test-unity-player-windows.ps1 -GameAssembly path/to/JuniorCoder.GameScene.dll
./scripts/build-unity-player.ps1 -Target Linux
./scripts/test-unity-player-linux.ps1 -GameAssembly path/to/JuniorCoder.GameScene.dll
~~~

The actual-module probe executes the provided assembly; only use trusted application snapshots. Fixture output deliberately includes the original module as a behavioral baseline; never ship these test directories as protected releases.


## Linux Player evidence

The rebuilt Unity 6000.3.22f1 Linux x64 Development Player also passed the actual-method managed/native encrypted comparisons and signed-grant expiry in the Ubuntu container:
artifacts/linux-player-fixtures-7ce91c5224744b76b8ef17c17dc354a2/player.log

Both Players were headless isolated harnesses. This does not establish full cooperative-game behavior, graphics/ML integration, Debian/Astra/RED OS/ALT compatibility or deb/rpm packaging. Linux native crypto currently links libcrypto.so.3. All 21 inspected original game assembly hashes remained unchanged after the tests.
