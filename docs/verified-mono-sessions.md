# Verified Mono startup sessions

## Implemented boundary

VerifiedManagedGraph.BindMono accepts explicitly trusted, already-loaded host assemblies. It refuses non-Mono runtimes and refuses to begin if any application assembly identity from the signed graph is already loaded. It then preloads every signed image from the captured bytes before returning a VerifiedMonoSession.

GetAssembly returns a captured assembly only after checking the current AppDomain for foreign assemblies with the same simple name as a bound application or pinned host assembly. The comparisons use actual Assembly object identity, not MVID: the probes preserve the original MVID in the modified DLL.

Capture now rejects module initializers, in addition to its existing native-import/mixed-mode/multi-module restrictions. No application module initializer may run while only part of the graph has been loaded. Normal type initialization still follows runtime rules.

The loader installs no AssemblyResolve handler. In tested Mono runtimes, preloaded exact identities satisfy the static references before resolver callbacks. This matters because earlier callbacks can win over a later "secure" resolver.

## Evidence

Tested on 2026-09-17:
- Unity 6000.3.22f1 Windows x64 Development Player.
- Unity 6000.3.22f1 Linux x64 Development Player, Ubuntu 24.04.4 container.
- The same editor's bundled Mono 6.13.0 x86 executable.

Both Players explicitly report pointerSize=8 and return exitCode=0. The harness performs valid/invalid P-256 license checks, signed snapshot checks, static preflight and these binding experiments:

| Scenario | Observed result |
|---|---|
| Earlier foreign resolver, no startup binding | Foreign dependency executes (-999); expected vulnerability reproduced |
| Signed dependency preloaded first | Signed dependency executes (31337), no resolver invocation |
| Foreign dependency preloaded first | Foreign dependency executes (-999); expected vulnerability reproduced |
| BindMono with an earlier foreign resolver | Signed dependency executes (31337), foreign resolver never called |
| BindMono after a foreign same-identity DLL is loaded | Startup rejected |
| Another same-identity DLL loaded after binding | GetAssembly detects the collision and refuses to return the entry |

The two DLLs in a collision intentionally share both assembly identity and MVID. A successful MVID comparison alone would not have stopped these cases.

Additional Windows .NET 10 regressions pass 119,032 checks; the Linux managed-only run passes 92,388. The latter does not run native VM/CLI optional suites. .NET rejects BindMono as unsupported; its loader semantics are not assumed equivalent.

## Exact limitations

This is startup binding under a trusted, quiescent host, not a sandbox or a general anti-tamper boundary. No concurrent external assembly loading is allowed during binding or between a validation and use. The private lock coordinates Durevo callers only. Arbitrary in-process code, native injection, verifier patching and memory modification remain outside this guarantee.

A retained Assembly reference can be used without another GetAssembly check. Late collision detection is point-in-time, not a continuous monitor. After an exception during partial binding, restart the host: already-loaded Mono assemblies cannot be rolled back here. The session does not unload assemblies.

Host identities are pinned by the caller as Assembly objects; the session does not authenticate the host/framework's original bytes. Dynamic loads, reflection-based plugins, type forwarding, strong-name/GAC edge cases and cyclic application graphs require further targeted tests. Native libraries are not authenticated by this API.

Unity loads Assembly-CSharp before this API can run. BindMono deliberately rejects preloaded application assemblies, so it is currently for explicitly loaded protected modules. It cannot simply be wrapped around JuniorCoder's existing Assembly-CSharp. No production JuniorCoder restructuring or integration has been done.

The standalone Player harness has no gameplay, ML, Scratch, coop or graphics acceptance coverage. This is version 6000.3.22f1, not the project's configured 6000.3.23f1. Debian/Astra/RED OS/ALT and installer packaging remain untested. Existing VM payload recovery remains possible.

## Reproduce

The test project lives in tests/UnityPlayerSmoke. It was created locally with:

~~~powershell
unity projects new UnityPlayerSmoke --path C:/Users/servak/Documents/JunCod/Durevo/tests --editor-version 6000.3.22f1 --template com.unity.template.urp-blank --format json
~~~

The project already exists; do not repeat creation on top of it. All fixtures use ephemeral signing keys; only public keys and signatures are written.

~~~powershell
./scripts/build-unity-player.ps1 -Target Windows
./scripts/test-unity-player-windows.ps1
./scripts/build-unity-player.ps1 -Target Linux
docker build -t durevo-native-tests:local native
./scripts/test-unity-player-linux.ps1
~~~

Builds use installed Editor modules, .NET locked restore, Mono scripting backend and disabled managed stripping. The helper copies the canonical smoke sources and runtime DLLs into the separate test project. Generated binaries and Library/Temp are excluded from git.

Unity's editor contains an older Mono.Cecil package. PreparePlugins excludes Durevo's Cecil from the Editor using SetExcludeEditorFromAnyPlatform(true), retaining it in Players. This setting is written through PluginImporter, not manual .meta editing. Player runtime uses the netstandard2.0 dependency distributed by the Durevo CLI.

Evidence logs from this run:
- artifacts/player-fixtures-d4c230cb3cfd43ec883e10a297e4e20a/player.log
- artifacts/linux-player-fixtures-045155ddd7144b789be1f5e07dd31d12/player.log

The artifacts directory is local and ignored; the scripts regenerate fresh evidence.
