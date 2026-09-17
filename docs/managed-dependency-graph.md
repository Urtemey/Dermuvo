# Signed managed dependency preflight

Status: implemented static-graph validation. Optional Mono startup binding now exists; see verified-mono-sessions.md. The low-level host-resolution API remains unprotected.

VerifiedManagedGraph.Capture receives a VerifiedRelease, application DLL paths and explicit host AssemblyName identities. It snapshots the signed bytes of all selected application images and reads their metadata without loading them into the execution runtime.

Each static AssemblyRef must match either a captured application's full identity or an explicitly trusted host identity (name, version, culture, public-key token). There is no implicit trust for System.*, Unity*, mscorlib or netstandard. Host trust is a caller policy and is not an authentication of host assembly bytes.

Rejected cases include missing or uncaptured dependencies, version/identity mismatch, duplicate application names, application/host collisions, duplicate paths, native module imports, mixed-mode or multi-module images, changed signed bytes and exhausted budgets. Limits: 128 application images, 512 host identities, 512 static references per image, 128 MiB total and 64 MiB per image. This initial native/multi-module restriction is an implementation boundary, not a reduction in the final game-support objective.

The private signed snapshots are retained. LoadImageUsingHostResolution can load only a captured path and never reopens the DLL from disk. Its name intentionally exposes the unresolved boundary: the runtime still selects dependencies. No claim of exclusive binding is made.

## Evidence — 2026-09-17

ManagedGraphSuite passes 15 preflight/snapshot checks under Windows and Ubuntu .NET 10:
- Incomplete graph rejected before entry code is loaded.
- Signed but uncaptured dependency rejected.
- Missing host policy, wrong host version, duplicate identity and application version mismatch rejected.
- Native-import metadata and changed dependency bytes rejected.
- Both signed assemblies execute after their source files are deleted when the test host explicitly resolves from captured images.

The Unity 6000.3.22f1 bundled Mono 6.13.0 x86 smoke rejects the same unsigned dependency during preflight. Positive multi-image loading under Unity Player has not been tested.

Complete project results: Windows 119,030 checks; Ubuntu 119,033; Linux native sanitizer smoke 100,000 bounded malformed programs. Counts do not measure resistance.

## Remaining attacks and next enforcement work

The original DependencyBoundaryProbe still succeeds through VerifiedManagedImage.Load. Even a successfully validated graph is not sufficient if a host resolver or previously loaded assembly selects other bytes. AssemblyResolve is not an exclusive interception mechanism, and adding a global handler alone must not be labeled a fix.

Next enforcement must account for already-loaded identities, actual runtime binding, resolver precedence, forwarding, and dynamic assembly/native loads in the actual Unity Player. Dynamic calls or reflection are not modeled by static AssemblyRef validation. Patching the verifier or host remains outside the cryptographic guarantee. Existing VM payload recovery also remains possible.

Mono.Cecil 0.11.6 is now a runtime dependency for metadata inspection; the CLI distributes its netstandard2.0 DLL and upstream license. This does not add Cecil's other companion libraries: this path uses only Mono.Cecil.dll.
