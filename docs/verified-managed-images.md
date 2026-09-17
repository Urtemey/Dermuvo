# Verified managed image snapshots

Status: experimental .NET Standard 2.1 API, verified under Windows and Ubuntu .NET 10, also exercised in separate Unity 6000.3.22f1 Windows/Linux x64 Players. See verified-mono-sessions.md for tested scope and startup binding.

## Contract

Obtain a VerifiedRelease from SignedRelease.Verify using a public key trusted independently of the package, the expected product and the required minimum revision. Pass that descriptor, the release directory and a listed DLL path to VerifiedManagedImage.Capture.

Capture reads a bounded private buffer (at most 64 MiB), compares its exact size and SHA-256 to the signed inventory, and retains that buffer. Load passes the retained bytes to Assembly.Load; it does not reopen the original path. File changes after the inventory scan therefore cannot silently replace this particular loaded image. Changes during capture are accepted only if the captured bytes still match the signed digest.

The snapshot does not expose its byte array. Paths must satisfy the portable inventory policy; unlisted files, traversal, observed symlinks, size violations and digest mismatches are rejected.

## Proven behavior

ManagedImageSuite covers a same-length modification after release verification, deletion of the source before loading, execution against original arithmetic results, in-memory assembly location, unlisted paths, traversal, caller size bounds, immutable inventory hashes and truncation.

On 2026-09-17 all 12 checks passed on Windows x64 and Ubuntu 24.04.4 x64. These are .NET 10 runtime results, not Unity Player acceptance.

## Known dependency attack

DependencyBoundaryProbe creates a signed entry assembly referring to an unsigned dependency. Only the entry is in the signed release. A host AssemblyResolve handler supplies the dependency from an unsigned memory buffer. The signed entry executes that code successfully on both tested platforms.

This intentionally passing reproduction is printed as KNOWN GAP, not a successful protection claim. It establishes that signing an entry image does not establish trust in its dependency graph. Dependencies, dynamic loads, native libraries and already-loaded host assemblies remain outside this API's authentication guarantee.

Do not use a global resolution handler as proof of exclusive loading: an assembly might already be loaded, resolved elsewhere, or introduced through another API. A complete design needs an explicit host/framework trust boundary and enforcement of application dependency resolution in the actual Unity runtime.

## Other limits

The API does not prevent verifier patching, memory dumping, or execution by a modified host. It does not hide code. Assembly.Load may reject a signed file that is not a valid compatible assembly. No sandbox is provided.

Filesystem attribute checks are not a general defense against a hostile filesystem (including races and special files). The integrity guarantee is about bytes that successfully pass the signed digest check, not universal availability or race-free path traversal.

There is no integration with Unity's initial Assembly-CSharp loading, no native-library authentication, no production signing-key infrastructure, and no anti-rollback state beyond the caller-selected revision policy.
