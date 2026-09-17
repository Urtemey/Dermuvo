# Integration constraints from current JuniorCoder source

This is a read-only inspection, not update-system acceptance.

- UpdateClient/CodeManifest.cs defines files with path, sha256, size.
- UpdateClient/CodeDeltaPatcher.cs computes SHA256 on downloaded files, stages updates,
  and uses the existing resumable downloader.
- Common/Tools/AddressableContentUpdater.cs checks and updates Addressables catalogs.
- Common/AddressablesPreseed/OfflinePreseedBootstrap.cs installs InternalIdTransformFunc,
  loads a local first-run catalog and tracks a consumed marker.
- StartMenu/AppWarmupController.cs warms scenes/labels/prefixes through existing download APIs.

Consequences for Durevo:
1. Prefer post-build DLL transformation before the existing update hashes/manifests are emitted.
2. Preserve DLL filenames and externally referenced assembly/type/member identities until their
   dependent DLLs, serialized content and dynamic bindings have been traced.
3. Keep current catalogs, addresses, labels, GUIDs, content-state files and offline preseed rules.
4. Do not replace bundle providers, encryption formats or downloader protocols as a prerequisite.
5. A basic metadata/IL pass should not need a new runtime bootstrap; encrypted VM does.
6. Stable protected identities across partial releases are essential. Random changes to every DLL
   on each build may also increase update traffic even without breaking correctness.
7. Validate old content/new client, old client/new compatible content, cache reuse, clean install,
   interrupted download/retry, recovery and offline startup before accepting release integration.

Architecture inventory:
artifacts/architecture-inventory-20260917/summary.json plus per-assembly JSON.
This uses 21 cached assemblies, not fresh binaries matching all current source.
The scanner records exposed types/members, references, resource names and dynamic calls.
Its private-static candidates are REVIEW candidates only. Module-wide dynamic flags are
deliberately conservative; zero candidates does not mean renaming is impossible.

Current public build reports contain original method signatures and readable key-slot names.
Before shipping architecture-hiding output, split developer diagnostics from public metadata:
otherwise the protection report itself supplies a map to the competitor. Existing
release policy needs slot IDs/features, not an unredacted list of original method names.

No Unity game source or content was modified. Automatic renaming is not implemented by
this inventory increment. Next work: trace dynamic-contract targets and introduce an
explicit reviewed rename plan with reference rewriting and behavioural comparison.
