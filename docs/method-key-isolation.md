# Independent method encryption keys

Protector.Protect now accepts an optional methodKeys dictionary mapping exact method
signatures to VmEncryptionKey authorities. It snapshots keys with ordinal matching,
requires exact coverage (no missing, extra or null authorities), requires virtualization,
and rejects combining the map with a shared encryption authority. The existing single-key
API remains compatible. Selected methods may deliberately share an authority as one group.

This is build-side support: no key bytes are embedded in the transformed assembly.
No runtime ABI or envelope format changed. Each wrapper carries its own key identity;
the existing registry independently provisions and disposes its lease.

## Verified boundary

MethodKeySuite executes compiled wrappers with two independent random keys in managed,
native, and verified-native modes. It verifies:
- A works when only A is provisioned; B refuses execution.
- Both methods match original results with both keys.
- Disposing A revokes A without revoking B.
- Captured A fails AES-GCM decryption of B even with B's actual identity and context.
- B successfully decrypts B as a positive control.
- Neither raw key occurs in the published assembly.
- Invalid mappings fail without publishing an assembly.

Evidence: artifacts/method-keys-windows.log and artifacts/method-keys-linux.log.
These are .NET tests on Windows and the existing Ubuntu container, not acceptance
of Unity Players or all supported Linux distributions.

## Remaining integration and limits

The release-plan and CLI now support explicit keyring publication; see [keyring-release.md](keyring-release.md).
Confidential provisioning remains unfinished. Independent signed feature grants and expiry are now
tested in all three execution modes; see [feature-grants.md](feature-grants.md).

This limits compromise to the independently keyed groups actually exposed. It does not
hide keys from a hostile licensed process. If all keys are provisioned together, an attacker
may recover all of them. There is no claim of resistance to live key extraction, clock
tampering or bypassing the client. Existing recovery probes intentionally continue to
demonstrate those gaps. Do not derive all client keys from a root shipped to that client
and describe it as independent compromise isolation.
