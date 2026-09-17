# Keyring release publication

The build pipeline accepts independent named key slots:

~~~text
protect-release-keyring <source-root> <NEW-output-root> <plan.json> <encrypted-issuer.pem> <keyring.json> [native-library]
~~~

A keyring is a JSON object mapping slots to raw 32-byte key files. Relative paths resolve
against the keyring file directory, not the working directory:

~~~json
{
  "arithmetic": "keys/arithmetic.vmkey",
  "branches": "keys/branches.vmkey"
}
~~~

Each VM module in plan v1 supplies KeySlots alongside Methods:

~~~json
"KeySlots": {
  "System.Int32 Durevo.Fixture.Cases::Arithmetic(System.Int32,System.Int32)": "arithmetic",
  "System.Int32 Durevo.Fixture.Cases::Branches(System.Int32)": "branches"
}
~~~

The plan must also supply root-level KeyFeatures mapping every slot to an explicit feature mask; see [release-feature-policy.md](release-feature-policy.md).

Assignments must exactly cover Methods. Slots are case-sensitive, 1-64 ASCII letters,
digits, underscores or hyphens. Distinct slots must have distinct key identities; explicit
method sharing within one slot is allowed. Empty, missing, unused and unknown slots are
rejected. Basic obfuscation modules cannot declare KeySlots. The previous shared-key command
remains supported but cannot accept slot assignments. Core API exposes the same contract
through ProtectedReleaseBuilder.Build(..., keyring: ...).

The CLI reads each key once for both its forbidden-file hash and encryption authority,
wipes the temporary byte buffer, and disposes all authorities on success/failure. Key files,
keyring, signing key, plan and native inputs must be outside source/output. Exact copies of
active raw keys, signing-key file and keyring are rejected from input/payload inventory.
This is not detection of arbitrary encoded or unrelated secrets. The Core API's caller
remains responsible for supplying forbiddenFileHashes when invoking it directly.

The signed build report includes slot-to-key-ID and method-to-slot mappings, never raw
key material or key-file paths. Key IDs and slot names are public metadata.

## Evidence and limits

ProtectedReleaseCliSuite launches the CLI, verifies its release signature, checks the
signed mappings, scans shipped files for test keys, then loads the packaged runtime and
executes both protected methods with independent leases. Invalid assignments, same key
in distinct slots, missing/unused keys, key paths inside source, duplicate JSON keyring
entries and a renamed secret copy fail without publication. Windows and Ubuntu logs:
artifacts/keyring-release-windows.log and artifacts/keyring-release-linux.log.

This increment tests keyring publication in managed VM mode; independent methods in
native and verified-native modes are separately exercised by MethodKeySuite. Full
multi-key Unity Player packaging and school distribution acceptance remain unverified.
Signed-policy grant issuance is now supported; confidential key delivery is not. Issuing and provisioning each group only
when entitled is still required; shipping every key to every client defeats the intended
compromise containment. Existing in-process key extraction remains reproducible.
