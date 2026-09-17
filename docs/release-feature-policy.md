# Signed release feature policy

Keyring release plans now require a root-level KeyFeatures object whose case-sensitive
slot names exactly match the external keyring:

~~~json
"KeyFeatures": {
  "arithmetic": 1,
  "branches": 2
}
~~~

Values are unsigned 64-bit feature masks. Zero is an explicit choice of no feature-bit
requirement, not an omitted default. The builder snapshots this map and puts it into
durevo.build.json, which is covered by the release signature. Shared-key legacy plans
must not include KeyFeatures.

~~~text
issue-release-grant <release-root> <slot> <license> <program-key> <issuer.pem> <product> <minimum-revision> <NEW-grant>
~~~

DUREVO_KEY_PASSWORD unlocks the encrypted issuer key. The release must have been signed
by the same authority. The command:
1. Verifies the complete release inventory/signature, expected product and revision floor.
2. Captures the report bytes and rechecks their size/hash against the verified inventory.
3. Checks report version/product/revision and exact correspondence of slots and features.
4. Checks the supplied program key identity against the signed slot.
5. Verifies the license signature/product and requires its features to cover the slot mask.
6. Emits the existing signed DUR-KGR1 grant without including the program key.

CLI inputs and output must be outside the immutable release; existing grant output is
never overwritten. Core API is ReleaseGrantIssuer.Issue. File reads are bounded and reject
static links. This is trusted build/issuer storage, not a hostile-filesystem sandbox.

## Verification

ProtectedReleaseCliSuite builds a signed keyring release, issues a grant through the CLI,
and activates the method in its packaged runtime using that grant. Negative cases cover
missing feature policy, incomplete masks, absent slot, wrong key/product, insufficient
license rights, too-high revision floor, modified report and output overwrite.

Evidence: artifacts/release-policy-windows.log and artifacts/release-policy-linux.log.
No new Unity Player acceptance is claimed by these .NET/Ubuntu-container tests.

## Boundaries still open

This is policy-controlled issuance, not confidential key delivery or an online license
service. It still requires trusted selection/storage of the key files and private issuer
key. The low-level issue-program-grant command remains available to trusted issuer
operators and does not consult a release policy.

The existing grant binds a license, key identity and feature mask, not a release hash or
revision. Reusing a key across releases with different entitlement rules may let an old
grant unlock the newer protected code. Rotate affected keys when changing those rules;
cryptographic release-specific runtime grant binding remains unfinished. The revision
floor only constrains the release selected during issuance.

Reading keys from the licensed process, patching the client and manipulating clocks
remain unresolved. Signed policy does not change these threat boundaries.
