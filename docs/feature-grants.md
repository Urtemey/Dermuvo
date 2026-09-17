# Feature-scoped program-key grants

ProgramKeyGrantIssuer.Issue now verifies the complete signed license format and refuses
keyFeatures outside the license feature mask. It snapshots the bounded ticket before
verification and binding. Previously it checked the signature alone and could issue a
grant the client would later reject.

OfflineLicense.VerifySignature authenticates and parses claims only. Its name and comments
explicitly distinguish it from execution authorization: it does not validate product/device,
current time or requested seats/features. OfflineLicense.Verify calls that parser and
continues to enforce all existing execution policy checks. Issuers can prepare grants
for future-dated tickets; runtime activation still checks validity at the supplied clock.

Client activation independently enforces grant features even if a trusted signer
mistakenly issues an excessive grant. The regression test constructs such a deliberately
misissued grant directly with the signature primitive, rather than weakening issuer checks.

MethodKeySuite now executes independently encrypted methods with signed grants in managed,
native and verified-native modes. Ticket A permits only feature 1 and expires earlier;
ticket B permits only feature 2 and lasts longer. Tests prove:
- A's grant activates A but leaves B unavailable.
- B's grant cannot be attached to A's ticket.
- A expires while B keeps executing.
- Observing A's expiry invalidates that lease permanently despite later clock rollback.
- B eventually expires at its own boundary.

Evidence:
- artifacts/feature-grants-windows.log: 143794 full-suite assertions.
- artifacts/feature-grants-linux.log: 143806 full-suite assertions, plus existing native
  sanitizers and interposition controls in the Ubuntu container.
- artifacts/feature-grants-mono.log: existing bundled Unity 6000.3.22f1 Mono smoke passed,
  including managed grant activation/expiry. This is not a Unity Player acceptance run
  for the new multi-key scenario.

Signed release policy now supplies slot feature masks during issuance; see [release-feature-policy.md](release-feature-policy.md).

Historical increment limits: no confidential key-delivery protocol, issuance service, batch policy manifest,
or automatic release-slot-to-feature policy was added. The trusted issuer still chooses
keyFeatures for each key; passing zero deliberately makes that key require no feature
bits. Operators must maintain that mapping accurately. Client clocks remain untrusted;
fresh activation with a manipulated clock is not solved. In-process key extraction and
low-level registration bypass remain reproducible. None of these tests prove resistance
against an attacker controlling the executing process.
