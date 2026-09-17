# Signed program-key grants

A functional licensing layer for encrypted integer VM programs, not a claim of tamper resistance.

## Format and issuance

DUR-KGR1 is exactly 144 bytes: domain (8), SHA-256 of the exact signed license ticket (32), SHA-256 of the 32-byte program key (32), required feature bits (little-endian uint64), and a P-256/SHA-256 fixed-width P1363 signature (64). The same publisher key signs the license and grant. The grant contains no program key and is not encrypted key delivery.

ProgramKeyGrantIssuer.Issue verifies the license signature before signing its binding. Runtime activation verifies both signatures, exact ticket/key binding, expected key ID, product/device, seats and the union of caller-required and issuer-required feature bits.

CLI:

~~~powershell
dotnet run --project src/Durevo.Cli -c Release -- issue-program-grant license.bin program.vmkey 2 encrypted-issuer.pem new-grant.bin
~~~

The encrypted issuer PEM password comes from DUREVO_KEY_PASSWORD (at least 16 characters). The command refuses to overwrite output and clears its owned raw-key buffer. Keep issuer secrets and program keys outside public game/update directories.

## Runtime

ProgramKeyGrant.Activate returns an EncryptedIntegerMachine.KeyLease. It requires explicit expected identities and a trusted clock callback. Every new encrypted VM invocation checks the license time window before taking a key snapshot. Observing an invalid time disposes the lease; changing the clock back does not revive that lease. Clock callbacks run outside the registry lock, and registration identity is checked again afterward.

Already-authorized calls can finish after expiry/disposal. This is not instantaneous revocation. Renewal currently requires disposal of the previous same-key lease and fresh activation. A renewed or re-signed ticket needs a matching new grant because the binding covers exact ticket bytes.

Features apply to the whole program key: all methods encrypted with one key share access to that key. Use separate keys when independent feature authorization is required.

## Remaining attack surface

- The clock, expected device identifier, trust anchor and host execution are trusted inputs. No secure hardware time, persistent rollback prevention, device attestation or online revocation exists.
- Re-activation with a dishonest clock is still possible; the in-session expiry latch is not anti-rollback protection across restarts.
- Public low-level RegisterKey deliberately remains available without license checks. Someone who has the raw key can use it or decrypt programs offline, regardless of grants.
- Key delivery and secure storage are unfinished. Smoke tests read a synthetic raw key from a test file outside the encrypted release; this is not a production deployment pattern.
- Client patching, memory dumping, and key extraction remain unresolved. Signatures authenticate data when the verifier runs faithfully; they do not make that verifier unpatchable.
- No production JuniorCoder integration or gameplay performance acceptance has been performed.

## Verification

ProgramKeyGrantSuite covers byte mutations, wrong binding/identity/rights, malformed and forged tickets, time boundaries, disposal, in-session rollback after expiry and a reentrant clock that revokes the lease. CLI tests exercise issuance and overwrite/forged-license rejection.

Windows .NET regression: 120,932 checks, including 165 grant checks and 32 CLI checks. These are correctness checks, not a cracking-time estimate.

Unity 6000.3.22f1 Windows x64 Development Player passed the signed-grant encrypted managed-wrapper smoke, including expiry and subsequent rollback rejection:
artifacts/player-fixtures-e1d4469ab7834b9ea1f14abc7f2aef1d/player.log

Standalone bundled Mono also passed. Ubuntu .NET passed 120,935 checks and 100,000 malformed native programs under sanitizers. Unity 6000.3.22f1 Linux x64 Development Player passed the same managed-wrapper grant/expiry smoke; evidence: artifacts/linux-player-fixtures-bd3394e7bd8e4ae9ad69526d45a74d66/player.log. Native encrypted VM is tested under .NET, not Unity Player. Real JuniorCoder and Debian/Astra/RED OS/ALT acceptance remain pending.

## Native activation

ProgramKeyGrant.ActivateNative verifies the same grant and license policy but registers native key ownership. It returns the same disposable lease abstraction; expiry/disposal semantics are unchanged. Newly compiled native-encrypted wrappers require this kind of lease (or explicit low-level RegisterNativeKey). Managed activation remains available for managed encrypted wrappers. The activation caller still supplies a key buffer and must clear its own copy. See native-encrypted-execution.md.
