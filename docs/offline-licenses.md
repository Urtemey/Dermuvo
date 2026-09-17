# Offline license protocol v1

Implemented in Durevo.Runtime/OfflineLicense.cs; issuance belongs to the build-side Durevo.Core/LicenseIssuer.cs.
No issuer private key is embedded in the runtime or committed to the repository.

## Wire format
Payload followed by exactly 64 bytes of ECDSA P-256/SHA-256 signature in IEEE P1363 r||s format.
Payload:
- ASCII domain/version DUR-LIC1 (8 bytes).
- License ID, product ID, device ID: each prefixed with a little-endian unsigned 16-bit UTF-8 byte length.
- Not-before and exclusive expiry: little-endian signed 64-bit Unix seconds.
- Feature mask: little-endian unsigned 64-bit integer.
- Licensed seats: little-endian unsigned 32-bit integer.

Identifiers are 1..256 strict UTF-8 bytes and not whitespace-only. No case folding or Unicode normalization is performed: product/device matching is ordinal. Entire ticket is bounded at 4096 bytes.
The verification trust anchor is a caller-pinned uncompressed SEC1 P-256 public point (04||X||Y), not an attacker-provided key from the ticket.
Signature verification precedes claims parsing. Caller-owned buffers are copied. Domain mismatch, trailing data and invalid lengths are rejected even if the signature is valid.

## Application policy
A caller must supply expected product, expected device, required feature bits, requested seats and time.
A license is valid only for notBefore <= now < expiry. No hidden network access or auto-renewal occurs.
Wrong signatures/keys raise CryptographicException; malformed payloads raise parsing errors; entitlement mismatches raise UnauthorizedAccessException.

## Proven evidence
- Windows and Ubuntu 24.04.4 x86_64 both passed the 1,436-case license suite.
- Every single-bit mutation of the test ticket, every truncation, excessive length, wrong product/device/key/features/seats and validity boundaries are exercised.
- Windows-issued public test vector verifies on Ubuntu. The corresponding private test key was ephemeral and not saved.
- Total project suite: 82,165 checks on each OS, including the VM/obfuscation regressions.

## Remaining work — do not confuse signatures with tamper resistance
- An attacker controlling the client can patch Verify or its caller. This API is not yet bound to protected operations or native enforcement.
- Time is supplied by the application. Local clock rollback is not detected.
- Device ID is supplied by the application. Hardware fingerprint collection and legitimate recovery are not implemented.
- Seats is an entitlement comparison, not distributed counting of live classroom sessions.
- Key provisioning/storage, rotation/revocation and operator issuance CLI/service are not implemented.
- Selected license cases now pass in separate Unity 6000.3.22f1 Windows/Linux x64 Players. Actual JuniorCoder licensing integration remains absent. See verified-mono-sessions.md.
- Runtime accepts untrusted ticket bytes defensively but assumes its caller owns and configures the trust anchor correctly.
