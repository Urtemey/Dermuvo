# Licensed-process recovery assessment — 2026-09-17

## Result

The current managed key registry does not resist arbitrary managed code running inside the licensed process. LicensedRecoveryProbe recovers the active synthetic key through reflection and decrypts two genuinely transformed fixture methods. After the license expires, the original wrapper rejects execution, while recovered Arithmetic and Branches programs run directly through IntegerMachine with matching results.

This is a demonstrated defeat of the current licensed-client confidentiality boundary. It is not a signature forgery, remote exploit, external process injection demonstration, or estimate of time needed to reconstruct JuniorCoder.

## Reproduction and scope

Run dotnet run --project tests/Durevo.Tests -c Release on Windows, or scripts/test-linux.ps1 for the pinned Ubuntu container. The probe is part of the managed test suite and prints KNOWN GAP when this attack succeeds. It intentionally records an existing vulnerability; if the storage architecture changes, reassess the attack rather than preserving its success as a product requirement.

The harness:
1. Generates an ephemeral issuer and program key; encrypts Arithmetic and Branches from Durevo.Fixture through Protector.
2. Activates using a correctly signed license and grant.
3. Disposes the build-side encryption authority and wipes the original caller key buffer.
4. Calls the protected wrapper successfully; the attack routine receives only the public key ID.
5. Reflects the private runtime registry and clones the active key. This assumes arbitrary code already executing in the same process and knowledge of runtime implementation.
6. Advances the trusted test clock to expiry; confirms the original wrapper rejects the call.
7. Extracts ciphertext/context from the transformed assembly, decrypts with standard AES-GCM, and executes recovered programs without registration or licensing.
8. Compares results at seven signed integer boundary/sample inputs for each method and clears owned secret buffers.

The probe never reads production keys, license servers or game files. It writes only temporary synthetic artifacts. No recovered key is printed or persisted.

Verified: Windows .NET 93,429 assertions and Ubuntu .NET 93,432 assertions, managed-only suites. The probe adds 21 assertions. These runs do not include native execution or the CLI suites, and the new attack itself has not been run inside Unity Player.

## Consequences for implementation

Authenticated key delivery alone cannot close this attack: the active client must use the key, and our current runtime retains a directly inspectable copy. Removing RegisterKey, renaming private members, or encrypting the key with another persistent managed key does not address the demonstrated trust boundary.

The next implementation must reduce the easy reusable extraction path:
- Move selected sensitive execution, key use and envelope decryption behind a native interface that does not return raw keys or plaintext programs to managed code.
- Keep the current managed path as an explicitly weaker compatibility/test backend; do not silently fall back to it when native protection is requested.
- Review activation inputs and native-library binding together. Moving a byte array into native memory alone only changes the extraction technique.
- Add an adversarial check at the native interface and evaluate key/plaintext exposure with a debugger. Passing the existing reflection probe alone is insufficient.
- Measure per-call cost and complete actual Unity Windows/Linux tests before selecting game methods for integration.

Even with these changes, a local administrator controlling the client can inspect native memory and patch execution. The intended improvement is increased reconstruction effort, requiring independent evaluation, not impossibility of copying.
