# Signed release inventory v1 — 2026-09-17

## Purpose
Authenticate the immutable release file inventory using a publisher-pinned P-256 key.
An attacker cannot simply modify a library and recompute the unsigned report hashes.
This is a point-in-time filesystem check, not yet a tamper-resistant loader or a defense against verifier patching.

## CLI
```
sign-release <root> <product> <revision> <encrypted-private-key.pem>
verify-release <root> <public-key.bin> <product> <minimum-revision>
```
Use with dotnet run --project src/Durevo.Cli -c Release -- followed by the command.
The issuer key must be P-256 encrypted PKCS#8 PEM and reside outside the release directory. Its password comes from the process environment DUREVO_KEY_PASSWORD (minimum 16 characters), never command-line arguments. Environment variables are not a hardware keystore and must be scoped to the trusted signing process. Key provisioning/rotation remain separate work.
The public key is 65-byte uncompressed SEC1 (04||X||Y). It is a trusted input: do not accept a public key supplied by an untrusted package.
sign-release refuses an existing manifest and publishes durevo.release using an atomic rename after flushing the staging file. Run only on a quiescent, trusted build output, not a directory being modified concurrently.

## Signed bytes
ASCII DUR-REL1, product (u16 UTF-8 byte length + strict UTF-8), revision u64, file count u32.
Each entry: relative path (u16 UTF-8 length + bytes), file size i64, SHA-256 (32 bytes).
All integers little-endian. Entries sorted ordinally, unique case-insensitively. The payload is followed by a 64-byte IEEE P1363 P-256/SHA-256 signature.
Domain separation prevents treating a license ticket as a release manifest.
Limits: 16 MiB signed manifest, 10,000 files, 1,024 UTF-8 bytes per path, 256 per product, directory depth 128. Positive revision floor required explicitly.

## Filesystem policy
Forward-slash relative paths only. Reject traversal, absolute/drive/ADS paths, Windows reserved device names, ambiguous trailing spaces/dots, invalid portable characters, symlinks/reparse points and case collisions.
The reserved root file durevo.release is excluded from the file inventory. Empty directories are not authenticated.
Missing, added, renamed or modified files invalidate verification. Writable application data must be outside the immutable protected package; compatibility with the full existing JuniorCoder installation has not been established.
Static symlink checks are not race-free open-by-handle validation. This scanner assumes regular application files, not a hostile changing filesystem containing special devices/FIFOs. It is not a general untrusted-filesystem sandbox.
A file can change after verification. Loading the exact verified bytes, native-library lifetime binding and in-process enforcement remain required.

## Evidence
Windows: 251 release signature/filesystem checks and 9 CLI subprocess checks; 118,995 total with native regression.
Ubuntu: 254 release checks (three extra symlink/case tests) and 9 CLI checks; 118,998 total, plus 100,000 native malformed programs under ASan/UBSan.
Cases include mutation of every manifest byte, signature truncation, wrong signer/product, revision rollback, same-size native DLL tamper, missing/added/renamed files, malformed and reserved paths, cross-domain tickets and signed trailing data.
CLI tests exercise encrypted ephemeral signing keys, wrong password, no-overwrite, a key inside the release directory, oversized input and a modified assembly. Private test keys are deleted; no production key is generated.

## Remaining enforcement gaps
- Integrity verification is not yet coupled to actual code loading or protected operations.
- An attacker controlling the process can patch the verifier, caller, pinned key or native runtime.
- The minimum revision is supplied by the host; no persistent tamper-resistant monotonic state exists.
- Hostile concurrent replacement, hardlink identity and Linux special-file handling require a stronger loader boundary.
- Full Unity and distro integration, operational key management and independent adversarial evaluation remain open.
