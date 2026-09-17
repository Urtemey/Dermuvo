> Superseded priorities: [GOALS-RU.md](GOALS-RU.md). Architecture concealment and resistance to commercial cloning are primary; DRM is secondary. The historical acceptance list below is not the current required scope.

# Durevo: protection requirements and evidence

Objective: a high-quality Windows/Linux protection system for JuniorCoder, not a claim of Denuvo equivalence.

## Threat model
The adversary owns the machine, has a licensed release, can inspect and modify files and memory and use AI-assisted decompilers. Offline operation must remain possible. No embedded symmetric secret can be treated as permanently secret. The attacker may bypass the verifier rather than forge its signature.

## Workstreams (all required before declaring completion)
- Managed transformation pipeline: opt-in scope, resource/string protection, control-flow transformations, deterministic contract preservation, randomized releases, independent decompiler evaluation.
- Offline signed licenses: private signing keys outside distribution, explicit product/features/device policy, rotation and recovery. A signature does not stop verifier patching.
- Tamper resistance: signed release inventory, runtime integration, binding to protected operations; no single unprotected Boolean gate.
- Selective native/virtualized implementation of valuable operations, with Windows and Linux ABI tests and measured performance. No claim that native code is unrecoverable.
- Unity integration: preserve serialization, reflection, Python/Lua interfaces, SB3 persistence and public contracts. Transform before update hashes. Do not mutate the production checkout as an experiment.
- Delivery: existing update migration, recovery, deb/rpm, target distro/version matrix, offline school use, legitimate license recovery.
- Evaluation: baseline vs protected decompilation and modification effort; Python/Scratch/ML/coop/LAN runtime scenarios; false-positive, startup and memory budgets; independent adversarial review.

## Initial implementation boundary
The CLI is a .NET 10 build-time tool. It does not require .NET 10 in the protected application. Injected IL references the target core library. Compatibility must still be verified in actual Unity Mono builds on both platforms.
Initial transformations are basic-block layout permutation, integer masking and string concealment. They are not cryptographic confidentiality or mature virtualization. Basic obfuscation now preserves exception-region boundaries while permuting blocks within intervals (see exception-regions.md). VM virtualization still rejects exception handlers; strong-named inputs remain unsupported. Exact method signatures must be selected. No type/member renaming occurs in the initial pass.

## Acceptance gate
Unit tests alone cannot establish resistance to reverse engineering. Do not declare the goal complete until workstreams above have concrete evidence, and document residual attacks. No destructive responses, kernel drivers or stealth behavior are part of this product.
