# protocol/zkp — README

This directory contains the experimental Zero-Knowledge Proof (ZKP) protocol layer for rippled. The module implements shielded value transfers, an incremental Merkle tree for commitments, ZKP prover/verification wrappers, and new transactor types to enable private, ZKP-backed transactions on XRPL and to serve as the basis for future private cross-chain bridges (e.g., XRPL ↔ Ethereum).

This README gives a developer-focused overview, build/run instructions, testing and benchmarking tips, and important security notes.

## Contents (high level)
- Incremental Merkle Tree: efficient append-only tree with O(log n) updates and auth-paths.
- Note model: shielded value structures, commitments and nullifiers, and keypairs.
- ZK Prover wrapper: circuit init, key management, proof creation/verification APIs.
- Transactors: `ZkDeposit`, `ZkWithdraw`, `ZkPayment`.
- ST blob: `STZKProof` for embedding serialized proofs in transactions.
- Tests: unit / integration / benchmark suites (e.g., `ZKProver_test`, `ZKPTransaction_test`).

## Status
Experimental. Useful for development, testing and research. Not production-ready. Do not use on mainnet without independent security and protocol review.

## Key goals
- Privacy-preserving shielded transfers on XRPL.
- Minimal disruption to rippled: encapsulated module design.
- Performance-first: incremental Merkle tree and circuit pruning to reduce proving time.
- Foundation for Zero-Knowledge Bridging across chains.

## Prerequisites
Follow the rippled top-level build instructions first (see top-level BUILD.md). In addition, the ZKP module depends on a ZKP toolchain and common crypto libraries. Typical dependencies include (but are not limited to):

- C++ toolchain supporting C++17/C++20 (as required by the branch)
- CMake (standard rippled build)
- libsnark / alternative proving backend (or compatible proving library)
- libff (or equivalent finite-field library used by your proving backend)
- GMP / libgmpxx
- Cryptographic primitives / libs: secp256k1, Ed25519 libs (for signature comparisons), hashing libs
- Optional: libsodium, OpenSSL for random / crypto helpers

If you are building this inside the rippled repo, most dependency wiring is handled at the top-level build. See BUILD.md and any module-specific README in this directory for extra steps.

## Building
Recommended: build as part of the rippled top-level build.

1. From repository root:
   - Follow BUILD.md to configure the build environment and install prerequisites.
   - Configure & build (example; adapt to your environment):
   ```bash
   mkdir -p build
    cd build
    cmake .. # pass any rippled build options you normally use
    cmake --build . -- -j$(nproc)   
   ```
2. If the ZKP module exposes CMake options, enable them during cmake (check top-level CMake output for flags such as `ENABLE_ZKP` or similar). If this branch adds a dedicated option, the build logs will show it.

Note: If you prefer to develop the ZKP module independently, create a small local CMake project that links against the proving library and the necessary rippled headers — but for integration tests and transactor wiring, the top-level rippled build is recommended.

## Generating circuits & keys
ZKP systems normally require:
- Circuit definition (R1CS or high-level circuit file).
- Trusted/parameter setup or proving/verifying keys (depending on the proving system).
- Precomputed keys must be generated and made available to the ZKP prover at runtime.

This repository includes circuits and helper code; however, key-generation steps are sensitive and environment-specific. Typical workflow:
- Build the circuit using the chosen compiler (e.g., libsnark tooling or your circuit compiler).
- Run the setup to generate proving & verification keys.
- Place generated keys into the module’s expected path (documented in module config or code comments).
- You may find scripts in this directory/branch for key generation — search for `generate_keys`, `build_circuit`, or `setup` scripts.

If you cannot find scripts here, ask the module owner or check commit notes for the branch that introduced the ZKP module.

## Running tests & benchmarks
Unit and integration tests help validate correctness and measure performance. Once the tests are built, run them to ensure the module functions as expected. Below are the new tests created for verifying the functionality and reliability of the ZKPs. Debugging/print statements are commented out but still in the files, uncomment them if you wish to get the readings so you can analyze the outputs effectively.

- From the rippled build directory:
   ```bash
    ./rippled --unittest ZKProver
    ./rippled --unittest ZKPTransaction
    ./rippled --unittest MerkleTree
   ```

or run the test binary directly in the `build` tree.

- Benchmarks / performance regressions:
- There are benchmark tests for Merkle operations and proof generation. Run these tests to reproduce the charts in the experimental results.
- Expect proof generation times in the experimental branch to be roughly ~25s per deposit proof in our environment after optimizations (was ~40s before constraint pruning). Actual times depend heavily on hardware and proving backend.

## Example usage (developer)
Typical flow for a deposit:
1. Client constructs a Note with value, randomness and generates a commitment.
2. Client obtains a Merkle root (anchor) and generates a deposit proof via the prover API.
3. Client submits a `ZkDeposit` transaction with the serialized proof blob (`STZKProof`) and associated public inputs.
4. Server-side `preclaim` verifies proof and `doApply` records the commitment in the IncrementalMerkleTree.

For withdraw:
1. Client creates a withdrawal proof referencing a valid anchor and uses the note’s secret to create a nullifier.
2. `ZkWithdraw` verifies the proof, checks nullifier uniqueness, updates the nullifier set and releases funds.

See tests (`ZKPTransaction_test`, `ZKProver_test`) for concrete usage patterns and helper code examples.

## API pointers / important headers
- Incremental Merkle Tree: `IncrementalMerkleTree.h`
- Merkle witness: contains auth-path and verify helpers.
- Note and AddressKeyPair: `Note.h`
- Shielded pool: `ShieldedMerkleTree.h`
- ZKP wrapper: `ZKProver.h`
- Transactors: `ZkDeposit.h`, `ZkWithdraw.h`, `ZkPayment.h`
- Proof blob: `STZKProof.h`
- Tests: `ZKProver_test`, `ZKPTransaction_test`

Open these headers to see method-level docs and serialized formats.

## Performance notes
- Replacing the standard Merkle tree with an Incremental Merkle Tree reduces append/auth-path overhead from O(n) to O(log n).
- Circuit pruning (removal of unnecessary constraints tailored to XRPL flows) reduced end-to-end deposit proof generation from ~40s → ~25s in our benchmark environment.
- Proof generation remains the dominant cost. Consider: alternative proving systems (Groth16 vs Plonk variants), GPU-accelerated proving, and precomputation to reduce latency.

## Security & audits
- This module is experimental. ZKP and bridge logic are security-sensitive.
- Recommended steps before any production use:
- Independent code audit (C++ + memory safety).
- Circuit review for soundness and missing constraints.
- Thorough test coverage and property-based tests for nullifiers and double-spend protection.
- Protocol-level review for cross-chain bridge assumptions and threat modeling.

Do not deploy to mainnet or hold real value without these reviews.

## Troubleshooting
- Missing proving keys: ensure you have run the circuit setup and placed keys where the module expects them.
- Build failures: confirm the required cryptographic/prover libraries are installed and visible to CMake.
- Slow proof generation: profiling the prover and enabling any available precomputation (e.g., precompute elliptic curve fixed-base multiples, precompute Merkle nodes) can help.
- Tests failing intermittently: check for platform-specific nondeterminism (random seeds), and ensure consistent library versions.

## Contributing & contact
- Issues and PRs: open them in the rippled repository under the XRPLF organization.
- For major design changes, open a discussion first (issue or RFC) to align on goals and safety considerations.
- If you need help reproducing experimental results or running the module, ask on the branch’s review thread or open a developer issue in the repo.

## License
Follows the rippled repository license (see top-level LICENSE.md). The ZKP code in this directory inherits the repository license unless otherwise noted in individual files.