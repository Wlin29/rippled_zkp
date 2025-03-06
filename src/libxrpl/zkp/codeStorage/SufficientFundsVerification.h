// #ifndef SUFFICIENT_FUNDS_CIRCUIT_H
// #define SUFFICIENT_FUNDS_CIRCUIT_H

// #include "SufficientFundsCircuit.h"
// #include <include/xrpl/protocol/STObject.h>
// #include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
// #include <vector>

// namespace ripple {

// // Define the proof type that will be used
// using ProofType =
//     libsnark::r1cs_ppzksnark_proof<libsnark::CurveType>;
// using VerificationKeyType =
//     libsnark::r1cs_ppzksnark_verification_key<
//         libsnark::CurveType>;
// using ProcessedVerificationKeyType =
//     libsnark::r1cs_ppzksnark_processed_verification_key<
//         libsnark::CurveType>;

// class ZKPProof
// {
// public:
//     // Generate a proof that amount <= balance
//     static ProofType
//     generateSufficientFundsProof(
//         uint64_t balance,
//         uint64_t amount,
//         size_t bit_length = 64);

//     // Verify a proof
//     static bool
//     verifySufficientFundsProof(
//         const ProofType& proof,
//         uint64_t amount,
//         const VerificationKeyType& vk);

//     // Serialize a proof to a byte vector
//     static std::vector<unsigned char>
//     serializeProof(const ProofType& proof);

//     // Deserialize a proof from a byte vector
//     static ProofType
//     deserializeProof(const std::vector<unsigned char>& serialized);

//     // Get the verification key (should be generated once and stored)
//     static VerificationKeyType
//     getVerificationKey(size_t bit_length = 64);

// private:
//     // Setup function to generate proving and verification keys
//     static std::pair<
//         libsnark::r1cs_ppzksnark::r1cs_ppzksnark_proving_key<
//             libsnark::CurveType>,
//         VerificationKeyType>
//     generateKeypair(size_t bit_length = 64);
// };

// }  // namespace ripple

// #endif  // SUFFICIENT_FUNDS_CIRCUIT_H