#pragma once
#include <vector>
#include <memory>
#include <string>
#include <xrpl/basics/base_uint.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libxrpl/zkp/circuits/MerkleCircuit.h>

namespace ripple {
namespace zkp {

using DefaultCurve = libff::alt_bn128_pp;
using FieldT = libff::Fr<DefaultCurve>;

// Structure to hold proof + public inputs
struct ProofData {
    std::vector<unsigned char> proof;
    FieldT anchor;           // PUBLIC: merkle root
    FieldT nullifier;        // PUBLIC: derived from secret spendKey
    FieldT value_commitment; // PUBLIC: commitment to value
    
    // Default constructor
    ProofData() = default;
    
    // Constructor
    ProofData(std::vector<unsigned char> p, FieldT a, FieldT n, FieldT vc)
        : proof(std::move(p)), anchor(a), nullifier(n), value_commitment(vc) {}
    
    // Check if proof data is valid
    bool empty() const { return proof.empty(); }
};

class ZkProver {
public:
    static void initialize();
    static bool isInitialized;

    // UNIFIED key management - single circuit for both operations
    static bool generateKeys(bool forceRegeneration = false);
    static bool saveKeys(const std::string& basePath);
    static bool loadKeys(const std::string& basePath);

    // UNIFIED circuit - handles both deposits and withdrawals
    static std::shared_ptr<MerkleCircuit> unifiedCircuit;

    // Proof creation returns ProofData (proof + public inputs)
    static ProofData createDepositProof(
        const Note& outputNote,                    // Note being created
        const std::vector<uint256>& authPath = {}, // Optional: for tree inclusion
        size_t position = 0                        // Optional: position in tree
    );

    static ProofData createWithdrawalProof(
        const Note& inputNote,                     // Note being spent
        const uint256& a_sk,                       // Secret spending key
        const std::vector<uint256>& authPath,      // Merkle authentication path
        size_t position,                           // Position in tree
        const uint256& merkleRoot                  // Expected merkle root
    );
    
    // Helper function to create notes (like Zcash)
    static Note createNote(
        uint64_t value,
        const uint256& a_pk,     // Recipient public key
        const uint256& rho,      // Nullifier seed  
        const uint256& r         // Note randomness
    );
    
    static Note createRandomNote(uint64_t value);  // For testing/deposits

    // Verification with individual parameters
    static bool verifyDepositProof(
        const std::vector<unsigned char>& proof,
        const FieldT& anchor,
        const FieldT& nullifier,
        const FieldT& value_commitment);

    static bool verifyWithdrawalProof(
        const std::vector<unsigned char>& proof,
        const FieldT& anchor,
        const FieldT& nullifier,
        const FieldT& value_commitment);
    
    // CONVENIENCE: Verify using ProofData structure
    static bool verifyDepositProof(const ProofData& proofData) {
        return verifyDepositProof(proofData.proof, proofData.anchor, 
                                proofData.nullifier, proofData.value_commitment);
    }
    
    static bool verifyWithdrawalProof(const ProofData& proofData) {
        return verifyWithdrawalProof(proofData.proof, proofData.anchor,
                                   proofData.nullifier, proofData.value_commitment);
    }

    // Utility functions
    static std::vector<bool> uint256ToBits(const uint256& input);
    static uint256 bitsToUint256(const std::vector<bool>& bits);
    
    // NEW: Helper functions
    static uint256 fieldElementToUint256(const FieldT& element);
    static uint256 generateRandomUint256();

private:
    // UNIFIED proving and verification keys - one set for both operations
    static std::shared_ptr<libsnark::r1cs_gg_ppzksnark_proving_key<DefaultCurve>> provingKey;
    static std::shared_ptr<libsnark::r1cs_gg_ppzksnark_verification_key<DefaultCurve>> verificationKey;

    static std::vector<unsigned char> serializeProof(
        const libsnark::r1cs_gg_ppzksnark_proof<DefaultCurve>& proof);
    static libsnark::r1cs_gg_ppzksnark_proof<DefaultCurve> deserializeProof(
        const std::vector<unsigned char>& proofData);
};

} // namespace zkp
} // namespace ripple