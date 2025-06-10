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

// NEW: Structure to hold proof + public inputs
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

    // Key management
    static bool generateDepositKeys(bool forceRegeneration = false);
    static bool generateWithdrawalKeys(bool forceRegeneration = false);
    static bool generateKeys(bool forceRegeneration = false);
    static bool saveKeys(const std::string& basePath);
    static bool loadKeys(const std::string& basePath);

    static std::shared_ptr<MerkleCircuit> depositCircuit;
    static std::shared_ptr<MerkleCircuit> withdrawalCircuit;

    // UPDATED: Proof creation returns ProofData (proof + public inputs)
    static ProofData createDepositProof(
        uint64_t amount,
        const uint256& commitment,
        const std::string& spendKey,
        const FieldT& value_randomness // NEW PARAM
    );

    static ProofData createWithdrawalProof(
        uint64_t amount,                     
        const uint256& merkleRoot,          
        const uint256& nullifier,           
        const std::vector<uint256>& merklePath,
        size_t pathIndex,
        const std::string& spendKey,
        const FieldT& value_randomness // NEW PARAM
    );

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

private:
    static std::shared_ptr<libsnark::r1cs_gg_ppzksnark_proving_key<DefaultCurve>> depositProvingKey;
    static std::shared_ptr<libsnark::r1cs_gg_ppzksnark_verification_key<DefaultCurve>> depositVerificationKey;
    static std::shared_ptr<libsnark::r1cs_gg_ppzksnark_proving_key<DefaultCurve>> withdrawalProvingKey;
    static std::shared_ptr<libsnark::r1cs_gg_ppzksnark_verification_key<DefaultCurve>> withdrawalVerificationKey;

    static std::vector<unsigned char> serializeProof(
        const libsnark::r1cs_gg_ppzksnark_proof<DefaultCurve>& proof);
    static libsnark::r1cs_gg_ppzksnark_proof<DefaultCurve> deserializeProof(
        const std::vector<unsigned char>& proofData);
};

} // namespace zkp
} // namespace ripple