#ifndef ZK_PROVER_H
#define ZK_PROVER_H

#include <vector>
#include <cstdint>
#include <string>
#include <memory>
#include <xrpl/protocol/UintTypes.h>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

// Forward declarations to avoid exposing libsnark types in the header
namespace libsnark {
    template<typename ppT> class r1cs_ppzksnark_proving_key;
    template<typename ppT> class r1cs_ppzksnark_verification_key;
    template<typename ppT> class r1cs_ppzksnark_proof;
}

namespace ripple {
namespace zkp {

typedef libff::alt_bn128_pp DefaultCurve;
class ZkProver {
public:
    // Initialize the library (call once at startup)
    static void initialize();

    // Generate proving/verification keys (can be done once or loaded from files)
    static bool generateKeys(bool forceRegeneration = false);
    
    // Save keys to file for persistence
    static bool saveKeys(const std::string& provingKeyPath, 
                         const std::string& verificationKeyPath);
    
    // Load keys from file
    static bool loadKeys(const std::string& provingKeyPath, 
                         const std::string& verificationKeyPath);

    // Create a deposit proof (for shielding funds)
    static std::vector<unsigned char> createDepositProof(
        uint64_t publicAmount,           // Amount visible on chain
        const uint256& commitment,       // Commitment to shield
        const std::string& spendKey);    // Secret key for later spending
    
    // Create a withdrawal proof (for unshielding funds)
    static std::vector<unsigned char> createWithdrawalProof(
        uint64_t publicAmount,           // Amount to withdraw
        const uint256& nullifier,        // Nullifier to prevent double-spending
        const uint256& merkleRoot,       // Current merkle root
        const std::vector<uint256>& merklePath, // Authentication path
        size_t pathIndex,                // Index in the tree
        const std::string& spendKey);    // Secret key to authorize spending
    
    // Verify a deposit proof
    static bool verifyDepositProof(
        const std::vector<unsigned char>& proofData,
        uint64_t publicAmount,
        const uint256& commitment);
    
    // Verify a withdrawal proof
    static bool verifyWithdrawalProof(
        const std::vector<unsigned char>& proofData,
        uint64_t publicAmount,
        const uint256& merkleRoot,
        const uint256& nullifier);

    // Convert uint256 to the bit vector format used by libsnark
    static std::vector<bool> uint256ToBits(const uint256& input);
    
    // Convert from libsnark bit vector back to uint256
    static uint256 bitsToUint256(const std::vector<bool>& bits);
    
    // Helper to serialize proof for on-chain storage
    static std::vector<unsigned char> serializeProof(
        const libsnark::r1cs_ppzksnark_proof<DefaultCurve>& proof);
    
    // Helper to deserialize proof from transaction data
    static libsnark::r1cs_ppzksnark_proof<DefaultCurve> deserializeProof(
        const std::vector<unsigned char>& proofData);

private:
    // Static members to hold the keys
    static std::shared_ptr<libsnark::r1cs_ppzksnark_proving_key<DefaultCurve>> provingKey;
    static std::shared_ptr<libsnark::r1cs_ppzksnark_verification_key<DefaultCurve>> verificationKey;
    
    // Flag to check if the system has been initialized
    static bool isInitialized;
}; 

} // namespace zkp
} // namespace ripple

#endif // ZK_PROVER_H