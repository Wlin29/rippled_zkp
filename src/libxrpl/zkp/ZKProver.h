#ifndef ZK_PROVER_H
#define ZK_PROVER_H

#include <vector>
#include <xrpl/basics/base_uint.h>

namespace ripple {
namespace zkp {

class ZkProver {
public:
    // Generate proving/verification keys (one-time setup)
    static void generateKeys();
    
    // Create a deposit proof
    static std::vector<unsigned char> createDepositProof(
        uint64_t publicAmount,
        uint64_t value,
        const std::string& senderSecret,
        const std::string& recipient);
    
    // Create a withdrawal proof
    static std::vector<unsigned char> createWithdrawalProof(
        uint64_t publicAmount, 
        uint64_t value,
        const std::string& spenderSecret,
        const std::string& recipient,
        const std::vector<bool>& merklePath,
        const std::vector<bool>& merkleRoot);
    
    // Verify a deposit proof
    static bool verifyDepositProof(
        const std::vector<unsigned char>& proofData,
        uint64_t publicAmount,
        const std::vector<bool>& commitment);
    
    // Verify a withdrawal proof
    static bool verifyWithdrawalProof(
        const std::vector<unsigned char>& proofData,
        uint64_t publicAmount,
        const std::vector<bool>& merkleRoot,
        const std::vector<bool>& nullifier);
};

} // namespace zkp
} // namespace ripple

#endif