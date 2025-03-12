#ifndef RIPPLE_ZK_CIRCUIT_H
#define RIPPLE_ZK_CIRCUIT_H

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libff/algebra/curves/bn128/bn128_pp.hpp>

namespace ripple {
namespace zkp {

class ZkCircuit {
public:
    // Initialize the circuit
    static void initialize();
    
    // Generate deposit circuit and keys
    static void generateDepositKeys();
    
    // Generate withdrawal circuit and keys
    static void generateWithdrawalKeys();
    
    // Create a deposit proof
    static std::vector<unsigned char> proveDeposit(
        uint64_t value,
        const std::string& secret,
        uint256& outCommitment);
    
    // Create a withdrawal proof
    static std::vector<unsigned char> proveWithdrawal(
        uint64_t value,
        const std::string& secret,
        const std::vector<uint256>& merklePath,
        size_t pathIndex,
        const uint256& merkleRoot,
        uint256& outNullifier);
    
    // Verify a deposit proof
    static bool verifyDeposit(
        const std::vector<unsigned char>& proof,
        uint64_t value,
        const uint256& commitment);
    
    // Verify a withdrawal proof
    static bool verifyWithdrawal(
        const std::vector<unsigned char>& proof,
        uint64_t value,
        const uint256& merkleRoot,
        const uint256& nullifier);
};

} // namespace zkp
} // namespace ripple

#endif // RIPPLE_ZK_CIRCUIT_H