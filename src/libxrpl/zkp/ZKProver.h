#ifndef ZK_PROVER_H
#define ZK_PROVER_H

#include <vector>
#include <string>
#include <memory>
#include <xrpl/protocol/UintTypes.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

namespace ripple {
namespace zkp {

using DefaultCurve = libff::alt_bn128_pp;

class ZkProver {
public:
    static void initialize();
    static bool isInitialized;

    static std::shared_ptr<libsnark::r1cs_gg_ppzksnark_proving_key<DefaultCurve>> depositProvingKey;
    static std::shared_ptr<libsnark::r1cs_gg_ppzksnark_verification_key<DefaultCurve>> depositVerificationKey;
    static std::shared_ptr<libsnark::r1cs_gg_ppzksnark_proving_key<DefaultCurve>> withdrawalProvingKey;
    static std::shared_ptr<libsnark::r1cs_gg_ppzksnark_verification_key<DefaultCurve>> withdrawalVerificationKey;

    // Key management
    static bool generateDepositKeys(bool forceRegeneration = false);
    static bool generateWithdrawalKeys(bool forceRegeneration = false);
    static bool generateKeys(bool forceRegeneration = false);

    static bool saveKeys(const std::string& basePath);
    static bool loadKeys(const std::string& basePath);

    // Proof creation
    static std::vector<unsigned char> createDepositProof(
        uint64_t publicAmount,
        const uint256& commitment,
        const std::string& spendKey);

    static std::vector<unsigned char> createWithdrawalProof(
        uint64_t publicAmount,
        const uint256& nullifier,
        const uint256& merkleRoot,
        const std::vector<uint256>& merklePath,
        size_t pathIndex,
        const std::string& spendKey);

    // Proof verification
    static bool verifyDepositProof(
        const std::vector<unsigned char>& proofData,
        uint64_t publicAmount,
        const uint256& commitment);

    static bool verifyWithdrawalProof(
        const std::vector<unsigned char>& proofData,
        uint64_t publicAmount,
        const uint256& merkleRoot,
        const uint256& nullifier);

    // Utility functions
    static std::vector<bool> uint256ToBits(const uint256& input);
    static uint256 bitsToUint256(const std::vector<bool>& bits);

private:
    // Proof serialization
    static std::vector<unsigned char> serializeProof(
        const libsnark::r1cs_gg_ppzksnark_proof<DefaultCurve>& proof);
    static libsnark::r1cs_gg_ppzksnark_proof<DefaultCurve> deserializeProof(
        const std::vector<unsigned char>& proofData);
};

} // namespace zkp
} // namespace ripple

#endif // ZK_PROVER_H