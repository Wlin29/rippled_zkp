#ifndef COMMITMENT_GENERATOR_H
#define COMMITMENT_GENERATOR_H

#include <xrpl/protocol/UintTypes.h>
#include <string>
#include <vector>
#include <cstdint>

namespace ripple {
namespace zkp {

/**
 * @brief Structure to hold commitment data
 */
struct Commitment {
    uint256 commitment;     // The commitment that will be added to the Merkle tree
    uint256 nullifier;      // The nullifier that will be revealed when spending
    std::string blindingFactor; // Random blinding factor used in commitment
    uint64_t amount;        // Amount of XRP
    AccountID recipient;    // Recipient account ID
};

/**
 * @brief Class for generating and managing commitments for the ZKP system
 */
class CommitmentGenerator {
public:
    /**
     * @brief Generate a new commitment for depositing funds
     * 
     * @param amount Amount of XRP
     * @param recipient Recipient account ID
     * @return Commitment structure with all necessary data
     */
    static Commitment generateCommitment(uint64_t amount, const AccountID& recipient);
    
    /**
     * @brief Generate a nullifier from a commitment and a secret
     * 
     * @param commitment The commitment
     * @param secret Secret key for spending
     * @return uint256 The nullifier
     */
    static uint256 generateNullifier(const uint256& commitment, const std::string& secret);
    
    /**
     * @brief Generate a random blinding factor
     * 
     * @return std::string Random blinding factor
     */
    static std::string generateRandomBlindingFactor();
    
    /**
     * @brief Hash the commitment components to create the commitment value
     * 
     * @param amount Amount of XRP
     * @param recipient Recipient account ID
     * @param blindingFactor Random blinding factor
     * @return uint256 The commitment hash
     */
    static uint256 hashCommitment(
        uint64_t amount, 
        const AccountID& recipient, 
        const std::string& blindingFactor);
};

} // namespace zkp
} // namespace ripple

#endif // COMMITMENT_GENERATOR_H
