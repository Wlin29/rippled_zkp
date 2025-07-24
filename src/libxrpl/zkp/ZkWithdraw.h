#ifndef RIPPLE_TX_ZKWITHDRAW_H_INCLUDED
#define RIPPLE_TX_ZKWITHDRAW_H_INCLUDED

#include <xrpld/app/tx/detail/Transactor.h>
#include <xrpl/protocol/STAmount.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/basics/base_uint.h>
#include "Note.h"
#include "ZKProver.h" 

namespace ripple {

// Forward declarations
class PreclaimContext;

/**
 * ZkWithdraw transaction processor
 * 
 * Handles zero-knowledge withdrawal operations that allow users to:
 * - Withdraw XRP from the shielded pool to any destination
 * - Prove ownership of a private note without revealing which one
 * - Maintain privacy while ensuring no double-spending
 * 
 * Required transaction fields:
 * - ZKProof: Serialized zero-knowledge proof
 * - Nullifier: Prevents double-spending 
 * - MerkleRoot: Tree anchor for proof validation
 * - ValueCommitment: Cryptographic amount commitment
 * - Destination: Recipient account
 * - Amount: Withdrawal amount in XRP
 */
class ZkWithdraw : public Transactor
{
public:
    static constexpr ConsequencesFactoryType ConsequencesFactory{Normal};

    explicit ZkWithdraw(ApplyContext& ctx) : Transactor(ctx) {}

    /**
     * Preflight validation (static checks)
     * - Verifies required fields are present
     * - Validates amount is positive XRP
     * - Checks ZK proof size constraints
     * - Ensures privacy feature is enabled
     */
    static NotTEC preflight(PreflightContext const& ctx);

    /**
     * Preclaim validation (ledger state checks)
     * - Initializes ZK system if needed
     * - Checks nullifier hasn't been used (prevents double-spending)
     * - Verifies zero-knowledge proof cryptographically
     * - Ensures shielded pool has sufficient balance
     */
    static TER preclaim(PreclaimContext const& ctx);

    /**
     * Transaction execution
     * - Updates shielded pool balance
     * - Records nullifier to prevent future double-spending
     * - Transfers XRP to destination account
     * - Creates destination account if needed
     */
    TER doApply() override;

    // Add helper function for creating withdrawal proofs
    static zkp::ProofData createWithdrawalProof(
        const zkp::Note& inputNote,
        const uint256& spendingKey,
        const std::vector<uint256>& authPath,
        size_t position,
        const uint256& merkleRoot
    );

private:
    /**
     * Get or create the global shielded pool SLE
     * @param create Whether to create if it doesn't exist
     * @return Shared pointer to shielded pool SLE
     */
    std::shared_ptr<SLE> getShieldedPool(bool create = false);

    /**
     * Verify zero-knowledge proof for withdrawal
     * This method is now static and takes PreclaimContext
     */
    bool verifyProof();

    /**
     * Verify zero-knowledge withdrawal proof
     * - Extracts proof data and public inputs from transaction
     * - Converts XRPL types to ZK proof system types  
     * - Calls ZkProver verification with proper parameters
     * - Handles all conversion and error cases
     * 
     * @param ctx Preclaim context containing transaction and view
     * @return true if proof is valid, false otherwise
     */
    static bool verifyZkProof(PreclaimContext const& ctx);

    /**
     * Transfer XRP to destination account
     * - Gets or creates destination account SLE
     * - Handles account creation with proper reserve requirements
     * - Updates account balance atomically
     * - Provides comprehensive error handling
     * 
     * @param destination Target account ID
     * @param amount Amount to transfer
     * @return TER result code
     */
    TER transferXRP(AccountID const& destination, STAmount const& amount);
};

} // namespace ripple

#endif