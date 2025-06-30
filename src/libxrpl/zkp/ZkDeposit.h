#ifndef RIPPLE_TX_ZKDEPOSIT_H_INCLUDED
#define RIPPLE_TX_ZKDEPOSIT_H_INCLUDED

#include <xrpld/app/tx/detail/Transactor.h>
#include <xrpl/protocol/STAmount.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/basics/base_uint.h>
#include "ZKProver.h"

namespace ripple {

// Forward declarations
class PreclaimContext;

/**
 * ZkDeposit transaction processor
 * 
 * Handles zero-knowledge deposit operations that allow users to:
 * - Deposit XRP into the shielded pool with full privacy
 * - Generate cryptographic commitments hiding transaction details
 * - Prove deposit validity without revealing amounts or identity
 * - Maintain unlinkability between deposits and future withdrawals
 * 
 * Required transaction fields:
 * - ZKProof: Zero-knowledge proof of deposit validity
 * - Commitment: Cryptographic commitment to the deposited note
 * - Nullifier: Unique identifier for double-spend prevention
 * - ValueCommitment: Cryptographic commitment hiding amount
 * - Amount: Deposit amount in XRP (for ledger balance updates)
 */
class ZkDeposit : public Transactor
{
public:
    static constexpr ConsequencesFactoryType ConsequencesFactory{Normal};

    explicit ZkDeposit(ApplyContext& ctx) : Transactor(ctx) {}

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
     * - Verifies zero-knowledge proof cryptographically
     * - Validates all cryptographic commitments
     */
    static TER preclaim(PreclaimContext const& ctx);

    /**
     * Transaction execution
     * - Transfers XRP from user account to shielded pool
     * - Updates shielded pool balance and commitment count
     * - Records commitment for future verification
     */
    TER doApply() override;

    /**
     * Client helper: Creates complete deposit proof
     * - Generates random note for deposit amount
     * - Creates zero-knowledge proof of deposit validity
     * - Returns ProofData for transaction submission
     * 
     * @param amount Deposit amount in drops
     * @param spendKey User's spending key
     * @return Complete proof data for transaction
     */
    static zkp::ProofData createDepositProof(
        uint64_t amount,
        const std::string& spendKey);

private:
    /**
     * Get or create the global shielded pool SLE
     * @param create Whether to create if it doesn't exist
     * @return Shared pointer to shielded pool SLE
     */
    std::shared_ptr<SLE> getShieldedPool(bool create = false);

    /**
     * Verify zero-knowledge deposit proof
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
     * Transfer XRP from user account to shielded pool
     * - Validates source account exists and has sufficient balance
     * - Deducts amount from user's account balance
     * - Handles all error cases gracefully
     * 
     * @param source Source account ID
     * @param amount Amount to transfer
     * @return TER result code
     */
    TER transferToPool(AccountID const& source, STAmount const& amount);
};

} // namespace ripple

#endif