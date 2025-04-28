#include "ZkPayment.h"
#include <xrpld/ledger/ApplyViewImpl.h>
#include "ShieldedMerkleTree.h"
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/jss.h>
#include <xrpl/basics/Blob.h>
#include "ZKProver.h"

namespace ripple {
    namespace keylet {
        inline Keylet nullifier(uint256 const& id)
        {
            // ltNULLIFIER must be defined in your ledger entries.
            return Keylet(ltNULLIFIER, id);
        }
        inline Keylet shielded_pool()
        {
            // ltSHIELDED_POOL must be defined in your ledger entries.
            return Keylet(ltSHIELDED_POOL, uint256());
        }
    }

// Fixed verify_zk_proof function to use proper namespaces
bool verify_zk_proof(ripple::Blob const& proofData, ripple::AccountID const& account)
{
    // Ensure the ZK prover is initialized
    if (!zkp::ZkProver::isInitialized)
        zkp::ZkProver::initialize();

    // Get the root and nullifier from account state
    // This is a simplified version - you would normally extract these from the transaction
    uint256 merkleRoot;  // Should be fetched from the pool state
    uint256 nullifier;   // Should be extracted from the transaction
    uint64_t amount = 0; // Amount would be extracted from the transaction

    // Use the ZkProver to verify the withdrawal proof
    return zkp::ZkProver::verifyWithdrawalProof(
        proofData, 
        amount, 
        merkleRoot, 
        nullifier);
}

NotTEC
ZKPayment::preflight(PreflightContext const& ctx)
{
    if (!ctx.rules.enabled(featureZeroKnowledgePrivacy))
        return temDISABLED;

    if (!ctx.tx.isFieldPresent(sfZKProof))
        return temMALFORMED;

    if (!ctx.tx.isFieldPresent(sfCommitment))
        return temMALFORMED;

    if (!ctx.tx.isFieldPresent(sfNullifier))
        return temMALFORMED;

    return preflight2(ctx);
}

TER
ZKPayment::preclaim(PreclaimContext const& ctx)
{
    // Check if proof is valid
    if (!verify_zk_proof(
            ctx.tx.getFieldVL(sfZKProof),
            ctx.tx.getAccountID(sfAccount)))
        return temINVALID_PROOF;

    // Check if nullifier already used
    if (ctx.view.exists(keylet::nullifier(ctx.tx.getFieldH256(sfNullifier))))
        return temDUPLICATE_NULLIFIER;

    return tesSUCCESS;
}

TER
ZKPayment::doApply()
{
    auto slePool = view().peek(keylet::shielded_pool());
    if (!slePool)
        return tecNO_ENTRY;

    // Add commitment to the Merkle tree in the pool
    auto& tx = ctx_.tx;
    uint256 commitment = tx.getFieldH256(sfCommitment);

    // Deserialize the Merkle tree
    SerialIter sit(
        slePool->getFieldVL(sfShieldedState).data(),
        slePool->getFieldVL(sfShieldedState).size());
    auto tree = ShieldedMerkleTree::deserialize(sit);

    // Add the new commitment
    tree.addCommitment(commitment);

    // Serialize the updated tree back into a blob
    Serializer s;
    tree.serialize(s);
    slePool->setFieldVL(sfShieldedState, s.getData());
    slePool->setFieldH256(sfCurrentRoot, tree.getRoot());
    slePool->setFieldU32(sfPoolSize, static_cast<std::uint32_t>(tree.getCommitments().size()));

    // Record nullifier to prevent double spending
    auto nullifierKeylet = keylet::nullifier(tx.getFieldH256(sfNullifier));
    auto sleNullifier = std::make_shared<SLE>(nullifierKeylet);
    sleNullifier->setFieldH256(sfNullifier, tx.getFieldH256(sfNullifier));
    view().insert(sleNullifier);

    // Update the pool
    view().update(slePool);

    return tesSUCCESS;
}

} // namespace ripple