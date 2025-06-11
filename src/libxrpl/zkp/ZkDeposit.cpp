#include "ZkDeposit.h"
#include "ShieldedMerkleTree.h"
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/jss.h>
#include <xrpl/protocol/LedgerFormats.h>

namespace ripple {

NotTEC
ZkDeposit::preflight(PreflightContext const& ctx)
{
    // Check for feature activation
    if (!ctx.rules.enabled(featureZeroKnowledgePrivacy))
        return temDISABLED;
    
    // Basic transaction checks
    if (auto const ret = preflight1(ctx); !isTesSuccess(ret))
        return ret;
    
    // Verify required fields
    if (!ctx.tx.isFieldPresent(sfAmount) || !ctx.tx.isFieldPresent(sfZKProof))
        return temBAD_AMOUNT;
    
    // Amount checks
    auto const amount = ctx.tx.getFieldAmount(sfAmount);
    if (amount.negative() || !amount.native())
        return temBAD_AMOUNT;
    
    return preflight2(ctx);
}

TER
ZkDeposit::preclaim(PreclaimContext const& ctx)
{
    // Verify the proof exists
    if (!ctx.tx.isFieldPresent(sfZKProof))
        return temBAD_PROOF;
    
    // Verify commitment is present
    if (!ctx.tx.isFieldPresent(sfCommitment))
        return temBAD_PROOF;
    
    return tesSUCCESS;
}

TER
ZkDeposit::doApply()
{
    auto const account = ctx_.tx.getAccountID(sfAccount);
    auto const amount = ctx_.tx.getFieldAmount(sfAmount);
    uint256 commitment = ctx_.tx.getFieldH256(sfCommitment);

    // Obtain the Shielded Pool ledger entry (or create one if it doesn't exist).
    auto shieldedPool = getShieldedPool(true);
    if (!shieldedPool)
        return tecINTERNAL;

    // Deserialize the serialized Merkle tree from the ledger.
    SerialIter sit(
        shieldedPool->getFieldVL(sfShieldedState).data(),
        shieldedPool->getFieldVL(sfShieldedState).size());
    auto tree = ShieldedMerkleTree::deserialize(sit);

    // Add the new commitment.
    size_t index = tree.addCommitment(commitment);
    
    // Transfer funds (example, moving funds into the pool).
    TER result = accountSend(ctx_.view(), account, xrpAccount(), amount);
    if (result != tesSUCCESS)
        return result;

    // Serialize the updated tree back into a blob.
    Serializer s;
    tree.serialize(s);
    shieldedPool->setFieldVL(sfShieldedState, s.getData());

    // Update the ledger entry with the new tree root and pool size.
    shieldedPool->setFieldH256(sfCurrentRoot, tree.getRoot());
    shieldedPool->setFieldU32(sfPoolSize, static_cast<std::uint32_t>(tree.getCommitments().size()));

    ctx_.view().update(shieldedPool);
    return tesSUCCESS;
}

std::shared_ptr<SLE>
ZkDeposit::getShieldedPool(bool create)
{
    Keylet const poolKeylet{ltSHIELDED_POOL, uint256(0)};
    auto shieldedPool = ctx_.view().peek(poolKeylet);
    
    if (!shieldedPool && create)
    {
        // Create the shielded pool
        shieldedPool = std::make_shared<SLE>(poolKeylet);
        
        // Initialize with empty tree
        ShieldedMerkleTree initialTree;
        Serializer s;
        initialTree.serialize(s);
        shieldedPool->setFieldVL(sfShieldedState, s.getData());
        
        // Set initial root & size
        shieldedPool->setFieldH256(sfCurrentRoot, initialTree.getRoot());
        shieldedPool->setFieldU32(sfPoolSize, 1); // Initial zero commitment
        
        ctx_.view().insert(shieldedPool);
    }
    
    return shieldedPool;
}

TER
ZkDeposit::accountSend(ApplyView& view,
                       AccountID const& src,
                       AccountID const& dst,
                       STAmount const& amount)
{
    // Look up source and destination ledger entries
    auto sleSrc = view.peek(keylet::account(src));
    auto sleDst = view.peek(keylet::account(dst));

    if (!sleSrc || !sleDst)
        return terNO_ACCOUNT;

    // Retrieve current balance from the source ledger entry
    STAmount srcBalance = sleSrc->getFieldAmount(sfBalance);
    
    // Check whether the source has enough funds
    if (srcBalance < amount)
        return terINSUF_FEE_B;

    // Deduct the amount from the source balance
    srcBalance = srcBalance - amount;
    sleSrc->setFieldAmount(sfBalance, srcBalance);

    // Credit the destination account
    STAmount dstBalance = sleDst->getFieldAmount(sfBalance);
    dstBalance = dstBalance + amount;
    sleDst->setFieldAmount(sfBalance, dstBalance);

    // Update both ledger entries in the view
    view.update(sleSrc);
    view.update(sleDst);

    return tesSUCCESS;
}

} // namespace ripple