#include "ZKWithdraw.h"
#include "ZKProver.h"
#include <xrpld/app/tx/detail/ZkWithdraw.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/jss.h>
#include <xrpl/protocol/LedgerFormats.h>
#include "ShieldedMerkleTree.h"

namespace ripple {

NotTEC
ZkWithdraw::preflight(PreflightContext const& ctx)
{
    // Check for feature activation
    if (!ctx.rules.enabled(featureZeroKnowledgePrivacy))
        return temDISABLED;
    
    // Basic transaction checks
    if (auto const ret = preflight1(ctx); !isTesSuccess(ret))
        return ret;
    
    // Verify required fields
    if (!ctx.tx.isFieldPresent(sfAmount) || 
        !ctx.tx.isFieldPresent(sfDestination) || 
        !ctx.tx.isFieldPresent(sfZKProof) ||
        !ctx.tx.isFieldPresent(sfNullifier))
        return temMALFORMED;
    
    // Amount checks
    auto const amount = ctx.tx.getFieldAmount(sfAmount);
    if (amount.negative() || !amount.native())
        return temBAD_AMOUNT;
    
    return preflight2(ctx);
}

TER
ZkWithdraw::preclaim(PreclaimContext const& ctx)
{
    // Get the shielded pool
    Keylet const poolKeylet{ltSHIELDED_POOL, uint256(0)};
    auto shieldedPool = ctx.view.peek(poolKeylet);
    if (!shieldedPool)
        return tecNO_ENTRY;
    
    // Deserialize the Merkle tree
    SerialIter sit(
        shieldedPool->getFieldVL(sfShieldedState).data(),
        shieldedPool->getFieldVL(sfShieldedState).size());
    auto tree = ShieldedMerkleTree::deserialize(sit);
    
    // Check for double-spend
    if (tree.isNullifierSpent(ctx.tx.getFieldH256(sfNullifier)))
        return tefALREADY;
    
    return tesSUCCESS;
}

TER
ZkWithdraw::doApply()
{
    auto const destination = ctx_.tx.getAccountID(sfDestination);
    auto const amount = ctx_.tx.getFieldAmount(sfAmount);
    auto const nullifier = ctx_.tx.getFieldH256(sfNullifier);
    
    // Get the shielded pool
    auto shieldedPool = getShieldedPool(false);
    if (!shieldedPool)
        return tecNO_ENTRY;
    
    // Deserialize the Merkle tree
    SerialIter sit(
        shieldedPool->getFieldVL(sfShieldedState).data(),
        shieldedPool->getFieldVL(sfShieldedState).size());
    auto tree = ShieldedMerkleTree::deserialize(sit);
    
    // Verify the ZK proof
    if (!verifyProof())
        return temBAD_PROOF;
    
    // Check for double-spend
    if (tree.isNullifierSpent(nullifier))
        return tefALREADY;
    
    // Mark nullifier as spent
    tree.markNullifierSpent(nullifier);
    
    // Transfer funds from pool to recipient (null -> destination)
    TER result = accountSend(ctx_.view(), xrpAccount(), destination, amount);
    if (result != tesSUCCESS)
        return result;
    
    // Serialize and save the updated tree
    Serializer s;
    tree.serialize(s);
    shieldedPool->setFieldVL(sfShieldedState, s.getData());
    
    ctx_.view().update(shieldedPool);
    
    return tesSUCCESS;
}

std::shared_ptr<SLE>
ZkWithdraw::getShieldedPool(bool create)
{
    Keylet const poolKeylet{ltSHIELDED_POOL, uint256(0)};
    return ctx_.view().peek(poolKeylet);
}

bool
ZkWithdraw::verifyProof()
{
    // Get proof data from transaction
    auto const& proofBlob = ctx_.tx.getFieldVL(sfZKProof);
    
    // Get public data
    uint64_t publicAmount = ctx_.tx.getFieldAmount(sfAmount).xrp().drops();
    
    // Get nullifier and merkle root
    auto const nullifier = ctx_.tx.getFieldH256(sfNullifier);
    
    // Get shielded pool
    auto shieldedPool = getShieldedPool(false);
    if (!shieldedPool)
        return false;
    
    // Get the current root for verification
    uint256 merkleRoot = shieldedPool->getFieldH256(sfCurrentRoot);
    
    // Convert to bit vectors
    std::vector<bool> nullifierBits;
    nullifierBits.reserve(256);
    for (int i = 0; i < 32; ++i) {
        for (int j = 0; j < 8; ++j) {
            nullifierBits.push_back((nullifier.data()[i] >> j) & 1);
        }
    }
    
    std::vector<bool> rootBits;
    rootBits.reserve(256);
    for (int i = 0; i < 32; ++i) {
        for (int j = 0; j < 8; ++j) {
            rootBits.push_back((merkleRoot.data()[i] >> j) & 1);
        }
    }
    
    // Verify the withdrawal proof
    return zkp::ZkProver::verifyWithdrawalProof(
        std::vector<unsigned char>(proofBlob.begin(), proofBlob.end()),
        publicAmount,
        rootBits,
        nullifierBits);
}

} // namespace ripple