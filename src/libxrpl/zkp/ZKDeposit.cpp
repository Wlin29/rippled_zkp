#include "ZKDeposit.h"
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/jss.h>
#include <xrpl/zkp/ZkProver.h>
#include <xrpl/protocol/LedgerFormats.h>
#include "ShieldedMerkleTree.h"

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
    uint256 commitment;
    
    if (ctx_.tx.isFieldPresent(sfCommitment))
        commitment = ctx_.tx.getFieldH256(sfCommitment);
    
    // Get or create shielded pool
    auto shieldedPool = getShieldedPool(true);
    if (!shieldedPool)
        return tecINTERNAL;
    
    // Verify the ZK proof
    if (!verifyProof())
        return temBAD_PROOF;
    
    // Deserialize the Merkle tree
    SerialIter sit(
        shieldedPool->getFieldVL(sfShieldedState).data(),
        shieldedPool->getFieldVL(sfShieldedState).size());
    auto tree = ShieldedMerkleTree::deserialize(sit);
    
    // Add the commitment to the tree
    size_t index = tree.addCommitment(commitment);
    
    // Transfer funds to the pool (account -> null)
    TER result = accountSend(ctx_.view(), account, xrpAccount(), amount);
    if (result != tesSUCCESS)
        return result;
    
    // Serialize and save the updated tree
    Serializer s;
    tree.serialize(s);
    shieldedPool->setFieldVL(sfShieldedState, s.getData());
    
    // Update the root and pool size
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

bool
ZkDeposit::verifyProof()
{
    // Get proof data from transaction
    auto const& proofBlob = ctx_.tx.getFieldVL(sfZKProof);
    
    // Get public data
    uint64_t publicAmount = ctx_.tx.getFieldAmount(sfAmount).xrp().drops();
    
    // Get commitment
    uint256 commitment;
    if (ctx_.tx.isFieldPresent(sfCommitment))
        commitment = ctx_.tx.getFieldH256(sfCommitment);
    else
        return false;
    
    // Convert commitment to bit vector for ZKP verification
    std::vector<bool> commitmentBits;
    commitmentBits.reserve(256);
    for (int i = 0; i < 32; ++i) {
        for (int j = 0; j < 8; ++j) {
            commitmentBits.push_back((commitment.data()[i] >> j) & 1);
        }
    }
    
    // Verify the deposit proof
    return zkp::ZkProver::verifyDepositProof(
        std::vector<unsigned char>(proofBlob.begin(), proofBlob.end()),
        publicAmount,
        commitmentBits);
}

} // namespace ripple