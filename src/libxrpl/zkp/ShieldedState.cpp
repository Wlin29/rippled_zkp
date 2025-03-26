// #include "ShieldedState.h"
// #include <xrpl/protocol/STObject.h>
// #include <xrpl/protocol/Keylet.h>
// #include <xrpl/protocol/jss.h>
// #include <xrpl/basics/Log.h>

// namespace ripple {

// ShieldedState::ShieldedState(const ShieldedMerkleTree& tree)
//     : tree_(tree)
// {
// }

// Blob ShieldedState::serialize() const
// {
//     Serializer s;
//     tree_.serialize(s);
//     return s.getData();
// }

// ShieldedState ShieldedState::deserialize(Blob const& data)
// {
//     ShieldedState state;
//     SerialIter sit(data.data(), data.size());
//     state.tree_ = ShieldedMerkleTree::deserialize(sit);
//     return state;
// }

// size_t ShieldedState::addCommitment(uint256 const& commitment)
// {
//     return tree_.addCommitment(commitment);
// }

// void ShieldedState::markNullifierSpent(uint256 const& nullifier)
// {
//     tree_.markNullifierSpent(nullifier);
// }

// bool ShieldedState::isNullifierSpent(uint256 const& nullifier) const
// {
//     return tree_.isNullifierSpent(nullifier);
// }

// uint256 ShieldedState::getRoot() const
// {
//     return tree_.getRoot();
// }

// std::vector<uint256> ShieldedState::getAuthPath(size_t leafIndex) const
// {
//     return tree_.getAuthPath(leafIndex);
// }

// bool ShieldedState::isValidRoot(uint256 const& root) const
// {
//     return tree_.isValidRoot(root);
// }

// // Helper to get the shielded state from the ledger
// std::shared_ptr<ShieldedState> getShieldedState(
//     ReadView const& view, 
//     AccountID const& account)
// {
//     // Get the shielded pool state from the ledger
//     auto const k = keylet::shieldedPool(account);
//     auto const sle = view.read(k);
    
//     if (!sle)
//         return nullptr;
    
//     // Extract the shielded state blob from the SLE
//     if (!sle->isFieldPresent(sfShieldedState))
//         return nullptr;
    
//     auto const& stateBlob = sle->getFieldVL(sfShieldedState);
//     return std::make_shared<ShieldedState>(ShieldedState::deserialize(stateBlob));
// }

// // Helper to update the shielded state in the ledger
// TER updateShieldedState(
//     ApplyView& view,
//     AccountID const& account,
//     ShieldedState const& state)
// {
//     auto const k = keylet::shieldedPool(account);
//     auto sle = view.peek(k);
    
//     if (!sle)
//     {
//         // Create a new shielded pool state
//         sle = std::make_shared<SLE>(k);
//         sle->setAccountID(sfAccount, account);
//         sle->setFieldU32(sfPoolSize, 0);
//         view.insert(sle);
//     }
    
//     // Serialize the state
//     auto stateBlob = state.serialize();
//     sle->setFieldVL(sfShieldedState, stateBlob);
    
//     // Update the current root
//     sle->setFieldH256(sfCurrentRoot, state.getRoot());
    
//     // Update the pool size
//     sle->setFieldU32(sfPoolSize, static_cast<uint32_t>(state.getTree().getCommitments().size()));
    
//     view.update(sle);
//     return tesSUCCESS;
// }

// } // namespace ripple
