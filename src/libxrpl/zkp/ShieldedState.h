// #pragma once

// #include "ShieldedMerkleTree.h"
// #include <xrpl/protocol/SField.h>
// #include <xrpl/protocol/STObject.h>
// #include <xrpl/protocol/Serializer.h>

// namespace ripple {

// // Class to handle the serialization and deserialization of the shielded state
// class ShieldedState
// {
// public:
//     ShieldedState() = default;
    
//     // Create from a Merkle tree
//     explicit ShieldedState(const ShieldedMerkleTree& tree);
    
//     // Getters
//     const ShieldedMerkleTree& getTree() const { return tree_; }
//     ShieldedMerkleTree& getTree() { return tree_; }
    
//     // Serialize to a blob for storing in ledger
//     Blob serialize() const;
    
//     // Deserialize from a blob stored in ledger
//     static ShieldedState deserialize(Blob const& data);
    
//     // Add a commitment to the Merkle tree
//     size_t addCommitment(uint256 const& commitment);
    
//     // Mark a nullifier as spent
//     void markNullifierSpent(uint256 const& nullifier);
    
//     // Check if a nullifier is spent
//     bool isNullifierSpent(uint256 const& nullifier) const;
    
//     // Get the current Merkle root
//     uint256 getRoot() const;
    
//     // Get authentication path for a leaf
//     std::vector<uint256> getAuthPath(size_t leafIndex) const;
    
//     // Check if a root is valid (exists in history)
//     bool isValidRoot(uint256 const& root) const;
    
// private:
//     ShieldedMerkleTree tree_;
// };

// // Helper function to retrieve ShieldedState from a ledger entry
// std::shared_ptr<ShieldedState> getShieldedState(
//     ReadView const& view, 
//     AccountID const& account);

// // Helper function to create or update ShieldedState in a ledger
// TER updateShieldedState(
//     ApplyView& view,
//     AccountID const& account,
//     ShieldedState const& state);

// } // namespace ripple
