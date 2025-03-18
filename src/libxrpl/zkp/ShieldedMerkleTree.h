#pragma once

#include <vector>
#include <set>
#include <cstdint>
#include <xrpl/protocol/UintTypes.h>
#include <xrpl/protocol/Serializer.h>
// #include <xrpl/protocol/SerialIter.h>

namespace ripple {

// You may adjust the depth as needed.
constexpr size_t TREE_DEPTH = 10;

class ShieldedMerkleTree
{
public:
    ShieldedMerkleTree();

    // Returns the SHA512-Half hash of two child nodes.
    static uint256 hashChildren(const uint256& left, const uint256& right);

    // Update the authentication path from the given leaf index up to the root.
    void updatePath(size_t leafIndex);

    // Add a new commitment as a leaf, update the tree and return its index.
    size_t addCommitment(const uint256& commitment);

    // Check whether a given nullifier is already marked as spent.
    bool isNullifierSpent(const uint256& nullifier) const;

    // Mark a given nullifier as spent.
    void markNullifierSpent(const uint256& nullifier);

    // Get the current Merkle root.
    uint256 getRoot() const;

    // Check whether a given root is valid (exists in history).
    bool isValidRoot(const uint256& root) const;

    // Get the authentication path (sibling nodes) for a given leaf index.
    std::vector<uint256> getAuthPath(size_t leafIndex) const;

    // Serialization
    void serialize(Serializer& s) const;
    static ShieldedMerkleTree deserialize(SerialIter& sit);

    // Accessor for commitments if needed.
    std::vector<uint256> const& getCommitments() const { return commitments; }

private:
    // The list of commitments (leaf values).
    std::vector<uint256> commitments;

    // The binary tree: level 0 is the root, level TREE_DEPTH are the leaves.
    std::vector< std::vector<uint256> > tree;

    // A set of spent nullifiers.
    std::set<uint256> nullifiers;

    // A history of recently computed roots.
    std::vector<uint256> rootHistory;
};

} // namespace ripple