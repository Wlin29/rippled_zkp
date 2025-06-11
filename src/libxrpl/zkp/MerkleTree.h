#pragma once

#include <vector>
#include <array>
#include <string>
#include <xrpl/basics/base_uint.h>

namespace ripple {
namespace zkp {

/**
 * Zcash-style Merkle Tree implementation
 * Uses SHA256 for internal hash computations
 */
class MerkleTree {
public:
    explicit MerkleTree(size_t depth);
    
    // Add a leaf and return its index
    size_t addLeaf(const uint256& leaf);
    
    // Get authentication path for a leaf
    std::vector<uint256> getAuthPath(size_t leafIndex) const;
    
    // Get current root
    uint256 getRoot() const;
    
    // Get tree depth
    size_t getDepth() const { return depth_; }
    
    // Get number of leaves
    size_t getNumLeaves() const { return leaves_.size(); }
    
    // Verify an authentication path
    static bool verifyPath(
        const uint256& leaf,
        const std::vector<uint256>& path,
        size_t index,
        const uint256& root);
    
    // Compute SHA256 of two 256-bit values
    static uint256 sha256_compress(const uint256& left, const uint256& right);

private:
    size_t depth_;
    std::vector<uint256> leaves_;
    std::vector<std::vector<uint256>> tree_; // tree_[level][index]
    
    void updatePath(size_t leafIndex);
    uint256 computeRoot() const;
};

} // namespace zkp
} // namespace ripple