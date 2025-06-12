#pragma once

#include <xrpl/basics/base_uint.h>
#include <vector>
#include <array>
#include <memory>
#include <unordered_map>

namespace ripple {
namespace zkp {

/**
 * Incremental Merkle Tree Implementation
 * 
 * Based on the approach used in Zcash for efficient note commitment trees.
 * Key features:
 * - O(log n) incremental updates
 * - Cached intermediate nodes
 * - Efficient authentication path generation
 * - Persistent storage support
 */
class IncrementalMerkleTree {
public:
    static constexpr size_t DEFAULT_DEPTH = 32;
    static constexpr size_t MAX_LEAVES = (1ULL << DEFAULT_DEPTH);
    
    explicit IncrementalMerkleTree(size_t depth = DEFAULT_DEPTH);
    
    // Core operations
    size_t append(const uint256& leaf);
    uint256 root() const;
    std::vector<uint256> authPath(size_t position) const;
    bool verify(const uint256& leaf, const std::vector<uint256>& path, size_t position, const uint256& expectedRoot) const;
    
    // State management
    size_t size() const { return next_position_; }
    bool empty() const { return next_position_ == 0; }
    void clear();
    
    // Serialization for persistence
    std::vector<uint8_t> serialize() const;
    static IncrementalMerkleTree deserialize(const std::vector<uint8_t>& data);
    
    // Batch operations for efficiency
    std::vector<size_t> appendBatch(const std::vector<uint256>& leaves);
    void precomputeNodes(size_t upToPosition);

private:
    size_t depth_;
    size_t next_position_;
    
    // Cached nodes: level -> position -> hash
    std::vector<std::unordered_map<size_t, uint256>> cached_nodes_;
    
    // Most recent nodes at each level (for incremental updates)
    std::vector<uint256> frontier_;
    
    // Helper functions
    uint256 hash(const uint256& left, const uint256& right) const;
    uint256 getNode(size_t level, size_t position) const;
    void setNode(size_t level, size_t position, const uint256& value);
    void updateFrontier(size_t position);
    uint256 computeRoot(size_t upToPosition) const;
    
    // Constants for empty tree optimization
    std::vector<uint256> empty_hashes_;
    void initializeEmptyHashes();
};

/**
 * Witness for Merkle tree membership proofs
 */
struct MerkleWitness {
    uint256 leaf;
    std::vector<uint256> auth_path;
    size_t position;
    uint256 root;
    
    bool verify() const;
    std::vector<uint8_t> serialize() const;        // DECLARATION ONLY
    static MerkleWitness deserialize(const std::vector<uint8_t>& data);  // DECLARATION ONLY
};

} // namespace zkp
} // namespace ripple