#include "IncrementalMerkleTree.h"
#include <iostream>
#include <cassert>
#include <algorithm>
#include <openssl/sha.h> 
#include <cstring> 

namespace ripple {
namespace zkp {

IncrementalMerkleTree::IncrementalMerkleTree(size_t depth) 
    : depth_(depth), next_position_(0) {
    
    if (depth > 64) {
        throw std::invalid_argument("Tree depth too large");
    }
    
    // Initialize storage for each level
    cached_nodes_.resize(depth + 1);
    frontier_.resize(depth + 1);
    
    // Precompute empty subtree hashes
    initializeEmptyHashes();
}

void IncrementalMerkleTree::initializeEmptyHashes() {
    empty_hashes_.resize(depth_ + 1);
    
    // Level 0 (leaves): use zero hash
    empty_hashes_[0] = uint256{};
    
    // Higher levels: hash(empty[i-1], empty[i-1])
    for (size_t i = 1; i <= depth_; ++i) {
        empty_hashes_[i] = hash(empty_hashes_[i-1], empty_hashes_[i-1]);
    }
}

uint256 IncrementalMerkleTree::hash(const uint256& left, const uint256& right) const {
    // Use consistent byte ordering
    std::vector<uint8_t> input(64);
    
    // Copy left hash (32 bytes)
    std::memcpy(&input[0], left.begin(), 32);
    
    // Copy right hash (32 bytes)
    std::memcpy(&input[32], right.begin(), 32);
    
    uint256 result;
    SHA256(input.data(), input.size(), result.begin());
    
    return result;
}

size_t IncrementalMerkleTree::append(const uint256& leaf) {
    if (next_position_ >= MAX_LEAVES) {
        throw std::overflow_error("Merkle tree is full");
    }
    
    size_t position = next_position_++;
    
    // Set the leaf
    setNode(0, position, leaf);
    
    // Update internal nodes incrementally
    updateFrontier(position);
    
    return position;
}

void IncrementalMerkleTree::updateFrontier(size_t position) {
    if (position != next_position_ - 1) {
        std::cout << "WARNING: updateFrontier called with wrong position: " 
                  << position << " expected: " << (next_position_ - 1) << std::endl;
        return;
    }
    
    uint256 current = getNode(0, position);
    size_t current_pos = position;
    
    // Store the leaf in frontier
    frontier_[0] = current;
    
    // Build up the tree level by level using the same logic as computeRoot
    for (size_t level = 0; level < depth_; ++level) {
        size_t parent_pos = current_pos >> 1;
        
        // Get left and right children for this parent
        size_t left_pos = parent_pos << 1;
        size_t right_pos = left_pos + 1;
        
        uint256 left_child, right_child;
        
        // Use same logic as computeRoot for getting children
        if (left_pos < next_position_) {
            left_child = getNode(level, left_pos);
        } else {
            left_child = empty_hashes_[level];
        }
        
        if (right_pos < next_position_) {
            right_child = getNode(level, right_pos);
        } else {
            right_child = empty_hashes_[level];
        }
        
        // Compute parent using same hash order as computeRoot
        uint256 parent = hash(left_child, right_child);
        
        // Store the computed parent
        setNode(level + 1, parent_pos, parent);
        frontier_[level + 1] = parent;
        
        // Move up to next level
        current = parent;
        current_pos = parent_pos;
        
        // If we've reached a point where this parent won't change, we can stop
        if (parent_pos == 0 || (next_position_ <= ((parent_pos + 1) << (level + 1)))) {
            break;
        }
    }
    
    // The root is stored at the top level
    frontier_[depth_] = frontier_[depth_ - 1];
}

uint256 IncrementalMerkleTree::computeRoot(size_t upToPosition) const {
    if (upToPosition == 0) {
        return empty_hashes_[depth_];
    }
    
    // Build tree bottom-up, level by level
    std::vector<uint256> current_level;
    
    // Level 0: collect all leaves up to position
    for (size_t pos = 0; pos < upToPosition; ++pos) {
        current_level.push_back(getNode(0, pos));
    }
    
    // Pad to next power of 2 for complete binary tree
    size_t target_size = 1;
    while (target_size < upToPosition) {
        target_size <<= 1;
    }
    
    // Pad with empty hashes to make complete level
    while (current_level.size() < target_size) {
        current_level.push_back(empty_hashes_[0]);
    }
    
    // Build tree level by level
    for (size_t level = 0; level < depth_; ++level) {
        if (current_level.size() <= 1) {
            break;
        }
        
        std::vector<uint256> next_level;
        
        // Process pairs at this level
        for (size_t i = 0; i < current_level.size(); i += 2) {
            uint256 left = current_level[i];
            uint256 right = (i + 1 < current_level.size()) ? 
                current_level[i + 1] : empty_hashes_[level];
            
            // Use same hash function as updateFrontier
            uint256 parent = hash(left, right);
            next_level.push_back(parent);
        }
        
        current_level = std::move(next_level);
    }
    
    // Return the root
    return current_level.empty() ? empty_hashes_[depth_] : current_level[0];
}

uint256 IncrementalMerkleTree::root() const {
    if (next_position_ == 0) {
        return empty_hashes_[depth_];
    }
    
    // Get any leaf and its authentication path
    uint256 leaf = getNode(0, 0);  // Use first leaf
    auto path = authPath(0);       // Get its authentication path
    
    uint256 current = leaf;
    size_t current_pos = 0;
    
    // Follow the path up using IDENTICAL logic to verify()
    for (size_t level = 0; level < depth_; ++level) {
        uint256 sibling = path[level];
        
        if (current_pos & 1) {
            // Current is right child, sibling is left
            current = hash(sibling, current);
        } else {
            // Current is left child, sibling is right
            current = hash(current, sibling);
        }
        
        current_pos >>= 1;
    }
    
    return current;
}

std::vector<uint256> IncrementalMerkleTree::authPath(size_t position) const {
    if (position >= next_position_) {
        throw std::out_of_range("Position not in tree");
    }
    
    std::vector<uint256> path;
    path.reserve(depth_);
    
    size_t current_pos = position;
    
    for (size_t level = 0; level < depth_; ++level) {
        // Calculate sibling position
        size_t sibling_pos = current_pos ^ 1;
        
        uint256 sibling;
        if (sibling_pos < next_position_) {
            // Sibling exists in tree
            sibling = getNode(level, sibling_pos);
        } else {
            // Sibling is empty (beyond current tree size)
            sibling = empty_hashes_[level];
        }
        
        path.push_back(sibling);
        current_pos >>= 1; // Move to parent level
    }
    
    return path;
}

bool IncrementalMerkleTree::verify(
    const uint256& leaf, 
    const std::vector<uint256>& path, 
    size_t position, 
    const uint256& expectedRoot) const {
    
    if (path.size() != depth_) {
        std::cout << "VERIFY FAIL: Path size mismatch: " << path.size() 
                  << " != " << depth_ << std::endl;
        return false;
    }
    
    uint256 current = leaf;
    size_t current_pos = position;
    
    // Follow the path up the tree using same logic as computeRoot
    for (size_t level = 0; level < depth_; ++level) {
        uint256 sibling = path[level];
        
        // Determine if current node is left or right child
        if (current_pos & 1) {
            // Current is right child, sibling is left
            current = hash(sibling, current);
        } else {
            // Current is left child, sibling is right
            current = hash(current, sibling);
        }
        
        current_pos >>= 1;
    }
    
    bool valid = (current == expectedRoot);
    if (!valid) {
        std::cout << "VERIFY FAIL: Root mismatch:" << std::endl;
        std::cout << "  Computed: " << current << std::endl;
        std::cout << "  Expected: " << expectedRoot << std::endl;
        std::cout << "  Leaf: " << leaf << std::endl;
        std::cout << "  Position: " << position << std::endl;
        
        // Debug: Show path
        std::cout << "  Auth path:" << std::endl;
        for (size_t i = 0; i < path.size(); ++i) {
            std::cout << "    Level " << i << ": " << path[i] << std::endl;
        }
    }
    
    return valid;
}

uint256 IncrementalMerkleTree::getNode(size_t level, size_t position) const {
    if (level >= cached_nodes_.size()) {
        return empty_hashes_.empty() ? uint256{} : empty_hashes_[std::min(level, empty_hashes_.size() - 1)];
    }
    
    auto it = cached_nodes_[level].find(position);
    if (it != cached_nodes_[level].end()) {
        return it->second;
    }
    
    // Return appropriate empty hash for this level
    if (level < empty_hashes_.size()) {
        return empty_hashes_[level];
    }
    return uint256{};
}

void IncrementalMerkleTree::setNode(size_t level, size_t position, const uint256& value) {
    if (level < cached_nodes_.size()) {
        cached_nodes_[level][position] = value;
    }
}

void IncrementalMerkleTree::clear() {
    next_position_ = 0;
    
    // Clear all cached nodes
    for (auto& level : cached_nodes_) {
        level.clear();
    }
    
    // Reset frontier to empty hashes
    if (!empty_hashes_.empty()) {
        for (size_t i = 0; i < frontier_.size() && i < empty_hashes_.size(); ++i) {
            frontier_[i] = empty_hashes_[i];
        }
    }
    
    std::cout << "Merkle tree cleared" << std::endl;
}

std::vector<uint8_t> IncrementalMerkleTree::serialize() const {
    std::vector<uint8_t> data;
    
    // Write header: depth (8 bytes) + next_position (8 bytes)
    data.resize(16);
    std::memcpy(data.data(), &depth_, 8);
    std::memcpy(data.data() + 8, &next_position_, 8);
    
    // Write number of levels with data
    uint64_t numLevels = 0;
    for (const auto& level : cached_nodes_) {
        if (!level.empty()) {
            numLevels++;
        }
    }
    
    size_t offset = data.size();
    data.resize(offset + 8);
    std::memcpy(data.data() + offset, &numLevels, 8);
    
    // Write each level's data
    for (size_t levelIdx = 0; levelIdx < cached_nodes_.size(); ++levelIdx) {
        const auto& level = cached_nodes_[levelIdx];
        if (level.empty()) continue;
        
        // Write level index and number of nodes
        offset = data.size();
        data.resize(offset + 16);
        std::memcpy(data.data() + offset, &levelIdx, 8);
        uint64_t nodeCount = level.size();
        std::memcpy(data.data() + offset + 8, &nodeCount, 8);
        
        // Write each node: position(8) + hash(32)
        for (const auto& [position, hash] : level) {
            offset = data.size();
            data.resize(offset + 40);
            std::memcpy(data.data() + offset, &position, 8);
            std::memcpy(data.data() + offset + 8, hash.begin(), 32);
        }
    }
    
    return data;
}

IncrementalMerkleTree IncrementalMerkleTree::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 16) {
        throw std::invalid_argument("Invalid serialized data size");
    }
    
    // Read header
    size_t depth, next_pos;
    std::memcpy(&depth, data.data(), 8);
    std::memcpy(&next_pos, data.data() + 8, 8);
    
    // Create tree
    IncrementalMerkleTree tree(depth);
    tree.next_position_ = next_pos;
    
    if (data.size() < 24) {
        return tree;
    }
    
    // Read number of levels
    uint64_t numLevels;
    std::memcpy(&numLevels, data.data() + 16, 8);
    
    size_t offset = 24;
    
    // Read each level's data
    for (uint64_t i = 0; i < numLevels && offset + 16 <= data.size(); ++i) {
        // Read level index and node count
        size_t levelIdx;
        uint64_t nodeCount;
        std::memcpy(&levelIdx, data.data() + offset, 8);
        std::memcpy(&nodeCount, data.data() + offset + 8, 8);
        offset += 16;
        
        // Read each node in this level
        for (uint64_t j = 0; j < nodeCount && offset + 40 <= data.size(); ++j) {
            size_t position;
            uint256 hash;
            std::memcpy(&position, data.data() + offset, 8);
            std::memcpy(hash.begin(), data.data() + offset + 8, 32);
            offset += 40;
            
            if (levelIdx < tree.cached_nodes_.size()) {
                tree.cached_nodes_[levelIdx][position] = hash;
            }
        }
    }
    
    return tree;
}

std::vector<size_t> IncrementalMerkleTree::appendBatch(const std::vector<uint256>& leaves) {
    std::vector<size_t> positions;
    positions.reserve(leaves.size());
    
    for (const auto& leaf : leaves) {
        try {
            size_t pos = append(leaf);
            positions.push_back(pos);
        } catch (const std::overflow_error& e) {
            std::cout << "Tree full during batch append at position " << positions.size() << std::endl;
            break;
        }
    }
    
    std::cout << "Batch append completed: " << positions.size() << " leaves added" << std::endl;
    return positions;
}

void IncrementalMerkleTree::precomputeNodes(size_t upToPosition) {
    if (upToPosition > next_position_) {
        upToPosition = next_position_;
    }
    
    std::cout << "Precomputing nodes up to position " << upToPosition << std::endl;
    
    // Compute all internal nodes for positions 0 to upToPosition-1
    for (size_t level = 0; level < depth_; ++level) {
        size_t nodesAtLevel = (upToPosition + (1ULL << level) - 1) >> level;
        
        for (size_t pos = 0; pos < nodesAtLevel; pos += 2) {
            size_t parent_pos = pos >> 1;
            
            // Skip if parent already computed
            if (level + 1 < cached_nodes_.size() && 
                cached_nodes_[level + 1].find(parent_pos) != cached_nodes_[level + 1].end()) {
                continue;
            }
            
            // Get left and right children
            uint256 left = getNode(level, pos);
            uint256 right = getNode(level, pos + 1);
            
            // Compute and store parent
            uint256 parent = hash(left, right);
            setNode(level + 1, parent_pos, parent);
        }
    }
    
    std::cout << "Precomputation completed" << std::endl;
}

bool MerkleWitness::verify() const {
    uint256 current = leaf;
    size_t current_pos = position;
    
    for (size_t level = 0; level < auth_path.size(); ++level) {
        uint256 sibling = auth_path[level];
        
        if (current_pos & 1) {
            // Current is right child, sibling is left
            std::vector<uint8_t> input(64);
            std::memcpy(&input[0], sibling.begin(), 32);
            std::memcpy(&input[32], current.begin(), 32);
            SHA256(input.data(), input.size(), current.begin());
        } else {
            // Current is left child, sibling is right
            std::vector<uint8_t> input(64);
            std::memcpy(&input[0], current.begin(), 32);
            std::memcpy(&input[32], sibling.begin(), 32);
            SHA256(input.data(), input.size(), current.begin());
        }
        
        current_pos >>= 1;
    }
    
    return current == root;
}

std::vector<uint8_t> MerkleWitness::serialize() const {
    std::vector<uint8_t> data;
    
    // Write leaf (32 bytes)
    data.resize(32);
    std::memcpy(data.data(), leaf.begin(), 32);
    
    // Write position (8 bytes)
    size_t offset = data.size();
    data.resize(offset + 8);
    std::memcpy(data.data() + offset, &position, 8);
    
    // Write root (32 bytes)
    offset = data.size();
    data.resize(offset + 32);
    std::memcpy(data.data() + offset, root.begin(), 32);
    
    // Write auth path length (8 bytes)
    offset = data.size();
    data.resize(offset + 8);
    uint64_t pathLen = auth_path.size();
    std::memcpy(data.data() + offset, &pathLen, 8);
    
    // Write auth path (32 * pathLen bytes)
    offset = data.size();
    data.resize(offset + 32 * pathLen);
    for (size_t i = 0; i < auth_path.size(); ++i) {
        std::memcpy(data.data() + offset + i * 32, auth_path[i].begin(), 32);
    }
    
    return data;
}

MerkleWitness MerkleWitness::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 80) { // 32 + 8 + 32 + 8 minimum
        throw std::invalid_argument("Invalid witness data size");
    }
    
    MerkleWitness witness;
    
    // Read leaf
    std::memcpy(witness.leaf.begin(), data.data(), 32);
    
    // Read position
    std::memcpy(&witness.position, data.data() + 32, 8);
    
    // Read root
    std::memcpy(witness.root.begin(), data.data() + 40, 32);
    
    // Read auth path length
    uint64_t pathLen;
    std::memcpy(&pathLen, data.data() + 72, 8);
    
    if (data.size() < 80 + 32 * pathLen) {
        throw std::invalid_argument("Invalid witness data size for auth path");
    }
    
    // Read auth path
    witness.auth_path.resize(pathLen);
    for (size_t i = 0; i < pathLen; ++i) {
        std::memcpy(witness.auth_path[i].begin(), data.data() + 80 + i * 32, 32);
    }
    
    return witness;
}

} // namespace zkp
} // namespace ripple
