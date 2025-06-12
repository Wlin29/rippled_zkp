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
    std::vector<uint8_t> input;
    input.insert(input.end(), left.begin(), left.end());
    input.insert(input.end(), right.begin(), right.end());
    
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
    // Update frontier nodes efficiently using bit operations
    uint256 current = getNode(0, position);
    
    for (size_t level = 0; level < depth_; ++level) {
        frontier_[level] = current;
        
        // Check if we need to combine with the left sibling
        if ((position >> level) & 1) {
            // Position is odd, combine with left sibling
            size_t left_pos = position ^ (1ULL << level);
            uint256 left = getNode(level, left_pos);
            current = hash(left, current);
        } else {
            // Position is even, we're done for now
            break;
        }
        
        // Set the parent node
        setNode(level + 1, position >> (level + 1), current);
    }
    
    // Update root
    frontier_[depth_] = computeRoot(next_position_);
}

uint256 IncrementalMerkleTree::root() const {
    if (next_position_ == 0) {
        return empty_hashes_[depth_];
    }
    return computeRoot(next_position_);
}

uint256 IncrementalMerkleTree::computeRoot(size_t upToPosition) const {
    if (upToPosition == 0) {
        return empty_hashes_[depth_];
    }
    
    // Build the tree bottom-up by processing all positions
    std::vector<std::vector<uint256>> tree_levels(depth_ + 1);
    
    // Level 0: Add all leaves
    for (size_t pos = 0; pos < upToPosition; ++pos) {
        tree_levels[0].push_back(getNode(0, pos));
    }
    
    // Pad with empty hashes to next power of 2
    size_t level_size = upToPosition;
    while (level_size & (level_size - 1)) { // Not power of 2
        tree_levels[0].push_back(empty_hashes_[0]);
        level_size++;
    }
    
    // Build each level
    for (size_t level = 0; level < depth_; ++level) {
        size_t current_size = tree_levels[level].size();
        if (current_size == 0) {
            tree_levels[level + 1].push_back(empty_hashes_[level + 1]);
            continue;
        }
        
        // Pair up nodes and hash them
        for (size_t i = 0; i < current_size; i += 2) {
            uint256 left = tree_levels[level][i];
            uint256 right = (i + 1 < current_size) ? 
                tree_levels[level][i + 1] : empty_hashes_[level];
            
            tree_levels[level + 1].push_back(hash(left, right));
        }
        
        // If we have only one node at the top level, that's our root
        if (tree_levels[level + 1].size() == 1) {
            return tree_levels[level + 1][0];
        }
    }
    
    return tree_levels[depth_][0];
}

std::vector<uint256> IncrementalMerkleTree::authPath(size_t position) const {
    if (position >= next_position_) {
        throw std::out_of_range("Position not in tree");
    }
    
    std::vector<uint256> path;
    path.reserve(depth_);
    
    for (size_t level = 0; level < depth_; ++level) {
        size_t sibling_pos = position ^ (1ULL << level);
        
        uint256 sibling;
        if (sibling_pos < next_position_) {
            sibling = getNode(level, sibling_pos);
        } else {
            sibling = empty_hashes_[level];
        }
        
        path.push_back(sibling);
        position >>= 1;
    }
    
    return path;
}

bool IncrementalMerkleTree::verify(
    const uint256& leaf, 
    const std::vector<uint256>& path, 
    size_t position, 
    const uint256& expectedRoot) const {
    
    if (path.size() != depth_) {
        return false;
    }
    
    uint256 current = leaf;
    
    for (size_t level = 0; level < depth_; ++level) {
        if ((position >> level) & 1) {
            // Right child
            current = hash(path[level], current);
        } else {
            // Left child
            current = hash(current, path[level]);
        }
    }
    
    return current == expectedRoot;
}

uint256 IncrementalMerkleTree::getNode(size_t level, size_t position) const {
    auto it = cached_nodes_[level].find(position);
    if (it != cached_nodes_[level].end()) {
        return it->second;
    }
    return empty_hashes_[level];
}

void IncrementalMerkleTree::setNode(size_t level, size_t position, const uint256& value) {
    cached_nodes_[level][position] = value;
}

std::vector<size_t> IncrementalMerkleTree::appendBatch(const std::vector<uint256>& leaves) {
    std::vector<size_t> positions;
    positions.reserve(leaves.size());
    
    for (const auto& leaf : leaves) {
        positions.push_back(append(leaf));
    }
    
    return positions;
}

void IncrementalMerkleTree::precomputeNodes(size_t upToPosition) {
    // Precompute commonly accessed nodes for better performance
    for (size_t pos = 0; pos < upToPosition; ++pos) {
        for (size_t level = 0; level < depth_; ++level) {
            size_t parent_pos = pos >> (level + 1);
            if (cached_nodes_[level + 1].find(parent_pos) == cached_nodes_[level + 1].end()) {
                // Compute parent if not cached
                size_t left_child = parent_pos << 1;
                size_t right_child = left_child + 1;
                
                uint256 left = getNode(level, left_child);
                uint256 right = getNode(level, right_child);
                
                setNode(level + 1, parent_pos, hash(left, right));
            }
        }
    }
}

std::vector<uint8_t> IncrementalMerkleTree::serialize() const {
    std::vector<uint8_t> data;
    
    // Write header
    data.resize(16);
    std::memcpy(data.data(), &depth_, 8);
    std::memcpy(data.data() + 8, &next_position_, 8);
    
    // Write cached nodes
    for (size_t level = 0; level <= depth_; ++level) {
        uint64_t count = cached_nodes_[level].size();
        
        size_t offset = data.size();
        data.resize(offset + 8);
        std::memcpy(data.data() + offset, &count, 8);
        
        for (const auto& [pos, hash] : cached_nodes_[level]) {
            offset = data.size();
            data.resize(offset + 8 + 32);
            std::memcpy(data.data() + offset, &pos, 8);
            std::memcpy(data.data() + offset + 8, hash.begin(), 32);
        }
    }
    
    return data;
}

IncrementalMerkleTree IncrementalMerkleTree::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 16) {
        throw std::invalid_argument("Invalid serialized data");
    }
    
    size_t depth, next_pos;
    std::memcpy(&depth, data.data(), 8);
    std::memcpy(&next_pos, data.data() + 8, 8);
    
    IncrementalMerkleTree tree(depth);
    tree.next_position_ = next_pos;
    
    size_t offset = 16;
    
    for (size_t level = 0; level <= depth; ++level) {
        if (offset + 8 > data.size()) break;
        
        uint64_t count;
        std::memcpy(&count, data.data() + offset, 8);
        offset += 8;
        
        for (uint64_t i = 0; i < count; ++i) {
            if (offset + 40 > data.size()) break;
            
            size_t pos;
            uint256 hash;
            std::memcpy(&pos, data.data() + offset, 8);
            std::memcpy(hash.begin(), data.data() + offset + 8, 32);
            
            tree.cached_nodes_[level][pos] = hash;
            offset += 40;
        }
    }
    
    return tree;
}

// MerkleWitness implementation
bool MerkleWitness::verify() const {
    uint256 current = leaf;
    
    for (size_t level = 0; level < auth_path.size(); ++level) {
        if ((position >> level) & 1) {
            // Right child
            std::vector<uint8_t> input;
            input.insert(input.end(), auth_path[level].begin(), auth_path[level].end());
            input.insert(input.end(), current.begin(), current.end());
            SHA256(input.data(), input.size(), current.begin());
        } else {
            // Left child
            std::vector<uint8_t> input;
            input.insert(input.end(), current.begin(), current.end());
            input.insert(input.end(), auth_path[level].begin(), auth_path[level].end());
            SHA256(input.data(), input.size(), current.begin());
        }
    }
    
    return current == root;
}

std::vector<uint8_t> MerkleWitness::serialize() const {
    std::vector<uint8_t> data;
    
    // Serialize leaf (32 bytes)
    data.insert(data.end(), leaf.begin(), leaf.end());
    
    // Serialize auth_path size (8 bytes)
    uint64_t path_size = auth_path.size();
    data.resize(data.size() + 8);
    std::memcpy(data.data() + data.size() - 8, &path_size, 8);
    
    // Serialize auth_path (32 bytes per element)
    for (const auto& node : auth_path) {
        data.insert(data.end(), node.begin(), node.end());
    }
    
    // Serialize position (8 bytes)
    data.resize(data.size() + 8);
    std::memcpy(data.data() + data.size() - 8, &position, 8);
    
    // Serialize root (32 bytes)
    data.insert(data.end(), root.begin(), root.end());
    
    return data;
}

MerkleWitness MerkleWitness::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 32 + 8 + 8 + 32) {
        throw std::invalid_argument("Insufficient data for MerkleWitness");
    }
    
    MerkleWitness witness;
    size_t offset = 0;
    
    // Deserialize leaf
    std::memcpy(witness.leaf.begin(), data.data() + offset, 32);
    offset += 32;
    
    // Deserialize auth_path size
    uint64_t path_size;
    std::memcpy(&path_size, data.data() + offset, 8);
    offset += 8;
    
    // Deserialize auth_path
    witness.auth_path.resize(path_size);
    for (uint64_t i = 0; i < path_size; ++i) {
        if (offset + 32 > data.size()) {
            throw std::invalid_argument("Invalid auth_path data");
        }
        std::memcpy(witness.auth_path[i].begin(), data.data() + offset, 32);
        offset += 32;
    }
    
    // Deserialize position
    std::memcpy(&witness.position, data.data() + offset, 8);
    offset += 8;
    
    // Deserialize root
    std::memcpy(witness.root.begin(), data.data() + offset, 32);
    
    return witness;
}

void IncrementalMerkleTree::clear() {
    next_position_ = 0;
    
    // Clear all cached nodes
    for (auto& level : cached_nodes_) {
        level.clear();
    }
    
    // Reset frontier
    std::fill(frontier_.begin(), frontier_.end(), uint256{});
}

} // namespace zkp
} // namespace ripple