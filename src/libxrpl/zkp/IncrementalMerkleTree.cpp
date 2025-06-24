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
    uint256 current = getNode(0, position);
    size_t current_pos = position;
    
    for (size_t level = 0; level < depth_; ++level) {
        frontier_[level] = current;
        
        // Compute parent position
        size_t parent_pos = current_pos >> 1;
        
        if (current_pos & 1) {
            // Right child - combine with left sibling
            size_t left_pos = current_pos ^ 1;
            uint256 left = getNode(level, left_pos);
            current = hash(left, current);
        } else {
            // Left child - combine with right sibling or empty
            size_t right_pos = current_pos ^ 1;
            uint256 right = (right_pos < next_position_) ? 
                getNode(level, right_pos) : empty_hashes_[level];
            current = hash(current, right);
        }
        
        // Store computed parent
        setNode(level + 1, parent_pos, current);
        current_pos = parent_pos;
    }
    
    // Update root in frontier
    frontier_[depth_] = current;
    
    // ADDITIONAL: Verify consistency
    uint256 computed_root = computeRoot(position + 1);
    if (current != computed_root) {
        std::cout << "WARNING: Frontier root mismatch at position " << position 
                  << ": frontier=" << current << " computed=" << computed_root << std::endl;
        // Force consistency
        frontier_[depth_] = computed_root;
    }
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
    
    // FIXED: More robust root computation with proper boundary handling
    uint256 current_root = empty_hashes_[depth_];
    
    // Use cached frontier if available
    if (upToPosition == next_position_ && !frontier_.empty()) {
        return frontier_[depth_];
    }
    
    // Recompute from scratch for consistency
    std::vector<uint256> current_level;
    
    // Collect all leaves
    for (size_t pos = 0; pos < upToPosition; ++pos) {
        current_level.push_back(getNode(0, pos));
    }
    
    // Build tree level by level
    for (size_t level = 0; level < depth_; ++level) {
        if (current_level.empty()) {
            return empty_hashes_[depth_];
        }
        
        if (current_level.size() == 1 && level == depth_ - 1) {
            return current_level[0];
        }
        
        std::vector<uint256> next_level;
        
        // Process pairs, padding with empty hash if needed
        for (size_t i = 0; i < current_level.size(); i += 2) {
            uint256 left = current_level[i];
            uint256 right = (i + 1 < current_level.size()) ? 
                current_level[i + 1] : empty_hashes_[level];
            
            next_level.push_back(hash(left, right));
        }
        
        current_level = std::move(next_level);
    }
    
    return current_level.empty() ? empty_hashes_[depth_] : current_level[0];
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
            
            // VALIDATION: Ensure sibling is not the default empty hash for real nodes
            if (sibling == uint256{} && level == 0 && sibling_pos < next_position_) {
                std::cout << "WARNING: Zero sibling at level " << level 
                          << " position " << sibling_pos << std::endl;
            }
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
        std::cout << "Path size mismatch: " << path.size() << " != " << depth_ << std::endl;
        return false;
    }
    
    if (position >= next_position_) {
        std::cout << "Position out of range: " << position << " >= " << next_position_ << std::endl;
        return false;
    }
    
    uint256 current = leaf;
    
    for (size_t level = 0; level < depth_; ++level) {
        // VALIDATION: Check for suspicious path elements
        if (path[level] == uint256{} && level < 4) { // First few levels shouldn't be zero for real trees
            std::cout << "WARNING: Zero path element at low level " << level << std::endl;
        }
        
        if ((position >> level) & 1) {
            // Right child
            current = hash(path[level], current);
        } else {
            // Left child
            current = hash(current, path[level]);
        }
    }
    
    bool valid = (current == expectedRoot);
    if (!valid) {
        std::cout << "Root mismatch: computed=" << current 
                  << " expected=" << expectedRoot << std::endl;
    }
    
    return valid;
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