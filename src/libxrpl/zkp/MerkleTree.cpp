// #include "MerkleTree.h"
// #include <openssl/sha.h>
// #include <cstring>
// #include <stdexcept>

// namespace ripple {
// namespace zkp {

// MerkleTree::MerkleTree(size_t depth) : depth_(depth) {
//     if (depth == 0 || depth > 32) {
//         throw std::invalid_argument("Tree depth must be between 1 and 32");
//     }
    
//     // Initialize tree levels
//     tree_.resize(depth_ + 1);
//     for (size_t level = 0; level <= depth_; ++level) {
//         tree_[level].resize(1 << (depth_ - level), uint256{}); // 2^(depth-level) nodes
//     }
// }

// size_t MerkleTree::addLeaf(const uint256& leaf) {
//     size_t index = leaves_.size();
//     leaves_.push_back(leaf);
    
//     // Update tree
//     tree_[0][index] = leaf;
//     updatePath(index);
    
//     return index;
// }

// std::vector<uint256> MerkleTree::getAuthPath(size_t leafIndex) const {
//     if (leafIndex >= leaves_.size()) {
//         throw std::out_of_range("Leaf index out of range");
//     }
    
//     std::vector<uint256> path;
//     size_t index = leafIndex;
    
//     for (size_t level = 0; level < depth_; ++level) {
//         // Get sibling
//         size_t siblingIndex = index ^ 1; // Flip last bit
//         if (siblingIndex < tree_[level].size()) {
//             path.push_back(tree_[level][siblingIndex]);
//         } else {
//             path.push_back(uint256{}); // Zero for missing siblings
//         }
//         index >>= 1; // Move to parent
//     }
    
//     return path;
// }

// uint256 MerkleTree::getRoot() const {
//     return tree_[depth_][0];
// }

// void MerkleTree::updatePath(size_t leafIndex) {
//     size_t index = leafIndex;
    
//     for (size_t level = 0; level < depth_; ++level) {
//         size_t parentIndex = index >> 1;
//         size_t leftIndex = parentIndex << 1;
//         size_t rightIndex = leftIndex + 1;
        
//         uint256 left = (leftIndex < tree_[level].size()) ? tree_[level][leftIndex] : uint256{};
//         uint256 right = (rightIndex < tree_[level].size()) ? tree_[level][rightIndex] : uint256{};
        
//         tree_[level + 1][parentIndex] = sha256_compress(left, right);
//         index = parentIndex;
//     }
// }

// uint256 MerkleTree::sha256_compress(const uint256& left, const uint256& right) {
//     // Concatenate left and right
//     std::array<uint8_t, 64> input;
//     std::memcpy(input.data(), left.begin(), 32);
//     std::memcpy(input.data() + 32, right.begin(), 32);
    
//     // Compute SHA256
//     std::array<uint8_t, 32> result;
//     SHA256(input.data(), 64, result.data());
    
//     // Convert to uint256
//     uint256 hash;
//     std::memcpy(hash.begin(), result.data(), 32);
//     return hash;
// }

// bool MerkleTree::verifyPath(
//     const uint256& leaf,
//     const std::vector<uint256>& path,
//     size_t index,
//     const uint256& root) {
    
//     uint256 current = leaf;
    
//     for (size_t level = 0; level < path.size(); ++level) {
//         if (index & 1) {
//             // Current is right child
//             current = sha256_compress(path[level], current);
//         } else {
//             // Current is left child
//             current = sha256_compress(current, path[level]);
//         }
//         index >>= 1;
//     }
    
//     return current == root;
// }

// } // namespace zkp
// } // namespace ripple