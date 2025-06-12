// #pragma once

// #include "IncrementalMerkleTree.h"
// #include <xrpl/basics/base_uint.h>
// #include <vector>

// namespace ripple {
// namespace zkp {

// /**
//  * Merkle Tree implementation
//  * Uses SHA256 for internal hash computations
//  */
// class MerkleTree {
// public:
//     explicit MerkleTree(size_t depth = 32) : tree_(depth) {}
    
//     // Legacy interface
//     size_t addLeaf(const uint256& leaf) {
//         return tree_.append(leaf);
//     }
    
//     uint256 getRoot() const {
//         return tree_.root();
//     }
    
//     std::vector<uint256> getAuthPath(size_t position) const {
//         return tree_.authPath(position);
//     }
    
//     static bool verifyPath(
//         const uint256& leaf,
//         const std::vector<uint256>& path,
//         size_t position,
//         const uint256& root) {
//         IncrementalMerkleTree temp(path.size());
//         return temp.verify(leaf, path, position, root);
//     }
    
//     size_t size() const { return tree_.size(); }
//     bool empty() const { return tree_.empty(); }
    
//     // New incremental features
//     std::vector<size_t> addLeavesParallel(const std::vector<uint256>& leaves) {
//         return tree_.appendBatch(leaves);
//     }
    
//     void optimize() {
//         tree_.precomputeNodes(tree_.size());
//     }
    
//     // Persistence
//     std::vector<uint8_t> serialize() const {
//         return tree_.serialize();
//     }
    
//     static MerkleTree deserialize(const std::vector<uint8_t>& data) {
//         MerkleTree wrapper(32);
//         wrapper.tree_ = IncrementalMerkleTree::deserialize(data);
//         return wrapper;
//     }

// private:
//     IncrementalMerkleTree tree_;
// };

// } // namespace zkp
// } // namespace ripple