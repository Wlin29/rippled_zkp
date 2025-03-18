// #include "ShieldedMerkleTree.h"
// #include <xrpl/crypto/Sha512.h>

// namespace ripple {

// ShieldedMerkleTree::ShieldedMerkleTree() {
//     // Initialize empty tree with specified depth
//     tree.resize(TREE_DEPTH + 1);
    
//     // Create a zero commitment as the first leaf
//     uint256 zeroCommitment;
//     addCommitment(zeroCommitment);
// }

// uint256 
// ShieldedMerkleTree::hashChildren(const uint256& left, const uint256& right) {
//     // SHA512-Half hash of two children
//     sha512_half_hasher h;
//     h(left.data(), left.size());
//     h(right.data(), right.size());
    
//     uint256 result;
//     h.finish(result.data());
//     return result;
// }

// void 
// ShieldedMerkleTree::updatePath(size_t leafIndex) {
//     // Update tree from the leaf to the root
//     size_t idx = leafIndex;
    
//     for (int level = TREE_DEPTH; level > 0; --level) {
//         size_t parentIndex = idx / 2;
//         size_t siblingIndex = idx ^ 1; // XOR with 1 gives the sibling
        
//         // Ensure the tree has enough space
//         if (parentIndex >= tree[level - 1].size()) {
//             tree[level - 1].resize(parentIndex + 1);
//         }
        
//         // Get the sibling, or use a zero hash if it doesn't exist
//         uint256 siblingValue;
//         if (siblingIndex < tree[level].size()) {
//             siblingValue = tree[level][siblingIndex];
//         }
        
//         // Hash the current node with its sibling
//         if (idx % 2 == 0) { // Left child
//             tree[level - 1][parentIndex] = hashChildren(tree[level][idx], siblingValue);
//         } else { // Right child
//             tree[level - 1][parentIndex] = hashChildren(siblingValue, tree[level][idx]);
//         }
        
//         // Move up to the parent
//         idx = parentIndex;
//     }
// }

// size_t 
// ShieldedMerkleTree::addCommitment(const uint256& commitment) {
//     // Add a new commitment as a leaf node
//     size_t index = commitments.size();
//     commitments.push_back(commitment);
    
//     // Make sure the tree is big enough
//     if (index >= tree[TREE_DEPTH].size()) {
//         tree[TREE_DEPTH].resize(index + 1);
//     }
//     tree[TREE_DEPTH][index] = commitment;
    
//     // Update the authentication path to the root
//     updatePath(index);
    
//     // Store the new root in history
//     uint256 newRoot = getRoot();
//     rootHistory.push_back(newRoot);
    
//     // Limit root history size (keep last 100 roots)
//     if (rootHistory.size() > 100) {
//         rootHistory.erase(rootHistory.begin());
//     }
    
//     return index;
// }

// bool 
// ShieldedMerkleTree::isNullifierSpent(const uint256& nullifier) const {
//     return nullifiers.find(nullifier) != nullifiers.end();
// }

// void 
// ShieldedMerkleTree::markNullifierSpent(const uint256& nullifier) {
//     nullifiers.insert(nullifier);
// }

// uint256 
// ShieldedMerkleTree::getRoot() const {
//     if (!tree[0].empty()) {
//         return tree[0][0];
//     }
//     return uint256();
// }

// bool 
// ShieldedMerkleTree::isValidRoot(const uint256& root) const {
//     for (const auto& historicalRoot : rootHistory) {
//         if (historicalRoot == root) {
//             return true;
//         }
//     }
//     return false;
// }

// std::vector<uint256> 
// ShieldedMerkleTree::getAuthPath(size_t leafIndex) const {
//     std::vector<uint256> path;
//     path.reserve(TREE_DEPTH);
    
//     size_t idx = leafIndex;
//     for (size_t level = TREE_DEPTH; level > 0; --level) {
//         size_t siblingIndex = idx ^ 1; // XOR with 1 gives sibling
        
//         if (siblingIndex < tree[level].size()) {
//             path.push_back(tree[level][siblingIndex]);
//         } else {
//             // If sibling doesn't exist, use a zero hash
//             path.push_back(uint256());
//         }
        
//         // Move up to parent
//         idx /= 2;
//     }
    
//     return path;
// }

// void 
// ShieldedMerkleTree::serialize(Serializer& s) const {
//     // Serialize commitment count
//     s.add32(static_cast<uint32_t>(commitments.size()));
    
//     // Serialize all commitments
//     for (const auto& commitment : commitments) {
//         s.addBitString(commitment);
//     }
    
//     // Serialize nullifiers
//     s.add32(static_cast<uint32_t>(nullifiers.size()));
//     for (const auto& nullifier : nullifiers) {
//         s.addBitString(nullifier);
//     }
    
//     // Serialize root history
//     s.add32(static_cast<uint32_t>(rootHistory.size()));
//     for (const auto& root : rootHistory) {
//         s.addBitString(root);
//     }
// }

// ShieldedMerkleTree 
// ShieldedMerkleTree::deserialize(SerialIter& sit) {
//     ShieldedMerkleTree tree;
    
//     // Deserialize commitments
//     uint32_t commitmentCount = sit.get32();
//     tree.commitments.clear();
//     tree.commitments.reserve(commitmentCount);
    
//     for (uint32_t i = 0; i < commitmentCount; ++i) {
//         tree.commitments.push_back(sit.getBitString<uint256>());
//     }
    
//     // Deserialize nullifiers
//     uint32_t nullifierCount = sit.get32();
//     tree.nullifiers.clear();
    
//     for (uint32_t i = 0; i < nullifierCount; ++i) {
//         tree.nullifiers.insert(sit.getBitString<uint256>());
//     }
    
//     // Deserialize root history
//     uint32_t rootCount = sit.get32();
//     tree.rootHistory.clear();
//     tree.rootHistory.reserve(rootCount);
    
//     for (uint32_t i = 0; i < rootCount; ++i) {
//         tree.rootHistory.push_back(sit.getBitString<uint256>());
//     }
    
//     // Rebuild the tree from leaves
//     tree.tree.resize(TREE_DEPTH + 1);
//     tree.tree[TREE_DEPTH].resize(tree.commitments.size());
    
//     for (size_t i = 0; i < tree.commitments.size(); ++i) {
//         tree.tree[TREE_DEPTH][i] = tree.commitments[i];
//         tree.updatePath(i);
//     }
    
//     return tree;
// }

// } // namespace ripple

/* do apply function for use with zkdeposit and zkwithdraw*/

// TER
// ZkDeposit::doApply()
// {
//     auto const account = ctx_.tx.getAccountID(sfAccount);
//     auto const amount = ctx_.tx.getFieldAmount(sfAmount);
//     uint256 commitment;
    
//     if (ctx_.tx.isFieldPresent(sfCommitment))
//         commitment = ctx_.tx.getFieldH256(sfCommitment);
    
//     // Get or create shielded pool
//     auto shieldedPool = getShieldedPool(true);
//     if (!shieldedPool)
//         return tecINTERNAL;
    
//     // Verify the ZK proof
//     if (!verifyProof())
//         return temBAD_PROOF;
    
//     // Deserialize the Merkle tree
//     SerialIter sit(
//         shieldedPool->getFieldVL(sfShieldedState).data(),
//         shieldedPool->getFieldVL(sfShieldedState).size());
//     auto tree = ShieldedMerkleTree::deserialize(sit);
    
//     // Add the commitment to the tree
//     size_t index = tree.addCommitment(commitment);
    
//     // Transfer funds to the pool (account -> null)
//     TER result = accountSend(ctx_.view(), account, xrpAccount(), amount);
//     if (result != tesSUCCESS)
//         return result;
    
//     // Serialize and save the updated tree
//     Serializer s;
//     tree.serialize(s);
//     shieldedPool->setFieldVL(sfShieldedState, s.getData());
    
//     // Update the root and pool size
//     shieldedPool->setFieldH256(sfCurrentRoot, tree.getRoot());
//     shieldedPool->setFieldU32(sfPoolSize, static_cast<std::uint32_t>(tree.getCommitments().size()));
    
//     ctx_.view().update(shieldedPool);
    
//     return tesSUCCESS;
// }