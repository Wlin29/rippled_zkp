#include "ShieldedMerkleTree.h"
#include <xrpl/protocol/digest.h>

namespace ripple {

ShieldedMerkleTree::ShieldedMerkleTree()
{
    // Initialize tree vector: TREE_DEPTH + 1 levels.
    tree.resize(TREE_DEPTH + 1);

    // Create a zero commitment as the first leaf.
    uint256 zeroCommitment;
    // zeroCommitment may be left default-initialized.
    addCommitment(zeroCommitment);
}

uint256 ShieldedMerkleTree::hashChildren(const uint256& left, const uint256& right)
{
    // Compute SHA512-Half hash
    sha512_half_hasher h;
    h(left.data(), left.size());
    h(right.data(), right.size());
    
    uint256 result;
    h(result.data(), result.size());
    return result;
}

void ShieldedMerkleTree::updatePath(size_t leafIndex)
{
    size_t idx = leafIndex;

    for (int level = TREE_DEPTH; level > 0; --level)
    {
        size_t parentIndex = idx / 2;
        size_t siblingIndex = idx ^ 1; // XOR with 1 gives sibling

        if (parentIndex >= tree[level - 1].size())
            tree[level - 1].resize(parentIndex + 1);

        uint256 siblingValue;
        if (siblingIndex < tree[level].size())
            siblingValue = tree[level][siblingIndex];

        if (idx % 2 == 0)
            tree[level - 1][parentIndex] = hashChildren(tree[level][idx], siblingValue);
        else
            tree[level - 1][parentIndex] = hashChildren(siblingValue, tree[level][idx]);

        idx = parentIndex;
    }
}

size_t ShieldedMerkleTree::addCommitment(const uint256& commitment)
{
    size_t index = commitments.size();
    commitments.push_back(commitment);

    if (index >= tree[TREE_DEPTH].size())
        tree[TREE_DEPTH].resize(index + 1);
    tree[TREE_DEPTH][index] = commitment;

    updatePath(index);

    uint256 newRoot = getRoot();
    rootHistory.push_back(newRoot);

    if (rootHistory.size() > 100)
        rootHistory.erase(rootHistory.begin());

    return index;
}

bool ShieldedMerkleTree::isNullifierSpent(const uint256& nullifier) const
{
    return nullifiers.find(nullifier) != nullifiers.end();
}

void ShieldedMerkleTree::markNullifierSpent(const uint256& nullifier)
{
    nullifiers.insert(nullifier);
}

uint256 ShieldedMerkleTree::getRoot() const
{
    if (!tree[0].empty())
        return tree[0][0];
    return uint256();
}

bool ShieldedMerkleTree::isValidRoot(const uint256& root) const
{
    for (const auto& historicalRoot : rootHistory)
    {
        if (historicalRoot == root)
            return true;
    }
    return false;
}

std::vector<uint256> ShieldedMerkleTree::getAuthPath(size_t leafIndex) const
{
    std::vector<uint256> path;
    path.reserve(TREE_DEPTH);
    
    size_t idx = leafIndex;
    for (size_t level = TREE_DEPTH; level > 0; --level)
    {
        size_t siblingIndex = idx ^ 1;
        if (siblingIndex < tree[level].size())
        {
            path.push_back(tree[level][siblingIndex]);
        }
        else
        {
            path.push_back(uint256());
        }
        idx /= 2;
    }
    
    return path;
}

void ShieldedMerkleTree::serialize(Serializer& s) const
{
    s.add32(static_cast<uint32_t>(commitments.size()));
    for (const auto& commitment : commitments)
    {
        s.addBitString(commitment);
    }
    
    s.add32(static_cast<uint32_t>(nullifiers.size()));
    for (const auto& nullifier : nullifiers)
    {
        s.addBitString(nullifier);
    }
    
    s.add32(static_cast<uint32_t>(rootHistory.size()));
    for (const auto& root : rootHistory)
    {
        s.addBitString(root);
    }
}

ShieldedMerkleTree ShieldedMerkleTree::deserialize(SerialIter& sit)
{
    ShieldedMerkleTree treeObj;
    
    uint32_t commitmentCount = sit.get32();
    treeObj.commitments.clear();
    treeObj.commitments.reserve(commitmentCount);
    
    for (uint32_t i = 0; i < commitmentCount; ++i)
    {
        treeObj.commitments.push_back(sit.getBitString<256>());
    }
    
    uint32_t nullifierCount = sit.get32();
    treeObj.nullifiers.clear();
    for (uint32_t i = 0; i < nullifierCount; ++i)
    {
        treeObj.nullifiers.insert(sit.getBitString<256>());
    }
    
    uint32_t rootCount = sit.get32();
    treeObj.rootHistory.clear();
    treeObj.rootHistory.reserve(rootCount);
    
    for (uint32_t i = 0; i < rootCount; ++i)
    {
        treeObj.rootHistory.push_back(sit.getBitString<256>());
    }
    
    // Rebuild the binary tree.
    treeObj.tree.resize(TREE_DEPTH + 1);
    treeObj.tree[TREE_DEPTH].resize(treeObj.commitments.size());
    
    for (size_t i = 0; i < treeObj.commitments.size(); ++i)
    {
        treeObj.tree[TREE_DEPTH][i] = treeObj.commitments[i];
        treeObj.updatePath(i);
    }
    
    return treeObj;
}

} // namespace ripple