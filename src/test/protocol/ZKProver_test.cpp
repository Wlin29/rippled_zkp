#include <xrpl/beast/unit_test.h>
#include <xrpl/protocol/UintTypes.h>
#include <string>
#include <random>
#include <iostream>
#include <chrono>
#include <iomanip>

#include <libxrpl/zkp/ZKProver.h>
#include <libxrpl/zkp/circuits/MerkleCircuit.h>
#include <libxrpl/zkp/IncrementalMerkleTree.h>
#include <libxrpl/zkp/Note.h>

/*
NOTE: May need to remove old keys before running tests
      rm -rf /tmp/zkp_test_keys*
*/

namespace ripple {

class ZKProver_test : public beast::unit_test::suite
{
private:
    uint256 generateRandomUint256() {
        uint256 result;
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint32_t> dis;
        
        for (int i = 0; i < 8; ++i) {
            uint32_t randomValue = dis(gen);
            std::memcpy(result.begin() + i * 4, &randomValue, 4);
        }
        
        return result;
    }
    
    std::string generateRandomSpendKey() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dis(100000, 999999);
        return "spend_key_" + std::to_string(dis(gen));
    }

public:
    void run() override
    {
        zkp::ZkProver::initialize();
        
        testKeyGeneration();
        testKeyPersistence();
        testProofSerialization();
        testDepositProofCreation();
        testWithdrawalProofCreation();
        testDepositProofVerification();
        testWithdrawalProofVerification();
        testInvalidProofVerification();
        testMultipleProofs();
        testEdgeCases();
        testNoteCreationAndCommitment();
        testIncrementalMerkleTree();
        testMerkleVerificationEnforcement();
    }

    void testKeyGeneration()
    {
        testcase("Key Generation");
        
        // Test key generation without checking private members
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        // Test force regeneration
        BEAST_EXPECT(zkp::ZkProver::generateKeys(true));
    }
    
    void testKeyPersistence()
    {
        testcase("Key Persistence");
        
        // Generate keys
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        // Save keys
        std::string keyPath = "/tmp/test_zkp_keys";
        BEAST_EXPECT(zkp::ZkProver::saveKeys(keyPath));
        
        // Test loading keys
        BEAST_EXPECT(zkp::ZkProver::loadKeys(keyPath));
    }
    
    void testProofSerialization()
    {
        testcase("Proof Serialization");
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        uint64_t amount = 1000000;
        uint256 commitment = generateRandomUint256();
        std::string spendKey = generateRandomSpendKey();
        auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(spendKey);
        zkp::FieldT value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(amount);
        
        auto proofData = zkp::ZkProver::createDepositProof(amount, commitment, spendKey, value_randomness);
        BEAST_EXPECT(!proofData.empty());
        BEAST_EXPECT(!proofData.proof.empty());
        BEAST_EXPECT(proofData.proof.size() > 0);
    }

    void testDepositProofCreation()
    {
        testcase("Deposit Proof Creation");
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));

        for (size_t idx : {0, 1, 2}) {
            uint64_t amount = 1000000 + idx * 100000;
            std::string spendKey = generateRandomSpendKey();

            auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(spendKey);
            zkp::FieldT value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(amount);

            std::cout << "=== CREATING DEPOSIT PROOF " << idx << " ===" << std::endl;
            
            // CREATE NOTE
            auto recipient = zkp::AddressKeyPair::generate();
            auto note = zkp::Note::createRandom(amount, recipient.a_pk);
            
            // COMPUTE COMMITMENT
            uint256 commitment = note.computeCommitment();
            
            std::cout << "Created note with commitment: " << commitment << std::endl;

            auto proofData = zkp::ZkProver::createDepositProof(amount, commitment, spendKey, value_randomness);
            BEAST_EXPECT(!proofData.empty());
            
            // VERIFY THE PROOF
            bool isValid = zkp::ZkProver::verifyDepositProof(proofData);
            BEAST_EXPECT(isValid);
            
            std::cout << "Deposit proof " << idx << " verification: " << (isValid ? "PASS" : "FAIL") << std::endl;
        }
    }

    void testWithdrawalProofCreation()
    {
        testcase("Withdrawal Proof Creation");
        
        BEAST_EXPECT(zkp::ZkProver::generateKeys(true));

        // CHANGE: Use IncrementalMerkleTree instead of MerkleTree
        zkp::IncrementalMerkleTree tree(2); // depth 2 = 4 leaves max
        
        // Add some dummy notes to the tree
        uint256 dummyNote1 = generateRandomUint256();
        uint256 dummyNote2 = generateRandomUint256();
        
        // CHANGE: Use append() instead of addLeaf()
        size_t note1Index = tree.append(dummyNote1);
        size_t note2Index = tree.append(dummyNote2);
        (void)note1Index;  // Suppress unused warning
        (void)note2Index;  // Suppress unused warning
        
        uint64_t amount = 500000;
        // CHANGE: Use root() instead of getRoot()
        uint256 merkleRoot = tree.root();
        uint256 nullifier = generateRandomUint256();
        std::string spendKey = generateRandomSpendKey();
        auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(spendKey);
        zkp::FieldT value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(amount);

        // CHANGE: Use authPath() instead of getAuthPath()
        std::vector<uint256> merklePath = tree.authPath(0);

        auto proofData = zkp::ZkProver::createWithdrawalProof(
            amount, merkleRoot, nullifier, merklePath, 0, spendKey, value_randomness);
        
        BEAST_EXPECT(!proofData.empty());
    }

    void testDepositProofVerification()
    {
        testcase("Deposit Proof Verification");
        
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        uint64_t amount = 2000000;
        uint256 commitment = generateRandomUint256();
        std::string spendKey = generateRandomSpendKey();

        auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(spendKey);
        zkp::FieldT value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(amount);
        
        auto proofData = zkp::ZkProver::createDepositProof(amount, commitment, spendKey, value_randomness);
        BEAST_EXPECT(!proofData.empty());
        
        bool isValid = zkp::ZkProver::verifyDepositProof(proofData);
        BEAST_EXPECT(isValid);
        
        auto tampered = proofData;
        tampered.nullifier = tampered.nullifier + zkp::FieldT::one();
        bool tamperedValid = zkp::ZkProver::verifyDepositProof(tampered);
        BEAST_EXPECT(!tamperedValid);
        
        zkp::ProofData emptyProof;
        bool emptyValid = zkp::ZkProver::verifyDepositProof(emptyProof);
        BEAST_EXPECT(!emptyValid);
    }

    void testWithdrawalProofVerification()
    {
        testcase("Withdrawal Proof Verification");
        
        BEAST_EXPECT(zkp::ZkProver::generateKeys(true));
        
        // CHANGE: Use IncrementalMerkleTree
        zkp::IncrementalMerkleTree tree(3);
        
        uint256 testNote = generateRandomUint256();
        tree.append(testNote);
        
        uint64_t amount = 750000;
        uint256 merkleRoot = tree.root();
        uint256 nullifier = generateRandomUint256();
        std::string spendKey = generateRandomSpendKey();

        auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(spendKey);
        zkp::FieldT value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(amount);

        std::vector<uint256> merklePath = tree.authPath(0);

        auto proofData = zkp::ZkProver::createWithdrawalProof(
            amount, merkleRoot, nullifier, merklePath, 0, spendKey, value_randomness);
        
        if (!proofData.empty()) {
            bool isValid = zkp::ZkProver::verifyWithdrawalProof(proofData);
            BEAST_EXPECT(isValid);
            
            auto wrongRoot = proofData;
            wrongRoot.anchor = wrongRoot.anchor + zkp::FieldT::one();
            bool wrongRootValid = zkp::ZkProver::verifyWithdrawalProof(wrongRoot);
            BEAST_EXPECT(!wrongRootValid);
        }
    }

    void testInvalidProofVerification()
    {
        testcase("Invalid Proof Verification");
        
        std::vector<unsigned char> invalidProof(100, 0xFF);
        zkp::FieldT dummyField = zkp::FieldT::zero();
        
        bool satisfied = zkp::ZkProver::verifyDepositProof(invalidProof, dummyField, dummyField, dummyField);
        (void)satisfied;  // Suppress unused warning
        BEAST_EXPECT(!satisfied);
        
        std::vector<unsigned char> largeInvalidProof(10000, 0xAA);
        bool largeSatisfied = zkp::ZkProver::verifyDepositProof(largeInvalidProof, dummyField, dummyField, dummyField);
        BEAST_EXPECT(!largeSatisfied);
    }

    void testMultipleProofs()
    {
        testcase("Multiple Proofs");
        
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        std::vector<zkp::ProofData> proofs;
        
        for (int i = 0; i < 3; ++i) {
            uint64_t amount = 1000000 + i * 250000;
            uint256 commitment = generateRandomUint256();
            std::string spendKey = generateRandomSpendKey();
            auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(spendKey);
            zkp::FieldT value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(amount);
            
            auto proof = zkp::ZkProver::createDepositProof(amount, commitment, spendKey, value_randomness);
            proofs.push_back(proof);
        }
        
        for (const auto& proof : proofs) {
            BEAST_EXPECT(!proof.empty());
            bool isValid = zkp::ZkProver::verifyDepositProof(proof);
            BEAST_EXPECT(isValid);
        }
        
        for (size_t i = 0; i < proofs.size(); ++i) {
            for (size_t j = 0; j < proofs.size(); ++j) {
                if (i != j) {
                    bool crossValid = zkp::ZkProver::verifyDepositProof(
                        proofs[i].proof, proofs[j].anchor, proofs[j].nullifier, proofs[j].value_commitment);
                    BEAST_EXPECT(!crossValid);
                }
            }
        }
    }

    void testEdgeCases()
    {
        testcase("Edge Cases");
        
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        uint64_t zeroAmount = 0;
        uint256 commitment = generateRandomUint256();
        std::string spendKey = generateRandomSpendKey();
        auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(spendKey);
        zkp::FieldT zero_value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(zeroAmount);
        
        auto zeroProof = zkp::ZkProver::createDepositProof(zeroAmount, commitment, spendKey, zero_value_randomness);
        bool zeroValid = zkp::ZkProver::verifyDepositProof(zeroProof);
        BEAST_EXPECT(zeroValid);
        
        uint64_t largeAmount = (1ULL << 50);
        zkp::FieldT large_value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(12345);
        
        auto largeProof = zkp::ZkProver::createDepositProof(largeAmount, commitment, spendKey, large_value_randomness);
        bool largeValid = zkp::ZkProver::verifyDepositProof(largeProof);
        BEAST_EXPECT(largeValid);
        
        std::cout << "Edge cases test: zero=" << zeroValid << ", large=" << largeValid << std::endl;
    }
    
    void testNoteCreationAndCommitment() {
        testcase("Note Creation and Commitment");
        
        // Generate address key pair
        auto recipient = zkp::AddressKeyPair::generate();
        
        // Create a note
        uint64_t amount = 1000000;
        auto note = zkp::Note::createRandom(amount, recipient.a_pk);
        
        // Verify note is valid
        BEAST_EXPECT(note.isValid());
        
        // Compute commitment
        auto commitment = note.computeCommitment();
        BEAST_EXPECT(commitment != uint256{});
        
        // Compute nullifier
        uint256 a_sk_uint256 = zkp::MerkleCircuit::bitsToUint256(recipient.a_sk);
        auto nullifier = note.computeNullifier(a_sk_uint256);
        BEAST_EXPECT(nullifier != uint256{});
        
        // Test serialization
        auto serialized = note.serialize();
        auto deserialized = zkp::Note::deserialize(serialized);
        
        BEAST_EXPECT(deserialized.value == note.value);
        BEAST_EXPECT(deserialized.rho == note.rho);
        BEAST_EXPECT(deserialized.r == note.r);
        BEAST_EXPECT(deserialized.a_pk == note.a_pk);
    }

    void testIncrementalMerkleTree() {
        testcase("Incremental Merkle Tree");
        
        zkp::IncrementalMerkleTree tree(4); // Small tree for testing
        
        // Test empty tree
        BEAST_EXPECT(tree.empty());
        BEAST_EXPECT(tree.size() == 0);
        
        // Add some leaves
        uint256 leaf1 = generateRandomUint256();
        uint256 leaf2 = generateRandomUint256();
        uint256 leaf3 = generateRandomUint256();
        
        size_t pos1 = tree.append(leaf1);
        size_t pos2 = tree.append(leaf2);
        size_t pos3 = tree.append(leaf3);
        
        BEAST_EXPECT(pos1 == 0);
        BEAST_EXPECT(pos2 == 1);
        BEAST_EXPECT(pos3 == 2);
        BEAST_EXPECT(tree.size() == 3);
        BEAST_EXPECT(!tree.empty());
        
        // Test authentication paths
        auto path1 = tree.authPath(pos1);
        auto path2 = tree.authPath(pos2);
        auto path3 = tree.authPath(pos3);
        
        BEAST_EXPECT(path1.size() == 4);
        BEAST_EXPECT(path2.size() == 4);
        BEAST_EXPECT(path3.size() == 4);
        
        // Verify paths
        uint256 root = tree.root();
        BEAST_EXPECT(tree.verify(leaf1, path1, pos1, root));
        BEAST_EXPECT(tree.verify(leaf2, path2, pos2, root));
        BEAST_EXPECT(tree.verify(leaf3, path3, pos3, root));
        
        // Test batch operations
        std::vector<uint256> batch_leaves = {
            generateRandomUint256(),
            generateRandomUint256(),
            generateRandomUint256()
        };
        
        auto positions = tree.appendBatch(batch_leaves);
        BEAST_EXPECT(positions.size() == 3);
        BEAST_EXPECT(tree.size() == 6);
        
        // Verify batch leaves
        uint256 new_root = tree.root();
        for (size_t i = 0; i < batch_leaves.size(); ++i) {
            auto path = tree.authPath(positions[i]);
            BEAST_EXPECT(tree.verify(batch_leaves[i], path, positions[i], new_root));
        }
        
        std::cout << "Incremental tree test: final size=" << tree.size() 
                  << ", root=" << new_root << std::endl;
    }

    void testMerkleVerificationEnforcement() {
        testcase("Merkle Verification Enforcement");
        
        BEAST_EXPECT(zkp::ZkProver::generateKeys(true));
        
        // Create a valid tree with a real note
        zkp::IncrementalMerkleTree tree(4);
        uint256 realLeaf = generateRandomUint256();
        size_t position = tree.append(realLeaf);
        
        uint256 validRoot = tree.root();
        std::vector<uint256> validPath = tree.authPath(position);
        
        // Test 1: Valid withdrawal should work
        uint64_t amount = 1000000;
        uint256 nullifier = generateRandomUint256();
        std::string spendKey = generateRandomSpendKey();
        auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(spendKey);
        zkp::FieldT value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits);
        
        auto validProof = zkp::ZkProver::createWithdrawalProof(
            amount, validRoot, nullifier, validPath, position, spendKey, value_randomness);
        
        bool validResult = zkp::ZkProver::verifyWithdrawalProof(validProof);
        BEAST_EXPECT(validResult);
        
        // Test 2: Invalid path should FAIL (but might not due to bug)
        std::vector<uint256> invalidPath(validPath.size());
        for (auto& node : invalidPath) {
            node = generateRandomUint256(); // Random garbage
        }
        
        auto invalidProof = zkp::ZkProver::createWithdrawalProof(
            amount, validRoot, nullifier, invalidPath, position, spendKey, value_randomness);
        
        bool invalidResult = zkp::ZkProver::verifyWithdrawalProof(invalidProof);
        
        // This SHOULD fail, but might pass if Merkle verification is broken
        if (invalidResult) {
            std::cout << "CRITICAL BUG: Invalid Merkle path accepted!" << std::endl;
            BEAST_EXPECT(false); // This should not happen
        } else {
            std::cout << "Good: Invalid Merkle path properly rejected" << std::endl;
        }
    }
};

BEAST_DEFINE_TESTSUITE(ZKProver, protocol, ripple);

}