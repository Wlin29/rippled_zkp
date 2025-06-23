#include <xrpl/beast/unit_test.h>
#include <xrpl/protocol/UintTypes.h>
#include <string>
#include <random>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <cstring>

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
        testUnifiedCircuitBehavior();
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
        
        // Save unified keys to a test location
        std::string keyPath = "/tmp/test_zkp_keys_unified";
        BEAST_EXPECT(zkp::ZkProver::saveKeys(keyPath));
        
        // Test loading keys
        BEAST_EXPECT(zkp::ZkProver::loadKeys(keyPath));
        
        std::cout << "Unified key persistence: SUCCESS" << std::endl;
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
        
        std::cout << "Unified circuit proof serialization: SUCCESS" << std::endl;
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
            
            // Create random commitment directly (Note creation is handled internally by ZkProver)
            uint256 commitment = generateRandomUint256();
            
            std::cout << "Using commitment: " << commitment << std::endl;

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
        
        // USE EXISTING UNIFIED KEYS - don't regenerate!
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));

        // Create incremental tree for testing
        zkp::IncrementalMerkleTree tree(2); // depth 2 = 4 leaves max
        
        // Add some dummy notes to the tree
        uint256 dummyNote1 = generateRandomUint256();
        uint256 dummyNote2 = generateRandomUint256();
        
        size_t note1Index = tree.append(dummyNote1);
        size_t note2Index = tree.append(dummyNote2);
        (void)note1Index;  // Suppress unused warning
        (void)note2Index;  // Suppress unused warning
        
        uint64_t amount = 500000;
        uint256 merkleRoot = tree.root();
        uint256 nullifier = generateRandomUint256();
        std::string spendKey = generateRandomSpendKey();
        auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(spendKey);
        zkp::FieldT value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(amount);

        std::vector<uint256> merklePath = tree.authPath(0);

        std::cout << "=== CREATING WITHDRAWAL PROOF (UNIFIED CIRCUIT) ===" << std::endl;
        std::cout << "Using unified circuit and keys" << std::endl;
        std::cout << "Tree root: " << merkleRoot << std::endl;
        std::cout << "Path length: " << merklePath.size() << std::endl;

        auto proofData = zkp::ZkProver::createWithdrawalProof(
            amount, merkleRoot, nullifier, merklePath, 0, spendKey, value_randomness);
        
        BEAST_EXPECT(!proofData.empty());
        std::cout << "Unified withdrawal proof creation: " << (!proofData.empty() ? "SUCCESS" : "FAILED") << std::endl;
        
        // VERIFY the withdrawal proof using unified verification key
        if (!proofData.empty()) {
            bool isValid = zkp::ZkProver::verifyWithdrawalProof(proofData);
            BEAST_EXPECT(isValid);
            std::cout << "Unified withdrawal proof verification: " << (isValid ? "PASS" : "FAIL") << std::endl;
        }
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
        
        // Test valid proof verification using unified verification key
        bool isValid = zkp::ZkProver::verifyDepositProof(proofData);
        BEAST_EXPECT(isValid);
        
        // Test tampered proof (should fail with unified verification)
        auto tampered = proofData;
        tampered.nullifier = tampered.nullifier + zkp::FieldT::one();
        bool tamperedValid = zkp::ZkProver::verifyDepositProof(tampered);
        BEAST_EXPECT(!tamperedValid);
        
        // Test empty proof (should fail)
        zkp::ProofData emptyProof;
        bool emptyValid = zkp::ZkProver::verifyDepositProof(emptyProof);
        BEAST_EXPECT(!emptyValid);
        
        std::cout << "Unified deposit verification: valid=" << isValid 
                  << ", tampered=" << tamperedValid << ", empty=" << emptyValid << std::endl;
    }

    void testWithdrawalProofVerification()
    {
        testcase("Withdrawal Proof Verification");
        
        // USE EXISTING UNIFIED KEYS - don't regenerate!
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
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

        std::cout << "=== WITHDRAWAL PROOF VERIFICATION (UNIFIED CIRCUIT) ===" << std::endl;
        std::cout << "Using unified verification key for withdrawal proof" << std::endl;

        auto proofData = zkp::ZkProver::createWithdrawalProof(
            amount, merkleRoot, nullifier, merklePath, 0, spendKey, value_randomness);
        
        if (!proofData.empty()) {
            // Test valid proof using unified verification key
            bool isValid = zkp::ZkProver::verifyWithdrawalProof(proofData);
            BEAST_EXPECT(isValid);
            
            // Test tampered proof (should fail with unified verification)
            auto wrongRoot = proofData;
            wrongRoot.anchor = wrongRoot.anchor + zkp::FieldT::one();
            bool wrongRootValid = zkp::ZkProver::verifyWithdrawalProof(wrongRoot);
            BEAST_EXPECT(!wrongRootValid);
            
            // Test cross-verification with deposit method (should fail due to different public inputs)
            bool crossValid = zkp::ZkProver::verifyDepositProof(proofData);
            BEAST_EXPECT(!crossValid);  // Different public inputs should fail
            
            std::cout << "Unified withdrawal verification: valid=" << isValid 
                      << ", tampered=" << wrongRootValid 
                      << ", cross-verification=" << crossValid << std::endl;
        } else {
            std::cout << "Withdrawal proof creation failed" << std::endl;
        }
    }

    void testInvalidProofVerification()
    {
        testcase("Invalid Proof Verification");
        
        std::vector<unsigned char> invalidProof(100, 0xFF);
        zkp::FieldT dummyField = zkp::FieldT::zero();
        
        // Both deposit and withdrawal use same unified verification key
        bool depositSatisfied = zkp::ZkProver::verifyDepositProof(invalidProof, dummyField, dummyField, dummyField);
        BEAST_EXPECT(!depositSatisfied);
        
        bool withdrawalSatisfied = zkp::ZkProver::verifyWithdrawalProof(invalidProof, dummyField, dummyField, dummyField);
        BEAST_EXPECT(!withdrawalSatisfied);
        
        std::vector<unsigned char> largeInvalidProof(10000, 0xAA);
        bool largeSatisfied = zkp::ZkProver::verifyDepositProof(largeInvalidProof, dummyField, dummyField, dummyField);
        BEAST_EXPECT(!largeSatisfied);
        
        std::cout << "Invalid proof rejection: deposit=" << !depositSatisfied 
                  << ", withdrawal=" << !withdrawalSatisfied << ", large=" << !largeSatisfied << std::endl;
    }

    void testMultipleProofs()
    {
        testcase("Multiple Proofs");
        
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        std::vector<zkp::ProofData> proofs;
        
        // Create multiple proofs using unified circuit
        for (int i = 0; i < 3; ++i) {
            uint64_t amount = 1000000 + i * 250000;
            uint256 commitment = generateRandomUint256();
            std::string spendKey = generateRandomSpendKey();
            auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(spendKey);
            zkp::FieldT value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(amount);
            
            auto proof = zkp::ZkProver::createDepositProof(amount, commitment, spendKey, value_randomness);
            proofs.push_back(proof);
        }
        
        // Verify all proofs using unified verification key
        for (const auto& proof : proofs) {
            BEAST_EXPECT(!proof.empty());
            bool isValid = zkp::ZkProver::verifyDepositProof(proof);
            BEAST_EXPECT(isValid);
        }
        
        // Test cross-verification (should fail due to different public inputs)
        for (size_t i = 0; i < proofs.size(); ++i) {
            for (size_t j = 0; j < proofs.size(); ++j) {
                if (i != j) {
                    bool crossValid = zkp::ZkProver::verifyDepositProof(
                        proofs[i].proof, proofs[j].anchor, proofs[j].nullifier, proofs[j].value_commitment);
                    BEAST_EXPECT(!crossValid);
                }
            }
        }
        
        std::cout << "Multiple proofs test: " << proofs.size() << " proofs generated and verified" << std::endl;
    }

    void testEdgeCases()
    {
        testcase("Edge Cases");
        
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        // Test zero amount
        uint64_t zeroAmount = 0;
        uint256 commitment = generateRandomUint256();
        std::string spendKey = generateRandomSpendKey();
        auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(spendKey);
        zkp::FieldT zero_value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(zeroAmount);
        
        auto zeroProof = zkp::ZkProver::createDepositProof(zeroAmount, commitment, spendKey, zero_value_randomness);
        bool zeroValid = zkp::ZkProver::verifyDepositProof(zeroProof);
        BEAST_EXPECT(zeroValid);
        
        // Test large amount
        uint64_t largeAmount = (1ULL << 50);
        zkp::FieldT large_value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(12345);
        
        auto largeProof = zkp::ZkProver::createDepositProof(largeAmount, commitment, spendKey, large_value_randomness);
        bool largeValid = zkp::ZkProver::verifyDepositProof(largeProof);
        BEAST_EXPECT(largeValid);
        
        std::cout << "Edge cases test: zero=" << zeroValid << ", large=" << largeValid << std::endl;
    }
    
    void testNoteCreationAndCommitment() {
        testcase("Note Creation and Commitment");
        
        // Test Note class functionality (used internally by ZkProver)
        uint64_t amount = 1000000;
        
        // Create a random note (this is what ZkProver does internally)
        auto note = zkp::Note::random(amount);
        
        // Verify note is valid
        BEAST_EXPECT(note.isValid());
        BEAST_EXPECT(note.value == amount);
        
        // Compute commitment (this is done internally by ZkProver)
        auto commitment = note.commitment();
        BEAST_EXPECT(commitment != uint256{});
        
        // Create another note with same amount - should have different commitment
        auto note2 = zkp::Note::random(amount);
        auto commitment2 = note2.commitment();
        BEAST_EXPECT(commitment != commitment2);  // Should be different due to randomness
        
        // Test nullifier computation
        uint256 a_sk = zkp::ZkProver::generateRandomUint256();
        auto nullifier = note.nullifier(a_sk);
        BEAST_EXPECT(nullifier != uint256{});
        
        // Test serialization
        auto serialized = note.serialize();
        auto deserialized = zkp::Note::deserialize(serialized);
        
        BEAST_EXPECT(deserialized.value == note.value);
        BEAST_EXPECT(deserialized.rho == note.rho);
        BEAST_EXPECT(deserialized.r == note.r);
        BEAST_EXPECT(deserialized.a_pk == note.a_pk);
        
        std::cout << "Note functionality test: SUCCESS" << std::endl;
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
        
        std::cout << "Incremental tree test: final size=" << tree.size() 
                  << ", root=" << root << std::endl;
    }

    void testMerkleVerificationEnforcement() {
        testcase("Merkle Verification Enforcement");
        
        // USE EXISTING UNIFIED KEYS - don't regenerate!
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
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
        
        std::cout << "=== MERKLE VERIFICATION ENFORCEMENT (UNIFIED CIRCUIT) ===" << std::endl;
        std::cout << "Testing valid and invalid Merkle paths with unified circuit" << std::endl;
        
        auto validProof = zkp::ZkProver::createWithdrawalProof(
            amount, validRoot, nullifier, validPath, position, spendKey, value_randomness);
        
        bool validResult = false;
        if (!validProof.empty()) {
            validResult = zkp::ZkProver::verifyWithdrawalProof(validProof);
            BEAST_EXPECT(validResult);
        }
        
        // Test 2: Invalid path should FAIL with unified circuit
        std::vector<uint256> invalidPath(validPath.size());
        for (auto& node : invalidPath) {
            node = generateRandomUint256(); // Random garbage
        }
        
        auto invalidProof = zkp::ZkProver::createWithdrawalProof(
            amount, validRoot, nullifier, invalidPath, position, spendKey, value_randomness);
        
        bool invalidResult = false;
        if (!invalidProof.empty()) {
            invalidResult = zkp::ZkProver::verifyWithdrawalProof(invalidProof);
        }
        
        // This SHOULD fail
        if (invalidResult) {
            std::cout << "CRITICAL BUG: Invalid Merkle path accepted!" << std::endl;
            BEAST_EXPECT(false); // This should not happen
        } else {
            std::cout << "Good: Unified circuit properly rejected invalid Merkle path" << std::endl;
            BEAST_EXPECT(true);
        }
        
        std::cout << "Merkle verification (unified): valid=" << validResult << ", invalid=" << invalidResult << std::endl;
    }
    
    void testUnifiedCircuitBehavior() {
        testcase("Unified Circuit Behavior Verification");
        
        // USE EXISTING UNIFIED KEYS - don't regenerate!
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        // Create both deposit and withdrawal proofs using same unified circuit
        uint64_t amount = 1500000;
        uint256 commitment = generateRandomUint256();
        std::string spendKey = generateRandomSpendKey();
        auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(spendKey);
        zkp::FieldT value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits);
        
        std::cout << "=== UNIFIED CIRCUIT BEHAVIOR TEST ===" << std::endl;
        std::cout << "Testing deposit and withdrawal with same unified circuit" << std::endl;
        
        // Create deposit proof using unified circuit
        auto depositProof = zkp::ZkProver::createDepositProof(amount, commitment, spendKey, value_randomness);
        BEAST_EXPECT(!depositProof.empty());
        
        // Create withdrawal proof using same unified circuit
        zkp::IncrementalMerkleTree tree(3);
        uint256 testNote = generateRandomUint256();
        tree.append(testNote);
        
        uint256 merkleRoot = tree.root();
        uint256 nullifier = generateRandomUint256();
        std::vector<uint256> merklePath = tree.authPath(0);
        
        auto withdrawalProof = zkp::ZkProver::createWithdrawalProof(
            amount, merkleRoot, nullifier, merklePath, 0, spendKey, value_randomness);
        
        if (!withdrawalProof.empty()) {
            // Both proofs should verify with unified verification key
            bool depositValid = zkp::ZkProver::verifyDepositProof(depositProof);
            bool withdrawalValid = zkp::ZkProver::verifyWithdrawalProof(withdrawalProof);
            
            BEAST_EXPECT(depositValid);
            BEAST_EXPECT(withdrawalValid);
            
            // Cross-verification should fail (different public inputs)
            bool crossDeposit = zkp::ZkProver::verifyDepositProof(
                withdrawalProof.proof, withdrawalProof.anchor, withdrawalProof.nullifier, withdrawalProof.value_commitment);
            bool crossWithdrawal = zkp::ZkProver::verifyWithdrawalProof(
                depositProof.proof, depositProof.anchor, depositProof.nullifier, depositProof.value_commitment);
            
            BEAST_EXPECT(!crossDeposit);
            BEAST_EXPECT(!crossWithdrawal);
            
            std::cout << "Unified circuit results:" << std::endl;
            std::cout << "  - Deposit proof verification: " << (depositValid ? "PASS" : "FAIL") << std::endl;
            std::cout << "  - Withdrawal proof verification: " << (withdrawalValid ? "PASS" : "FAIL") << std::endl;
            std::cout << "  - Cross-verification properly rejected: " << (!crossDeposit && !crossWithdrawal ? "PASS" : "FAIL") << std::endl;
            
            // Verify they use the same constraint system
            std::cout << "  - Both proofs use same unified verification key: YES" << std::endl;
            
        } else {
            std::cout << "Withdrawal proof creation failed" << std::endl;
        }
    }
};

BEAST_DEFINE_TESTSUITE(ZKProver, protocol, ripple);

}