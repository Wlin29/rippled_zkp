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
        testNoteCreationAndCommitment();
        testDepositProofCreation();
        testWithdrawalProofCreation();
        testDepositProofVerification();
        testWithdrawalProofVerification();
        testInvalidProofVerification();
        testMultipleProofs();
        testEdgeCases();
        testIncrementalMerkleTree();
        testMerkleVerificationEnforcement();
        testUnifiedCircuitBehavior();
        testZcashStyleWorkflow();
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
    
    void testNoteCreationAndCommitment() {
        testcase("Note Creation and Commitment - Zcash Style");
        
        uint64_t amount = 1000000;
        
        // Test ZkProver note creation methods
        zkp::Note randomNote = zkp::ZkProver::createRandomNote(amount);
        BEAST_EXPECT(randomNote.isValid());
        BEAST_EXPECT(randomNote.value == amount);
        
        // Test manual note creation
        uint256 a_pk = zkp::ZkProver::generateRandomUint256();
        uint256 rho = zkp::ZkProver::generateRandomUint256();
        uint256 r = zkp::ZkProver::generateRandomUint256();
        
        zkp::Note manualNote = zkp::ZkProver::createNote(amount, a_pk, rho, r);
        BEAST_EXPECT(manualNote.isValid());
        BEAST_EXPECT(manualNote.value == amount);
        BEAST_EXPECT(manualNote.a_pk == a_pk);
        BEAST_EXPECT(manualNote.rho == rho);
        BEAST_EXPECT(manualNote.r == r);
        
        // Test commitment computation
        auto commitment1 = randomNote.commitment();
        auto commitment2 = manualNote.commitment();
        BEAST_EXPECT(commitment1 != uint256{});
        BEAST_EXPECT(commitment2 != uint256{});
        BEAST_EXPECT(commitment1 != commitment2);  // Should be different due to randomness
        
        // Test nullifier computation
        uint256 a_sk = zkp::ZkProver::generateRandomUint256();
        auto nullifier1 = randomNote.nullifier(a_sk);
        auto nullifier2 = manualNote.nullifier(a_sk);
        BEAST_EXPECT(nullifier1 != uint256{});
        BEAST_EXPECT(nullifier2 != uint256{});
        
        // Test serialization
        auto serialized = randomNote.serialize();
        auto deserialized = zkp::Note::deserialize(serialized);
        
        BEAST_EXPECT(deserialized.value == randomNote.value);
        BEAST_EXPECT(deserialized.rho == randomNote.rho);
        BEAST_EXPECT(deserialized.r == randomNote.r);
        BEAST_EXPECT(deserialized.a_pk == randomNote.a_pk);
        
        std::cout << "note functionality test: SUCCESS" << std::endl;
    }

    void testDepositProofCreation()
    {
        testcase("Deposit Proof Creation - Zcash Style");
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));

        for (size_t idx = 0; idx < 3; ++idx) {
            uint64_t amount = 1000000 + idx * 100000;

            std::cout << "=== CREATING DEPOSIT PROOF " << idx << " (ZCASH STYLE) ===" << std::endl;
            
            // Create note first
            zkp::Note depositNote = zkp::ZkProver::createRandomNote(amount);
            
            std::cout << "Created note:" << std::endl;
            std::cout << "  Value: " << depositNote.value << std::endl;
            std::cout << "  Commitment: " << depositNote.commitment() << std::endl;
            std::cout << "  Rho: " << depositNote.rho << std::endl;
            std::cout << "  R: " << depositNote.r << std::endl;

            // Create proof using the note (new signature)
            auto proofData = zkp::ZkProver::createDepositProof(depositNote);
            BEAST_EXPECT(!proofData.empty());
            
            // Verify the proof using ProofData structure
            bool isValid = zkp::ZkProver::verifyDepositProof(proofData);
            BEAST_EXPECT(isValid);
            
            std::cout << "deposit proof " << idx << " verification: " << (isValid ? "PASS" : "FAIL") << std::endl;
        }
    }

    void testWithdrawalProofCreation()
    {
        testcase("Withdrawal Proof Creation - Zcash Style");
        
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));

        // Create incremental tree for testing
        zkp::IncrementalMerkleTree tree(4); // depth 4 for testing
        
        // Create note first
        uint64_t amount = 500000;
        zkp::Note inputNote = zkp::ZkProver::createRandomNote(amount);
        
        // Add the note's commitment to the tree
        uint256 noteCommitment = inputNote.commitment();
        size_t noteIndex = tree.append(noteCommitment);
        
        // Add some dummy notes to make tree more realistic
        uint256 dummyNote1 = generateRandomUint256();
        uint256 dummyNote2 = generateRandomUint256();
        tree.append(dummyNote1);
        tree.append(dummyNote2);
        
        uint256 merkleRoot = tree.root();
        std::vector<uint256> authPath = tree.authPath(noteIndex);
        
        // Generate spending key
        uint256 a_sk = zkp::ZkProver::generateRandomUint256();

        std::cout << "=== CREATING WITHDRAWAL PROOF (ZCASH STYLE) ===" << std::endl;
        std::cout << "Input note value: " << inputNote.value << std::endl;
        std::cout << "Input note commitment: " << noteCommitment << std::endl;
        std::cout << "Tree root: " << merkleRoot << std::endl;
        std::cout << "Auth path length: " << authPath.size() << std::endl;
        std::cout << "Position: " << noteIndex << std::endl;

        auto proofData = zkp::ZkProver::createWithdrawalProof(
            inputNote,      // Note being spent
            a_sk,           // Secret spending key
            authPath,       // Merkle authentication path
            noteIndex,      // Position in tree
            merkleRoot      // Expected merkle root
        );
        
        BEAST_EXPECT(!proofData.empty());
        std::cout << "withdrawal proof creation: " << (!proofData.empty() ? "SUCCESS" : "FAILED") << std::endl;
        
        // Verify the withdrawal proof
        if (!proofData.empty()) {
            bool isValid = zkp::ZkProver::verifyWithdrawalProof(proofData);
            BEAST_EXPECT(isValid);
            std::cout << "withdrawal proof verification: " << (isValid ? "PASS" : "FAIL") << std::endl;
        }
    }

    void testDepositProofVerification()
    {
        testcase("Deposit Proof Verification - Zcash Style");
        
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        // Create note first, then proof
        uint64_t amount = 2000000;
        zkp::Note depositNote = zkp::ZkProver::createRandomNote(amount);
        
        auto proofData = zkp::ZkProver::createDepositProof(depositNote);
        BEAST_EXPECT(!proofData.empty());
        
        // Test valid proof verification
        bool isValid = zkp::ZkProver::verifyDepositProof(proofData);
        BEAST_EXPECT(isValid);
        
        // Test tampered proof (should fail)
        auto tampered = proofData;
        tampered.nullifier = tampered.nullifier + zkp::FieldT::one();
        bool tamperedValid = zkp::ZkProver::verifyDepositProof(tampered);
        BEAST_EXPECT(!tamperedValid);
        
        // Test empty proof (should fail)
        zkp::ProofData emptyProof;
        bool emptyValid = zkp::ZkProver::verifyDepositProof(emptyProof);
        BEAST_EXPECT(!emptyValid);
        
        std::cout << "deposit verification: valid=" << isValid 
                  << ", tampered=" << tamperedValid << ", empty=" << emptyValid << std::endl;
    }

    void testWithdrawalProofVerification()
    {
        testcase("Withdrawal Proof Verification - Zcash Style");
        
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        zkp::IncrementalMerkleTree tree(3);
        
        // Create note and add to tree 
        uint64_t amount = 750000;
        zkp::Note inputNote = zkp::ZkProver::createRandomNote(amount);
        uint256 noteCommitment = inputNote.commitment();
        
        size_t noteIndex = tree.append(noteCommitment);
        uint256 merkleRoot = tree.root();
        std::vector<uint256> authPath = tree.authPath(noteIndex);
        
        uint256 a_sk = zkp::ZkProver::generateRandomUint256();

        std::cout << "=== WITHDRAWAL PROOF VERIFICATION (ZCASH STYLE) ===" << std::endl;

        // Create proof using new signature
        auto proofData = zkp::ZkProver::createWithdrawalProof(
            inputNote, a_sk, authPath, noteIndex, merkleRoot);
        
        if (!proofData.empty()) {
            // Test valid proof
            bool isValid = zkp::ZkProver::verifyWithdrawalProof(proofData);
            BEAST_EXPECT(isValid);
            
            // Test tampered proof (should fail)
            auto wrongRoot = proofData;
            wrongRoot.anchor = wrongRoot.anchor + zkp::FieldT::one();
            bool wrongRootValid = zkp::ZkProver::verifyWithdrawalProof(wrongRoot);
            BEAST_EXPECT(!wrongRootValid);
            
            // Test cross-verification with deposit method (should fail)
            bool crossValid = zkp::ZkProver::verifyDepositProof(proofData);
            BEAST_EXPECT(!crossValid);
            
            std::cout << "withdrawal verification: valid=" << isValid 
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
        
        // Test with individual parameters
        bool depositSatisfied = zkp::ZkProver::verifyDepositProof(invalidProof, dummyField, dummyField, dummyField);
        BEAST_EXPECT(!depositSatisfied);
        
        bool withdrawalSatisfied = zkp::ZkProver::verifyWithdrawalProof(invalidProof, dummyField, dummyField, dummyField);
        BEAST_EXPECT(!withdrawalSatisfied);
        
        // Test with ProofData structure
        zkp::ProofData invalidProofData{invalidProof, dummyField, dummyField, dummyField};
        bool depositProofDataSatisfied = zkp::ZkProver::verifyDepositProof(invalidProofData);
        BEAST_EXPECT(!depositProofDataSatisfied);
        
        bool withdrawalProofDataSatisfied = zkp::ZkProver::verifyWithdrawalProof(invalidProofData);
        BEAST_EXPECT(!withdrawalProofDataSatisfied);
        
        std::cout << "Invalid proof rejection: deposit=" << !depositSatisfied 
                  << ", withdrawal=" << !withdrawalSatisfied 
                  << ", proofData=" << !depositProofDataSatisfied << std::endl;
    }

    void testMultipleProofs()
    {
        testcase("Multiple Proofs - Zcash Style");
        
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        std::vector<zkp::ProofData> proofs;
        std::vector<zkp::Note> notes;
        
        // ✅ Create multiple proofs using Zcash-style approach
        for (int i = 0; i < 3; ++i) {
            uint64_t amount = 1000000 + i * 250000;
            
            // Create note first
            zkp::Note note = zkp::ZkProver::createRandomNote(amount);
            notes.push_back(note);
            
            // Then create proof
            auto proof = zkp::ZkProver::createDepositProof(note);
            proofs.push_back(proof);
        }
        
        // Verify all proofs
        for (size_t i = 0; i < proofs.size(); ++i) {
            BEAST_EXPECT(!proofs[i].empty());
            bool isValid = zkp::ZkProver::verifyDepositProof(proofs[i]);
            BEAST_EXPECT(isValid);
            
            std::cout << "Proof " << i << " for note value " << notes[i].value 
                      << ": " << (isValid ? "VALID" : "INVALID") << std::endl;
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
        
        std::cout << "Multiple Zcash-style proofs test: " << proofs.size() << " proofs generated and verified" << std::endl;
    }

    void testEdgeCases()
    {
        testcase("Edge Cases - Zcash Style");
        
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        // Test zero amount
        zkp::Note zeroNote = zkp::ZkProver::createRandomNote(0);
        auto zeroProof = zkp::ZkProver::createDepositProof(zeroNote);
        bool zeroValid = zkp::ZkProver::verifyDepositProof(zeroProof);
        BEAST_EXPECT(zeroValid);
        
        // Test large amount
        uint64_t largeAmount = (1ULL << 50);
        zkp::Note largeNote = zkp::ZkProver::createRandomNote(largeAmount);
        auto largeProof = zkp::ZkProver::createDepositProof(largeNote);
        bool largeValid = zkp::ZkProver::verifyDepositProof(largeProof);
        BEAST_EXPECT(largeValid);
        
        // Test maximum uint64_t amount
        uint64_t maxAmount = std::numeric_limits<uint64_t>::max();
        zkp::Note maxNote = zkp::ZkProver::createRandomNote(maxAmount);
        auto maxProof = zkp::ZkProver::createDepositProof(maxNote);
        bool maxValid = zkp::ZkProver::verifyDepositProof(maxProof);
        BEAST_EXPECT(maxValid);
        
        std::cout << "edge cases: zero=" << zeroValid 
                  << ", large=" << largeValid << ", max=" << maxValid << std::endl;
    }

    void testIncrementalMerkleTree() {
        testcase("Incremental Merkle Tree");
        
        zkp::IncrementalMerkleTree tree(4); // Small tree for testing
        
        // Test empty tree
        BEAST_EXPECT(tree.empty());
        BEAST_EXPECT(tree.size() == 0);
        
        // Add some leaves using note commitments
        zkp::Note note1 = zkp::ZkProver::createRandomNote(1000000);
        zkp::Note note2 = zkp::ZkProver::createRandomNote(2000000);
        zkp::Note note3 = zkp::ZkProver::createRandomNote(3000000);
        
        uint256 leaf1 = note1.commitment();
        uint256 leaf2 = note2.commitment();
        uint256 leaf3 = note3.commitment();
        
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
        testcase("Merkle Verification Enforcement - Zcash Style");
        
        // Create note first 
        uint64_t amount = 1000000;
        zkp::Note inputNote = zkp::ZkProver::createRandomNote(amount);
        uint256 noteCommitment = inputNote.commitment();
        
        // Create a tree and add the note
        zkp::IncrementalMerkleTree tree(20);
        size_t position = tree.append(noteCommitment);
        uint256 validRoot = tree.root();
        
        // Generate spending key
        uint256 a_sk = zkp::ZkProver::generateRandomUint256();
        
        // Get valid authentication path
        std::vector<uint256> validPath = tree.authPath(position);
        
        // Test 1: Valid proof should succeed
        auto validProof = zkp::ZkProver::createWithdrawalProof(
            inputNote, a_sk, validPath, position, validRoot);
        
        bool validResult = false;
        if (!validProof.empty()) {
            validResult = zkp::ZkProver::verifyWithdrawalProof(validProof);
        }
        
        BEAST_EXPECT(validResult);
        std::cout << "Valid Merkle path: " << (validResult ? "PASS" : "FAIL") << std::endl;

        // Test 2: Create invalid path
        std::vector<uint256> invalidPath(validPath.size());
        for (size_t i = 0; i < invalidPath.size(); ++i) {
            if (i < 3) {
                invalidPath[i] = uint256{};  // Zero values (obviously wrong)
            } else {
                invalidPath[i] = generateRandomUint256();  // Random values
            }
        }
        
        std::cout << "Testing with invalid path..." << std::endl;
        
        // This should FAIL during proof generation or verification
        bool proofGenerationFailed = false;
        auto invalidProof = zkp::ProofData{};
        
        try {
            invalidProof = zkp::ZkProver::createWithdrawalProof(
                inputNote, a_sk, invalidPath, position, validRoot);
        } catch (const std::exception& e) {
            std::cout << "Good: Invalid path rejected during proof generation: " << e.what() << std::endl;
            proofGenerationFailed = true;
        }
        
        bool invalidResult = false;
        if (!proofGenerationFailed && !invalidProof.empty()) {
            try {
                invalidResult = zkp::ZkProver::verifyWithdrawalProof(invalidProof);
            } catch (const std::exception& e) {
                std::cout << "Good: Invalid proof rejected during verification: " << e.what() << std::endl;
                invalidResult = false;
            }
        }
        
        // Either proof generation should fail OR verification should fail
        bool securityWorking = proofGenerationFailed || !invalidResult;
        BEAST_EXPECT(securityWorking);
        
        if (!securityWorking) {
            std::cout << "CRITICAL BUG: Invalid Merkle path accepted!" << std::endl;
        } else {
            std::cout << "Good: Invalid Merkle path properly rejected" << std::endl;
        }
        
        // Test 3: Invalid root should fail
        uint256 invalidRoot = generateRandomUint256();
        auto invalidRootProof = zkp::ZkProver::createWithdrawalProof(
            inputNote, a_sk, validPath, position, invalidRoot);
        
        bool invalidRootResult = false;
        if (!invalidRootProof.empty()) {
            invalidRootResult = zkp::ZkProver::verifyWithdrawalProof(invalidRootProof);
        }
        
        BEAST_EXPECT(!invalidRootResult);
        std::cout << "Invalid root test: " << (invalidRootResult ? "FAIL" : "PASS") << std::endl;
    }
    
    void testUnifiedCircuitBehavior() {
        testcase("Unified Circuit Behavior");
        
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        uint64_t amount = 1500000;
        
        std::cout << "=== UNIFIED CIRCUIT BEHAVIOR TEST (ZCASH STYLE) ===" << std::endl;
        
        // Create deposit note and proof
        zkp::Note depositNote = zkp::ZkProver::createRandomNote(amount);
        auto depositProof = zkp::ZkProver::createDepositProof(depositNote);
        BEAST_EXPECT(!depositProof.empty());
        
        // Create withdrawal note and proof
        zkp::Note withdrawalNote = zkp::ZkProver::createRandomNote(amount);
        uint256 withdrawalCommitment = withdrawalNote.commitment();
        
        zkp::IncrementalMerkleTree tree(3);
        size_t noteIndex = tree.append(withdrawalCommitment);
        
        uint256 merkleRoot = tree.root();
        uint256 a_sk = zkp::ZkProver::generateRandomUint256();
        std::vector<uint256> authPath = tree.authPath(noteIndex);
        
        auto withdrawalProof = zkp::ZkProver::createWithdrawalProof(
            withdrawalNote, a_sk, authPath, noteIndex, merkleRoot);
        
        if (!withdrawalProof.empty()) {
            // Both proofs should verify with unified verification key
            bool depositValid = zkp::ZkProver::verifyDepositProof(depositProof);
            bool withdrawalValid = zkp::ZkProver::verifyWithdrawalProof(withdrawalProof);
            
            BEAST_EXPECT(depositValid);
            BEAST_EXPECT(withdrawalValid);
            
            // Cross-verification should fail (different public inputs)
            bool crossDeposit = zkp::ZkProver::verifyDepositProof(
                withdrawalProof.proof, depositProof.anchor, depositProof.nullifier, depositProof.value_commitment);
            bool crossWithdrawal = zkp::ZkProver::verifyWithdrawalProof(
                depositProof.proof, withdrawalProof.anchor, withdrawalProof.nullifier, withdrawalProof.value_commitment);
            
            BEAST_EXPECT(!crossDeposit);
            BEAST_EXPECT(!crossWithdrawal);
            
            std::cout << "Unified circuit results:" << std::endl;
            std::cout << "  - Deposit proof verification: " << (depositValid ? "PASS" : "FAIL") << std::endl;
            std::cout << "  - Withdrawal proof verification: " << (withdrawalValid ? "PASS" : "FAIL") << std::endl;
            std::cout << "  - Cross-verification properly rejected: " << ((!crossDeposit && !crossWithdrawal) ? "PASS" : "FAIL") << std::endl;
            
        } else {
            std::cout << "Withdrawal proof creation failed" << std::endl;
        }
    }
    
    void testZcashStyleWorkflow() {
        testcase("Complete Workflow");
        
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        std::cout << "=== COMPLETE ZCASH-STYLE WORKFLOW ===" << std::endl;
        
        // Step 1: Alice creates a shielded note (deposit)
        uint64_t depositAmount = 1000000;
        zkp::Note aliceNote = zkp::ZkProver::createRandomNote(depositAmount);
        
        std::cout << "1. Alice creates note with value: " << aliceNote.value << std::endl;
        std::cout << "   Commitment: " << aliceNote.commitment() << std::endl;
        
        // Step 2: Alice creates deposit proof
        auto depositProof = zkp::ZkProver::createDepositProof(aliceNote);
        BEAST_EXPECT(!depositProof.empty());
        BEAST_EXPECT(zkp::ZkProver::verifyDepositProof(depositProof));
        
        std::cout << "2. Alice creates valid deposit proof" << std::endl;
        
        // Step 3: Add Alice's note to the commitment tree
        zkp::IncrementalMerkleTree commitmentTree(10);
        uint256 aliceCommitment = aliceNote.commitment();
        size_t aliceIndex = commitmentTree.append(aliceCommitment);
        
        // Add some other notes to the tree (for anonymity)
        for (int i = 0; i < 5; ++i) {
            zkp::Note dummyNote = zkp::ZkProver::createRandomNote(500000 + i * 100000);
            commitmentTree.append(dummyNote.commitment());
        }
        
        uint256 currentRoot = commitmentTree.root();
        std::cout << "3. Alice's note added to tree at index " << aliceIndex 
                  << ", tree size: " << commitmentTree.size() << std::endl;
        
        // Step 4: Alice wants to withdraw (spend her note)
        uint256 aliceSpendingKey = zkp::ZkProver::generateRandomUint256();
        std::vector<uint256> aliceAuthPath = commitmentTree.authPath(aliceIndex);
        
        // Step 5: Alice creates withdrawal proof
        auto withdrawalProof = zkp::ZkProver::createWithdrawalProof(
            aliceNote, aliceSpendingKey, aliceAuthPath, aliceIndex, currentRoot);
        
        BEAST_EXPECT(!withdrawalProof.empty());
        BEAST_EXPECT(zkp::ZkProver::verifyWithdrawalProof(withdrawalProof));
        
        std::cout << "4. Alice creates valid withdrawal proof" << std::endl;
        
        // Step 6: Verify privacy properties
        // The withdrawal proof should not reveal which note Alice is spending
        uint256 aliceNullifier = zkp::ZkProver::fieldElementToUint256(withdrawalProof.nullifier);
        std::cout << "5. Alice's nullifier: " << aliceNullifier << std::endl;
        
        // Step 7: Test double-spending prevention
        // Alice tries to spend the same note again (should be prevented by nullifier tracking)
        auto doubleSpendProof = zkp::ZkProver::createWithdrawalProof(
            aliceNote, aliceSpendingKey, aliceAuthPath, aliceIndex, currentRoot);
        
        if (!doubleSpendProof.empty()) {
            uint256 secondNullifier = zkp::ZkProver::fieldElementToUint256(doubleSpendProof.nullifier);
            bool sameNullifier = (aliceNullifier == secondNullifier);
            BEAST_EXPECT(sameNullifier);  // Same note should produce same nullifier
            
            std::cout << "6. Double-spend check: Same nullifier produced" << std::endl;
            std::cout << "   (In practice, the ledger would reject the second transaction)" << std::endl;
        }
        
        // Step 8: Test that different notes produce different nullifiers
        zkp::Note bobNote = zkp::ZkProver::createRandomNote(2000000);
        size_t bobIndex = commitmentTree.append(bobNote.commitment());
        currentRoot = commitmentTree.root();
        
        std::vector<uint256> bobAuthPath = commitmentTree.authPath(bobIndex);
        uint256 bobSpendingKey = zkp::ZkProver::generateRandomUint256();
        
        auto bobProof = zkp::ZkProver::createWithdrawalProof(
            bobNote, bobSpendingKey, bobAuthPath, bobIndex, currentRoot);
        
        if (!bobProof.empty()) {
            uint256 bobNullifier = zkp::ZkProver::fieldElementToUint256(bobProof.nullifier);
            bool differentNullifiers = (aliceNullifier != bobNullifier);
            BEAST_EXPECT(differentNullifiers);
            
            std::cout << "7. Privacy check: Different notes produce different nullifiers" << std::endl;
        }
        
        std::cout << "=== ZCASH-STYLE WORKFLOW COMPLETE ===" << std::endl;
    }
};

BEAST_DEFINE_TESTSUITE(ZKProver, protocol, ripple);

}