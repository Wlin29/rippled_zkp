#include <xrpl/beast/unit_test.h>
#include <xrpl/protocol/UintTypes.h>
#include <string>
#include <random>
#include <iostream>
#include <chrono>
#include <iomanip>

#include <libxrpl/zkp/ZKProver.h>
#include <libxrpl/zkp/circuits/MerkleCircuit.h>
#include <libxrpl/zkp/MerkleTree.h>
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
        
        // Run all test cases
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

        uint64_t testAmount = 500000;
        uint256 testCommitment = generateRandomUint256();
        std::string testSpendKey = generateRandomSpendKey();

        auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(testSpendKey);
        zkp::FieldT value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(testAmount);

        auto proofData = zkp::ZkProver::createDepositProof(testAmount, testCommitment, testSpendKey, value_randomness);
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
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));

        // Create a Merkle tree
        zkp::MerkleTree tree(2); // depth 2 = 4 leaves max
        
        // Add some dummy notes to the tree
        uint256 dummyNote1 = generateRandomUint256();
        uint256 dummyNote2 = generateRandomUint256();
        
        size_t note1Index = tree.addLeaf(dummyNote1);
        size_t note2Index = tree.addLeaf(dummyNote2);
        
        // Create our test note
        uint64_t amount = 2000000;
        std::string spendKey = generateRandomSpendKey();
        auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(spendKey);
        zkp::FieldT value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(amount);
        
        // TODO: In real implementation, compute actual note commitment
        uint256 ourNote = generateRandomUint256(); // Placeholder
        size_t ourNoteIndex = tree.addLeaf(ourNote);
        
        // Get authentication path and root
        auto authPath = tree.getAuthPath(ourNoteIndex);
        uint256 merkleRoot = tree.getRoot();
        
        std::cout << "Tree root: " << merkleRoot << std::endl;
        std::cout << "Note index: " << ourNoteIndex << std::endl;
        std::cout << "Auth path length: " << authPath.size() << std::endl;
        
        // Verify the path works
        bool pathValid = zkp::MerkleTree::verifyPath(ourNote, authPath, ourNoteIndex, merkleRoot);
        BEAST_EXPECT(pathValid);
        
        uint256 nullifier = generateRandomUint256();
        
        auto proofData = zkp::ZkProver::createWithdrawalProof(
            amount, merkleRoot, nullifier, authPath, ourNoteIndex, spendKey, value_randomness);
        BEAST_EXPECT(!proofData.empty());
    }
    
    void testDepositProofVerification()
    {
        testcase("Deposit Proof Verification");
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));

        uint64_t amount = 1000000;
        uint256 commitment = generateRandomUint256();
        std::string spendKey = generateRandomSpendKey();

        auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(spendKey);
        zkp::FieldT value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(amount);

        auto proofData = zkp::ZkProver::createDepositProof(amount, commitment, spendKey, value_randomness);
        BEAST_EXPECT(!proofData.empty());

        bool isValid = zkp::ZkProver::verifyDepositProof(proofData);
        BEAST_EXPECT(isValid);

        zkp::FieldT wrongNullifier = proofData.nullifier + zkp::FieldT::one();
        bool wrongNullifierResult = zkp::ZkProver::verifyDepositProof(
            proofData.proof, proofData.anchor, wrongNullifier, proofData.value_commitment);
        BEAST_EXPECT(!wrongNullifierResult);

        std::vector<unsigned char> emptyProof;
        bool emptyResult = zkp::ZkProver::verifyDepositProof(
            emptyProof, proofData.anchor, proofData.nullifier, proofData.value_commitment);
        BEAST_EXPECT(!emptyResult);
    }
    
    void testWithdrawalProofVerification()
    {
        testcase("Withdrawal Proof Verification");
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));

        uint64_t amount = 2000000;
        uint256 merkleRoot = generateRandomUint256();
        uint256 nullifier = generateRandomUint256();
        std::string spendKey = generateRandomSpendKey();

        std::vector<uint256> merklePath;
        for (int i = 0; i < 2; ++i) {
            merklePath.push_back(generateRandomUint256());
        }
        size_t pathIndex = 1;

        auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(spendKey);
        zkp::FieldT value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(amount);

        auto proofData = zkp::ZkProver::createWithdrawalProof(
            amount, merkleRoot, nullifier, merklePath, pathIndex, spendKey, value_randomness);
        BEAST_EXPECT(!proofData.empty());

        bool isValid = zkp::ZkProver::verifyWithdrawalProof(proofData);
        BEAST_EXPECT(isValid);

        zkp::FieldT wrongAnchor = proofData.anchor + zkp::FieldT::one();
        bool wrongAnchorResult = zkp::ZkProver::verifyWithdrawalProof(
            proofData.proof, wrongAnchor, proofData.nullifier, proofData.value_commitment);
        BEAST_EXPECT(!wrongAnchorResult);
    }
    
    void testInvalidProofVerification()
    {
        testcase("Invalid Proof Verification");
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));

        uint64_t amount = 1000000;
        uint256 commitment = generateRandomUint256();
        std::string spendKey = generateRandomSpendKey();

        auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(spendKey);
        zkp::FieldT value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(amount);

        auto validProofData = zkp::ZkProver::createDepositProof(amount, commitment, spendKey, value_randomness);

        std::vector<unsigned char> corruptedProof = validProofData.proof;
        if (!corruptedProof.empty()) {
            corruptedProof[0] ^= 0xFF;
        }

        bool depositCorrupted = zkp::ZkProver::verifyDepositProof(
            corruptedProof, validProofData.anchor, validProofData.nullifier, validProofData.value_commitment);
        BEAST_EXPECT(!depositCorrupted);

        std::vector<unsigned char> largeProof(10000, 0xFF);
        bool depositLarge = zkp::ZkProver::verifyDepositProof(
            largeProof, validProofData.anchor, validProofData.nullifier, validProofData.value_commitment);
        BEAST_EXPECT(!depositLarge);
    }
    
    void testMultipleProofs()
    {
        testcase("Multiple Proofs");
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));

        const size_t numProofs = 5;
        std::vector<zkp::ProofData> depositProofs;

        for (size_t i = 0; i < numProofs; ++i) {
            uint64_t amount = 1000000 + i * 100000;
            uint256 commitment = generateRandomUint256();
            std::string spendKey = generateRandomSpendKey();

            auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(spendKey);
            zkp::FieldT value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(amount);

            auto proofData = zkp::ZkProver::createDepositProof(amount, commitment, spendKey, value_randomness);
            BEAST_EXPECT(!proofData.empty());

            depositProofs.push_back(proofData);
        }

        for (size_t i = 0; i < numProofs; ++i) {
            bool isValid = zkp::ZkProver::verifyDepositProof(depositProofs[i]);
            BEAST_EXPECT(isValid);
        }

        for (size_t i = 0; i < numProofs; ++i) {
            for (size_t j = 0; j < numProofs; ++j) {
                if (i != j) {
                    bool shouldFail = zkp::ZkProver::verifyDepositProof(
                        depositProofs[i].proof,
                        depositProofs[j].anchor,
                        depositProofs[j].nullifier,
                        depositProofs[j].value_commitment);
                    BEAST_EXPECT(!shouldFail);
                }
            }
        }
    }
    
    void testEdgeCases()
    {
        testcase("Edge Cases");
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));

        uint256 commitment = generateRandomUint256();
        std::string spendKey = generateRandomSpendKey();
        auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(spendKey);

        // Zero amount - should work
        zkp::FieldT zero_value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits);
        auto zeroProof = zkp::ZkProver::createDepositProof(0, commitment, spendKey, zero_value_randomness);
        bool zeroValid = zkp::ZkProver::verifyDepositProof(zeroProof);
        BEAST_EXPECT(zeroValid);

        // Use 2^50 = 1,125,899,906,842,624 (safe for BN128 field arithmetic)
        uint64_t largeAmount = (1ULL << 50);
        
        // Use small offset to prevent field overflow in randomness computation
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
        
        std::cout << "Note commitment: " << commitment << std::endl;
        std::cout << "Note nullifier: " << nullifier << std::endl;
    }
};

BEAST_DEFINE_TESTSUITE(ZKProver, protocol, ripple);

}