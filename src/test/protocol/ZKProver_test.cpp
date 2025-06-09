#include <xrpl/beast/unit_test.h>
#include <xrpl/protocol/UintTypes.h>
#include <string>
#include <random>
#include <iostream>
#include <chrono>
#include <iomanip>

#include <libxrpl/zkp/ZKProver.h>

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
        
        // Test loading keys (just verify it doesn't crash)
        BEAST_EXPECT(zkp::ZkProver::loadKeys(keyPath));
    }
    
    void testProofSerialization()
    {
        testcase("Proof Serialization");
        
        // Ensure keys are generated
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        uint64_t testAmount = 500000;
        uint256 testCommitment = generateRandomUint256();
        std::string testSpendKey = generateRandomSpendKey();
        
        // UPDATED: Handle ProofData return type
        auto proofData = zkp::ZkProver::createDepositProof(testAmount, testCommitment, testSpendKey);
        BEAST_EXPECT(!proofData.empty());
        
        // Test that we can extract the proof bytes
        BEAST_EXPECT(!proofData.proof.empty());
        BEAST_EXPECT(proofData.proof.size() > 0);
    }
    
    void testDepositProofCreation()
    {
        testcase("Deposit Proof Creation");
        
        // Ensure keys are generated
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        for (size_t idx : {0, 1, 2, 3}) {
            uint64_t amount = 1000000 + idx * 100000;
            uint256 commitment = generateRandomUint256();
            std::string spendKey = generateRandomSpendKey();
            
            // UPDATED: Handle ProofData return type
            auto proofData = zkp::ZkProver::createDepositProof(amount, commitment, spendKey);
            BEAST_EXPECT(!proofData.empty());
        }
        
        // Test different commitments produce different proofs
        uint64_t amount = 1000000;
        std::string spendKey = generateRandomSpendKey();
        uint256 commitment1 = generateRandomUint256();
        uint256 commitment2 = generateRandomUint256();
        
        auto proof1 = zkp::ZkProver::createDepositProof(amount, commitment1, spendKey);
        auto proof2 = zkp::ZkProver::createDepositProof(amount, commitment2, spendKey);
        
        // UPDATED: Compare proof bytes instead of ProofData objects
        BEAST_EXPECT(proof1.proof != proof2.proof); // Different commitments should give different proofs
    }
    
    void testWithdrawalProofCreation()
    {
        testcase("Withdrawal Proof Creation");
        
        // Ensure keys are generated
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
        
        // UPDATED: Handle ProofData return type
        auto proofData = zkp::ZkProver::createWithdrawalProof(
            amount, merkleRoot, nullifier, merklePath, pathIndex, spendKey);
        BEAST_EXPECT(!proofData.empty());
    }
    
    void testDepositProofVerification()
    {
        testcase("Deposit Proof Verification");
        
        // Ensure keys are generated
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        // Create test data
        uint64_t amount = 1000000;
        uint256 commitment = generateRandomUint256();
        std::string spendKey = generateRandomSpendKey();
        
        // UPDATED: Create proof returns ProofData
        auto proofData = zkp::ZkProver::createDepositProof(amount, commitment, spendKey);
        BEAST_EXPECT(!proofData.empty());
        
        // UPDATED: Use ProofData convenience method for verification
        bool isValid = zkp::ZkProver::verifyDepositProof(proofData);
        BEAST_EXPECT(isValid);
        
        // Test verification with wrong public inputs should fail
        zkp::FieldT wrongNullifier = proofData.nullifier + zkp::FieldT::one();
        bool wrongNullifierResult = zkp::ZkProver::verifyDepositProof(
            proofData.proof, proofData.anchor, wrongNullifier, proofData.value_commitment);
        BEAST_EXPECT(!wrongNullifierResult);
        
        // Test verification with empty proof
        std::vector<unsigned char> emptyProof;
        bool emptyResult = zkp::ZkProver::verifyDepositProof(
            emptyProof, proofData.anchor, proofData.nullifier, proofData.value_commitment);
        BEAST_EXPECT(!emptyResult);
    }
    
    void testWithdrawalProofVerification()
    {
        testcase("Withdrawal Proof Verification");
        
        // Ensure keys are generated
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        // Create test data
        uint64_t amount = 2000000;
        uint256 merkleRoot = generateRandomUint256();
        uint256 nullifier = generateRandomUint256();
        std::string spendKey = generateRandomSpendKey();
        
        // Create merkle path
        std::vector<uint256> merklePath;
        for (int i = 0; i < 2; ++i) {
            merklePath.push_back(generateRandomUint256());
        }
        size_t pathIndex = 1;
        
        // UPDATED: Create proof returns ProofData
        auto proofData = zkp::ZkProver::createWithdrawalProof(
            amount, merkleRoot, nullifier, merklePath, pathIndex, spendKey);
        BEAST_EXPECT(!proofData.empty());
        
        // UPDATED: Use ProofData convenience method for verification
        bool isValid = zkp::ZkProver::verifyWithdrawalProof(proofData);
        BEAST_EXPECT(isValid);
        
        // Test verification with wrong public inputs should fail
        zkp::FieldT wrongAnchor = proofData.anchor + zkp::FieldT::one();
        bool wrongAnchorResult = zkp::ZkProver::verifyWithdrawalProof(
            proofData.proof, wrongAnchor, proofData.nullifier, proofData.value_commitment);
        BEAST_EXPECT(!wrongAnchorResult);
    }
    
    void testInvalidProofVerification()
    {
        testcase("Invalid Proof Verification");
        
        // Ensure keys are generated
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        uint64_t amount = 1000000;
        uint256 commitment = generateRandomUint256();
        std::string spendKey = generateRandomSpendKey();
        
        // UPDATED: Create valid proof
        auto validProofData = zkp::ZkProver::createDepositProof(amount, commitment, spendKey);
        
        // Test corrupted proof data
        std::vector<unsigned char> corruptedProof = validProofData.proof;
        if (!corruptedProof.empty()) {
            corruptedProof[0] ^= 0xFF; // Flip bits in first byte
        }
        
        bool depositCorrupted = zkp::ZkProver::verifyDepositProof(
            corruptedProof, validProofData.anchor, validProofData.nullifier, validProofData.value_commitment);
        BEAST_EXPECT(!depositCorrupted);
        
        // Test oversized proof data
        std::vector<unsigned char> largeProof(10000, 0xFF);
        bool depositLarge = zkp::ZkProver::verifyDepositProof(
            largeProof, validProofData.anchor, validProofData.nullifier, validProofData.value_commitment);
        BEAST_EXPECT(!depositLarge);
    }
    
    void testMultipleProofs()
    {
        testcase("Multiple Proofs");
        
        // Ensure keys are generated
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        const size_t numProofs = 5;
        std::vector<zkp::ProofData> depositProofs;  // UPDATED: Store ProofData
        
        // Generate multiple proofs
        for (size_t i = 0; i < numProofs; ++i) {
            uint64_t amount = 1000000 + i * 100000;
            uint256 commitment = generateRandomUint256();
            std::string spendKey = generateRandomSpendKey();
            
            auto proofData = zkp::ZkProver::createDepositProof(amount, commitment, spendKey);
            BEAST_EXPECT(!proofData.empty());
            
            depositProofs.push_back(proofData);
        }
        
        // Verify each proof with correct public inputs
        for (size_t i = 0; i < numProofs; ++i) {
            bool isValid = zkp::ZkProver::verifyDepositProof(depositProofs[i]);  // UPDATED: Use convenience method
            BEAST_EXPECT(isValid);
        }
        
        // Cross-verify proofs with wrong public inputs (should fail)
        for (size_t i = 0; i < numProofs; ++i) {
            for (size_t j = 0; j < numProofs; ++j) {
                if (i != j) {
                    // Use proof from i but public inputs from j (should fail)
                    bool shouldFail = zkp::ZkProver::verifyDepositProof(
                        depositProofs[i].proof, 
                        depositProofs[j].anchor,          // Wrong public inputs
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
        
        // Ensure keys are generated
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        uint256 commitment = generateRandomUint256();
        std::string spendKey = generateRandomSpendKey();
        
        // Test with zero amount
        auto zeroProof = zkp::ZkProver::createDepositProof(0, commitment, spendKey);
        bool zeroValid = zkp::ZkProver::verifyDepositProof(zeroProof);  // UPDATED: Use convenience method
        BEAST_EXPECT(zeroValid);
        
        // Test with maximum amount
        uint64_t maxAmount = std::numeric_limits<uint64_t>::max();
        auto maxProof = zkp::ZkProver::createDepositProof(maxAmount, commitment, spendKey);
        bool maxValid = zkp::ZkProver::verifyDepositProof(maxProof);  // UPDATED: Use convenience method
        BEAST_EXPECT(maxValid);
    }
    
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
    }
};

BEAST_DEFINE_TESTSUITE(ZKProver, protocol, ripple);

}