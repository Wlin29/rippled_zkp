#include <xrpl/beast/unit_test.h>
#include <xrpl/protocol/UintTypes.h>
#include <filesystem>
#include <iostream>

#include "libxrpl/zkp/ZKProver.h"
#include "libxrpl/zkp/CommitmentGenerator.h"
#include "libxrpl/zkp/ShieldedMerkleTree.h"

namespace ripple {

class ZKProver_test : public beast::unit_test::suite
{
private:
    // Helper function to generate random uint256
    uint256 generateRandomUint256() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint8_t> dist(0, 255);
        
        uint256 result;
        for (size_t i = 0; i < 32; ++i) {
            result.begin()[i] = dist(gen);
        }
        return result;
    }
    
    // Helper function to generate random spend key
    std::string generateRandomSpendKey() {
        auto timestamp = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::high_resolution_clock::now().time_since_epoch()).count();
        return "test_spend_key_" + std::to_string(timestamp);
    }
    
    // Helper function to clean up test files
    void cleanupTestFiles(const std::string& basePath) {
        std::vector<std::string> suffixes = {"_deposit_pk", "_deposit_vk", "_withdrawal_pk", "_withdrawal_vk"};
        for (const auto& suffix : suffixes) {
            std::filesystem::remove(basePath + suffix);
        }
    }

public:
    void run() override
    {
        testInitialization();
        testKeyGeneration();
        testKeyPersistence();
        testBitConversions();
        testProofSerialization();
        testDepositProofCreation();
        testWithdrawalProofCreation();
        testDepositProofVerification();
        testWithdrawalProofVerification();
        testInvalidProofVerification();
        testMultipleProofs();
        testEdgeCases();
    }

    void testInitialization()
    {
        testcase("ZkProver Initialization");
        
        // Test that initialization works without throwing
        try {
            zkp::ZkProver::initialize();
            pass();
        }
        catch (std::exception& e) {
            fail(std::string("Initialization failed: ") + e.what());
        }
        
        // Test that multiple initializations are safe
        try {
            zkp::ZkProver::initialize();
            zkp::ZkProver::initialize();
            pass();
        }
        catch (std::exception& e) {
            fail(std::string("Multiple initialization failed: ") + e.what());
        }
        
        // Verify initialization state
        BEAST_EXPECT(zkp::ZkProver::isInitialized);
    }
    
    void testKeyGeneration()
    {
        testcase("Key Generation");
        
        // Test deposit key generation
        bool depositResult = zkp::ZkProver::generateDepositKeys(true);
        BEAST_EXPECT(depositResult);
        BEAST_EXPECT(zkp::ZkProver::depositProvingKey != nullptr);
        BEAST_EXPECT(zkp::ZkProver::depositVerificationKey != nullptr);
        
        // Test withdrawal key generation
        bool withdrawalResult = zkp::ZkProver::generateWithdrawalKeys(true);
        BEAST_EXPECT(withdrawalResult);
        BEAST_EXPECT(zkp::ZkProver::withdrawalProvingKey != nullptr);
        BEAST_EXPECT(zkp::ZkProver::withdrawalVerificationKey != nullptr);
        
        // Test combined key generation
        bool combinedResult = zkp::ZkProver::generateKeys(true);
        BEAST_EXPECT(combinedResult);
        
        // Test that keys aren't regenerated when they exist
        auto oldDepositPk = zkp::ZkProver::depositProvingKey;
        bool noRegenResult = zkp::ZkProver::generateDepositKeys(false);
        BEAST_EXPECT(noRegenResult);
        BEAST_EXPECT(zkp::ZkProver::depositProvingKey == oldDepositPk);
        
        // Test forced regeneration
        bool forceRegenResult = zkp::ZkProver::generateDepositKeys(true);
        BEAST_EXPECT(forceRegenResult);
        BEAST_EXPECT(zkp::ZkProver::depositProvingKey != oldDepositPk);
    }
    
    void testKeyPersistence()
    {
        testcase("Key Persistence");
        
        std::string testBasePath = "/tmp/rippled_test_zkp_keys_" + std::to_string(std::time(nullptr));
        
        // Generate keys
        BEAST_EXPECT(zkp::ZkProver::generateKeys(true));
        
        // Save keys
        bool saveResult = zkp::ZkProver::saveKeys(testBasePath);
        BEAST_EXPECT(saveResult);
        
        // Verify files were created
        BEAST_EXPECT(std::filesystem::exists(testBasePath + "_deposit_pk"));
        BEAST_EXPECT(std::filesystem::exists(testBasePath + "_deposit_vk"));
        BEAST_EXPECT(std::filesystem::exists(testBasePath + "_withdrawal_pk"));
        BEAST_EXPECT(std::filesystem::exists(testBasePath + "_withdrawal_vk"));
        
        // Store original keys for comparison
        auto originalDepositPk = zkp::ZkProver::depositProvingKey;
        auto originalDepositVk = zkp::ZkProver::depositVerificationKey;
        auto originalWithdrawalPk = zkp::ZkProver::withdrawalProvingKey;
        auto originalWithdrawalVk = zkp::ZkProver::withdrawalVerificationKey;
        
        // Clear keys
        zkp::ZkProver::depositProvingKey.reset();
        zkp::ZkProver::depositVerificationKey.reset();
        zkp::ZkProver::withdrawalProvingKey.reset();
        zkp::ZkProver::withdrawalVerificationKey.reset();
        
        // Load keys
        bool loadResult = zkp::ZkProver::loadKeys(testBasePath);
        BEAST_EXPECT(loadResult);
        
        // Verify keys were loaded
        BEAST_EXPECT(zkp::ZkProver::depositProvingKey != nullptr);
        BEAST_EXPECT(zkp::ZkProver::depositVerificationKey != nullptr);
        BEAST_EXPECT(zkp::ZkProver::withdrawalProvingKey != nullptr);
        BEAST_EXPECT(zkp::ZkProver::withdrawalVerificationKey != nullptr);
        
        // Test loading non-existent keys
        bool loadFailResult = zkp::ZkProver::loadKeys("/nonexistent/path");
        BEAST_EXPECT(!loadFailResult);
        
        // Clean up
        cleanupTestFiles(testBasePath);
    }
    
    void testBitConversions()
    {
        testcase("uint256 <-> Bits Conversion");
        
        // Test with known values 
        std::string hexValue1 = "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF";
        uint256 testValue1{hexValue1}; 
        
        std::vector<bool> bits1 = zkp::ZkProver::uint256ToBits(testValue1);
        BEAST_EXPECT(bits1.size() == 256);
        
        uint256 roundtrip1 = zkp::ZkProver::bitsToUint256(bits1);
        BEAST_EXPECT(testValue1 == roundtrip1);
        
        // Test with zero
        uint256 zero;  // Default constructor creates zero
        std::vector<bool> zeroBits = zkp::ZkProver::uint256ToBits(zero);
        uint256 zeroRoundtrip = zkp::ZkProver::bitsToUint256(zeroBits);
        BEAST_EXPECT(zero == zeroRoundtrip);
        
        // Test with all ones - Use constructor
        uint256 maxValue{"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"};  
        std::vector<bool> maxBits = zkp::ZkProver::uint256ToBits(maxValue);
        uint256 maxRoundtrip = zkp::ZkProver::bitsToUint256(maxBits);
        BEAST_EXPECT(maxValue == maxRoundtrip);
        
        // Test with random values
        for (int i = 0; i < 10; ++i) {
            uint256 randomValue = generateRandomUint256();
            std::vector<bool> randomBits = zkp::ZkProver::uint256ToBits(randomValue);
            uint256 randomRoundtrip = zkp::ZkProver::bitsToUint256(randomBits);
            BEAST_EXPECT(randomValue == randomRoundtrip);
        }
        
        // Test with partial bits (less than 256)
        std::vector<bool> partialBits(100, true);
        uint256 partialResult = zkp::ZkProver::bitsToUint256(partialBits);
        std::vector<bool> partialRoundtrip = zkp::ZkProver::uint256ToBits(partialResult);
        
        // First 100 bits should be true, rest false
        for (size_t i = 0; i < 100; ++i) {
            BEAST_EXPECT(partialRoundtrip[i] == true);
        }
        for (size_t i = 100; i < 256; ++i) {
            BEAST_EXPECT(partialRoundtrip[i] == false);
        }
    }
    
    void testProofSerialization()
    {
        testcase("Proof Serialization");
        
        // Generate keys first
        BEAST_EXPECT(zkp::ZkProver::generateKeys(true));
        
        // Create a test proof
        uint64_t testAmount = 1000000; // 1 XRP in drops
        uint256 testCommitment = generateRandomUint256();
        std::string testSpendKey = generateRandomSpendKey();
        
        std::vector<unsigned char> proofData = zkp::ZkProver::createDepositProof(
            testAmount, testCommitment, testSpendKey);
        
        BEAST_EXPECT(!proofData.empty());
        
        // Test that proof data is reasonable size (not too small or huge)
        BEAST_EXPECT(proofData.size() > 100); // Should be substantial
        BEAST_EXPECT(proofData.size() < 10000); // But not unreasonably large
        
        log << "Proof size: " << proofData.size() << " bytes";
    }
    
    void testDepositProofCreation()
    {
        testcase("Deposit Proof Creation");
        
        // Ensure keys are generated
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        // Test with various amounts
        std::vector<uint64_t> testAmounts = {0, 1, 1000000, 1000000000000ULL};
        
        for (uint64_t amount : testAmounts) {
            uint256 commitment = generateRandomUint256();
            std::string spendKey = generateRandomSpendKey();
            
            std::vector<unsigned char> proof = zkp::ZkProver::createDepositProof(
                amount, commitment, spendKey);
            
            BEAST_EXPECT(!proof.empty());
            log << "Deposit proof for amount " << amount << ": " << proof.size() << " bytes";
        }
        
        // Test with different commitments but same amount
        uint64_t fixedAmount = 1000000;
        std::string fixedSpendKey = generateRandomSpendKey();
        
        uint256 commitment1 = generateRandomUint256();
        uint256 commitment2 = generateRandomUint256();
        
        auto proof1 = zkp::ZkProver::createDepositProof(fixedAmount, commitment1, fixedSpendKey);
        auto proof2 = zkp::ZkProver::createDepositProof(fixedAmount, commitment2, fixedSpendKey);
        
        BEAST_EXPECT(!proof1.empty());
        BEAST_EXPECT(!proof2.empty());
        BEAST_EXPECT(proof1 != proof2); // Different commitments should give different proofs
    }
    
    void testWithdrawalProofCreation()
    {
        testcase("Withdrawal Proof Creation");
        
        // Ensure keys are generated
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        // Create test data
        uint64_t amount = 1000000;
        uint256 nullifier = generateRandomUint256();
        uint256 merkleRoot = generateRandomUint256();
        std::string spendKey = generateRandomSpendKey();
        
        // Create a mock Merkle path (depth 2)
        std::vector<uint256> merklePath;
        for (int i = 0; i < 2; ++i) {
            merklePath.push_back(generateRandomUint256());
        }
        size_t pathIndex = 1; // For depth 2, valid indices are 0, 1, 2, 3
        
        std::vector<unsigned char> proof = zkp::ZkProver::createWithdrawalProof(
            amount, nullifier, merkleRoot, merklePath, pathIndex, spendKey);
        
        BEAST_EXPECT(!proof.empty());
        log << "Withdrawal proof size: " << proof.size() << " bytes";
        
        // Test with different path indices
        for (size_t idx : {0, 1, 2, 3}) { // Valid indices for depth 2
            auto proofAtIndex = zkp::ZkProver::createWithdrawalProof(
                amount, nullifier, merkleRoot, merklePath, idx, spendKey);
            BEAST_EXPECT(!proofAtIndex.empty());
        }
    }
    
    void testDepositProofVerification()
    {
        testcase("Deposit Proof Verification");
        
        // Ensure keys are generated
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        // Create a valid proof
        uint64_t amount = 1000000;
        uint256 commitment = generateRandomUint256();
        std::string spendKey = generateRandomSpendKey();
        
        std::vector<unsigned char> proof = zkp::ZkProver::createDepositProof(
            amount, commitment, spendKey);
        BEAST_EXPECT(!proof.empty());
        
        // Verify the valid proof
        bool isValid = zkp::ZkProver::verifyDepositProof(proof, amount, commitment);
        BEAST_EXPECT(isValid);
        
        // Test verification with wrong amount
        bool wrongAmount = zkp::ZkProver::verifyDepositProof(proof, amount + 1, commitment);
        BEAST_EXPECT(!wrongAmount);
        
        // Test verification with wrong commitment
        uint256 wrongCommitment = generateRandomUint256();
        bool wrongCommit = zkp::ZkProver::verifyDepositProof(proof, amount, wrongCommitment);
        BEAST_EXPECT(!wrongCommit);
        
        // Test with empty proof
        std::vector<unsigned char> emptyProof;
        bool emptyResult = zkp::ZkProver::verifyDepositProof(emptyProof, amount, commitment);
        BEAST_EXPECT(!emptyResult);
    }
    
    void testWithdrawalProofVerification()
    {
        testcase("Withdrawal Proof Verification");
        
        // Ensure keys are generated
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        // Create test data
        uint64_t amount = 1000000;
        uint256 nullifier = generateRandomUint256();
        uint256 merkleRoot = generateRandomUint256();
        std::string spendKey = generateRandomSpendKey();
        
        std::vector<uint256> merklePath;
        for (int i = 0; i < 2; ++i) {
            merklePath.push_back(generateRandomUint256());
        }
        size_t pathIndex = 1;
        
        // Create a valid proof
        std::vector<unsigned char> proof = zkp::ZkProver::createWithdrawalProof(
            amount, nullifier, merkleRoot, merklePath, pathIndex, spendKey);
        BEAST_EXPECT(!proof.empty());
        
        // Verify the valid proof
        bool isValid = zkp::ZkProver::verifyWithdrawalProof(proof, amount, merkleRoot, nullifier);
        BEAST_EXPECT(isValid);
        
        // Test verification with wrong amount
        bool wrongAmount = zkp::ZkProver::verifyWithdrawalProof(proof, amount + 1, merkleRoot, nullifier);
        BEAST_EXPECT(!wrongAmount);
        
        // Test verification with wrong merkle root
        uint256 wrongRootValue = generateRandomUint256(); 
        bool wrongRootResult = zkp::ZkProver::verifyWithdrawalProof(proof, amount, wrongRootValue, nullifier);
        BEAST_EXPECT(!wrongRootResult);
        
        // Test verification with wrong nullifier
        uint256 wrongNullifier = generateRandomUint256();
        bool wrongNullResult = zkp::ZkProver::verifyWithdrawalProof(proof, amount, merkleRoot, wrongNullifier);
        BEAST_EXPECT(!wrongNullResult);
    }
    
    void testInvalidProofVerification()
    {
        testcase("Invalid Proof Verification");
        
        // Ensure keys are generated
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        uint64_t amount = 1000000;
        uint256 commitment = generateRandomUint256();
        uint256 nullifier = generateRandomUint256();
        uint256 merkleRoot = generateRandomUint256();
        
        // Test with corrupted proof data
        std::vector<unsigned char> corruptedProof = {0x00, 0x01, 0x02, 0x03, 0x04};
        
        bool depositCorrupted = zkp::ZkProver::verifyDepositProof(corruptedProof, amount, commitment);
        BEAST_EXPECT(!depositCorrupted);
        
        bool withdrawalCorrupted = zkp::ZkProver::verifyWithdrawalProof(corruptedProof, amount, merkleRoot, nullifier);
        BEAST_EXPECT(!withdrawalCorrupted);
        
        // Test with very large proof data
        std::vector<unsigned char> largeProof(100000, 0xFF);
        
        bool depositLarge = zkp::ZkProver::verifyDepositProof(largeProof, amount, commitment);
        BEAST_EXPECT(!depositLarge);
        
        bool withdrawalLarge = zkp::ZkProver::verifyWithdrawalProof(largeProof, amount, merkleRoot, nullifier);
        BEAST_EXPECT(!withdrawalLarge);
    }
    
    void testMultipleProofs()
    {
        testcase("Multiple Proof Operations");
        
        // Ensure keys are generated
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        // Create multiple proofs and verify they're all valid
        const int numProofs = 5;
        std::vector<std::vector<unsigned char>> depositProofs;
        std::vector<uint64_t> amounts;
        std::vector<uint256> commitments;
        std::vector<std::string> spendKeys;
        
        for (int i = 0; i < numProofs; ++i) {
            uint64_t amount = 1000000 * (i + 1);
            uint256 commitment = generateRandomUint256();
            std::string spendKey = generateRandomSpendKey();
            
            auto proof = zkp::ZkProver::createDepositProof(amount, commitment, spendKey);
            BEAST_EXPECT(!proof.empty());
            
            depositProofs.push_back(proof);
            amounts.push_back(amount);
            commitments.push_back(commitment);
            spendKeys.push_back(spendKey);
        }
        
        // Verify all proofs
        for (int i = 0; i < numProofs; ++i) {
            bool isValid = zkp::ZkProver::verifyDepositProof(
                depositProofs[i], amounts[i], commitments[i]);
            BEAST_EXPECT(isValid);
        }
        
        // Verify cross-validation fails (proof i with data j where i != j)
        for (int i = 0; i < numProofs; ++i) {
            for (int j = 0; j < numProofs; ++j) {
                if (i != j) {
                    bool shouldFail = zkp::ZkProver::verifyDepositProof(
                        depositProofs[i], amounts[j], commitments[j]);
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
        
        // Test with zero amount
        uint256 commitment = generateRandomUint256();
        std::string spendKey = generateRandomSpendKey();
        
        auto zeroProof = zkp::ZkProver::createDepositProof(0, commitment, spendKey);
        BEAST_EXPECT(!zeroProof.empty());
        
        bool zeroValid = zkp::ZkProver::verifyDepositProof(zeroProof, 0, commitment);
        BEAST_EXPECT(zeroValid);
        
        // Test with maximum uint64 amount
        uint64_t maxAmount = std::numeric_limits<uint64_t>::max();
        auto maxProof = zkp::ZkProver::createDepositProof(maxAmount, commitment, spendKey);
        BEAST_EXPECT(!maxProof.empty());
        
        bool maxValid = zkp::ZkProver::verifyDepositProof(maxProof, maxAmount, commitment);
        BEAST_EXPECT(maxValid);
        
        // Test with empty spend key
        std::string emptySpendKey = "";
        auto emptyKeyProof = zkp::ZkProver::createDepositProof(1000000, commitment, emptySpendKey);
        BEAST_EXPECT(!emptyKeyProof.empty());
        
        // Test with very long spend key
        std::string longSpendKey(1000, 'a');
        auto longKeyProof = zkp::ZkProver::createDepositProof(1000000, commitment, longSpendKey);
        BEAST_EXPECT(!longKeyProof.empty());
        
        // Test withdrawal with minimal path (should still work with depth 2)
        std::vector<uint256> minimalPath(2, uint256{});
        auto minimalProof = zkp::ZkProver::createWithdrawalProof(
            1000000, commitment, commitment, minimalPath, 0, spendKey);
        BEAST_EXPECT(!minimalProof.empty());
    }
};

BEAST_DEFINE_TESTSUITE(ZKProver, test, ripple);

} // namespace ripple