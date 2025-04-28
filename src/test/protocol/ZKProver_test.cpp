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
public:
    void run() override
    {
        testInitialization();
        testKeyGenerationAndPersistence();
        testDepositProof();
        testWithdrawalProof();
        testProofVerification();
        testBitConversions();
    }

    void testInitialization()
    {
        testcase("ZKProver Initialization");
        
        try {
            zkp::ZkProver::initialize();
            pass();
        }
        catch (std::exception& e) {
            fail(std::string("Initialization failed: ") + e.what());
        }
    }
    
    void testKeyGenerationAndPersistence()
    {
        testcase("Key Generation and Persistence");
        
        // Generate keys
        bool depositKeysGenerated = zkp::ZkProver::generateDepositKeys(true);
        bool withdrawalKeysGenerated = zkp::ZkProver::generateWithdrawalKeys(true);
        BEAST_EXPECT(depositKeysGenerated);
        BEAST_EXPECT(withdrawalKeysGenerated);
        
        // Save keys to temporary file
        std::string basePath = "/tmp/rippled_test_zkp_keys";
        bool saved = zkp::ZkProver::saveKeys(basePath);
        BEAST_EXPECT(saved);
        
        // Check files were created
        BEAST_EXPECT(std::filesystem::exists(basePath + "_deposit_pk"));
        BEAST_EXPECT(std::filesystem::exists(basePath + "_deposit_vk"));
        BEAST_EXPECT(std::filesystem::exists(basePath + "_withdrawal_pk"));
        BEAST_EXPECT(std::filesystem::exists(basePath + "_withdrawal_vk"));
        
        // Load keys
        bool loaded = zkp::ZkProver::loadKeys(basePath);
        BEAST_EXPECT(loaded);
        
        // Clean up
        std::filesystem::remove(basePath + "_deposit_pk");
        std::filesystem::remove(basePath + "_deposit_vk");
        std::filesystem::remove(basePath + "_withdrawal_pk");
        std::filesystem::remove(basePath + "_withdrawal_vk");
    }
    
    void testDepositProof()
    {
        testcase("Deposit Proof Creation");
        
        // Ensure keys are generated
        zkp::ZkProver::generateKeys();
        
        // Create test data
        uint64_t amount = 100000000; // 100 XRP
        auto aliceID = AccountID();
        auto commitment = zkp::CommitmentGenerator::generateCommitment(amount, aliceID).commitment;
        
        // Create a proof
        std::vector<unsigned char> proof = zkp::ZkProver::createDepositProof(
            amount, commitment, "test_spend_key");
        
        // Verify proof is not empty
        BEAST_EXPECT(!proof.empty());
        std::cout << "Deposit proof size: " << proof.size() << " bytes" << std::endl;
    }
    
    void testWithdrawalProof()
    {
        testcase("Withdrawal Proof Creation");
        
        // Ensure keys are generated
        zkp::ZkProver::generateKeys();
        
        // Create a Merkle tree and add a commitment
        ShieldedMerkleTree tree;
        uint64_t amount = 100000000; // 100 XRP
        auto aliceID = AccountID();
        auto commitmentData = zkp::CommitmentGenerator::generateCommitment(amount, aliceID);
        
        // Add commitment to the tree
        size_t index = tree.addCommitment(commitmentData.commitment);
        BEAST_EXPECT(index > 0);
        
        // Get Merkle path
        auto merklePath = tree.getPath(index);
        BEAST_EXPECT(!merklePath.empty());
        
        // Generate nullifier
        uint256 nullifier = zkp::CommitmentGenerator::generateNullifier(
            commitmentData.commitment, "test_spend_key");
        
        // Create a proof
        std::vector<unsigned char> proof = zkp::ZkProver::createWithdrawalProof(
            amount, nullifier, tree.getRoot(), merklePath, index, "test_spend_key");
        
        // Verify proof is not empty
        BEAST_EXPECT(!proof.empty());
        std::cout << "Withdrawal proof size: " << proof.size() << " bytes" << std::endl;
    }
    
    void testProofVerification()
    {
        testcase("Proof Verification");
        
        // Ensure keys are generated
        zkp::ZkProver::generateKeys();
        
        // Create test data
        uint64_t amount = 100000000; // 100 XRP
        auto aliceID = AccountID();
        auto commitmentData = zkp::CommitmentGenerator::generateCommitment(amount, aliceID);
        
        // Create a deposit proof
        std::vector<unsigned char> depositProof = zkp::ZkProver::createDepositProof(
            amount, commitmentData.commitment, "test_spend_key");
        
        // Verify the deposit proof
        bool depositVerified = zkp::ZkProver::verifyDepositProof(
            depositProof, amount, commitmentData.commitment);
        BEAST_EXPECT(depositVerified);
        
        // Test with invalid data - should fail
        bool invalidVerified = zkp::ZkProver::verifyDepositProof(
            depositProof, amount + 1, commitmentData.commitment); // Wrong amount
        BEAST_EXPECT(!invalidVerified);
        
        // Create a Merkle tree for withdrawal test
        ShieldedMerkleTree tree;
        size_t index = tree.addCommitment(commitmentData.commitment);
        auto merklePath = tree.getPath(index);
        uint256 nullifier = zkp::CommitmentGenerator::generateNullifier(
            commitmentData.commitment, "test_spend_key");
        
        // Create a withdrawal proof
        std::vector<unsigned char> withdrawalProof = zkp::ZkProver::createWithdrawalProof(
            amount, nullifier, tree.getRoot(), merklePath, index, "test_spend_key");
        
        // Verify the withdrawal proof
        bool withdrawalVerified = zkp::ZkProver::verifyWithdrawalProof(
            withdrawalProof, amount, tree.getRoot(), nullifier);
        BEAST_EXPECT(withdrawalVerified);
        
        // Test with invalid data - should fail
        bool invalidWithdrawalVerified = zkp::ZkProver::verifyWithdrawalProof(
            withdrawalProof, amount, tree.getRoot(), uint256()); // Wrong nullifier
        BEAST_EXPECT(!invalidWithdrawalVerified);
    }
    
    void testBitConversions()
    {
        testcase("uint256 <-> Bits Conversion");
        
        // Create a test uint256
        uint256 original;
        original = uint256{std::string("1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF")};
        
        // Convert to bits
        std::vector<bool> bits = zkp::ZkProver::uint256ToBits(original);
        BEAST_EXPECT(bits.size() == 256);
        
        // Convert back to uint256
        uint256 roundtrip = zkp::ZkProver::bitsToUint256(bits);
        
        // Verify roundtrip conversion works
        BEAST_EXPECT(original == roundtrip);
        
        // Test with a different value
        uint256 second;
        second = uint256{std::string("FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321")};
        bits = zkp::ZkProver::uint256ToBits(second);
        roundtrip = zkp::ZkProver::bitsToUint256(bits);
        BEAST_EXPECT(second == roundtrip);
        
        // Test with zero
        uint256 zero;
        bits = zkp::ZkProver::uint256ToBits(zero);
        roundtrip = zkp::ZkProver::bitsToUint256(bits);
        BEAST_EXPECT(zero == roundtrip);
    }
};

BEAST_DEFINE_TESTSUITE(ZKProver, ripple_app, ripple);

} // namespace ripple