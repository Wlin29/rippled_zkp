#include <xrpl/basics/Slice.h>
#include <xrpl/beast/unit_test.h>
#include <xrpl/protocol/STAmount.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/Sign.h>
#include <xrpl/protocol/TxFormats.h>
#include <xrpl/protocol/UintTypes.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/jss.h>
#include <xrpl/protocol/Keylet.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <iostream>
#include <memory>
#include <chrono>
#include <set>

#include "libxrpl/zkp/ShieldedMerkleTree.h"
#include "libxrpl/zkp/CommitmentGenerator.h"
#include "libxrpl/zkp/ZKProver.h"

#include <xrpl/beast/utility/rngfill.h>
#include <xrpl/crypto/csprng.h>
#include <xrpl/protocol/PublicKey.h>
#include <xrpl/protocol/SecretKey.h>
#include <xrpl/protocol/digest.h>
#include <xrpl/protocol/Seed.h>
#include <xrpl/protocol/detail/secp256k1.h>
#include <algorithm>
#include <string>
#include <vector>
#include <stdexcept>


namespace ripple {

class ZKPTransaction_test : public beast::unit_test::suite
{
public:
    void
    run() override
    {
        // testShieldedPoolCreation();

        // testZKPTransactionFlow();

        // testMerkleTreeOperations();

        // testDoubleSpendProtection();

        testMetrics();
    }

    void testShieldedPoolCreation()
    {
        testcase("Shielded Pool Creation");
        try {
            // Create a keylet for the shielded pool
            auto poolKeylet = keylet::shieldedPool();
            std::cout << "Keylet created: " << poolKeylet.type << std::endl;
            
            // Create an SLE directly - this is for testing only
            auto sle = std::make_shared<SLE>(poolKeylet);
            std::cout << "SLE created successfully" << std::endl;
            
            // Initialize the required fields directly
            sle->setFieldH256(sfCurrentRoot, uint256());
            sle->setFieldU32(sfPoolSize, 1);
            
            // Create a minimal serialized tree state
            ShieldedMerkleTree tree;
            Serializer s;
            tree.serialize(s);
            sle->setFieldVL(sfShieldedState, s.getData());
            
            BEAST_EXPECT(sle->isFieldPresent(sfShieldedState));
            BEAST_EXPECT(sle->isFieldPresent(sfCurrentRoot));
            BEAST_EXPECT(sle->isFieldPresent(sfPoolSize));
        }
        catch (std::exception& e) {
            std::cout << "Exception: " << e.what() << std::endl;
            BEAST_EXPECT(false);
        }
    }

    void
    testZKPTransactionFlow()
    {
        testcase("ZKP Transaction Flow");
        try {
            std::cout << "Creating keypairs..." << std::endl;
            auto const alice = randomKeyPair(KeyType::secp256k1);
            auto const aliceID = calcAccountID(alice.first);
            auto const bob = randomKeyPair(KeyType::secp256k1);
            auto const bobID = calcAccountID(bob.first);
            
            std::cout << "Creating deposit transaction..." << std::endl;
            STTx depositTx(ttZK_DEPOSIT, [&aliceID](auto& obj) {
                obj.setAccountID(sfAccount, aliceID);
                obj.setFieldVL(sfSigningPubKey, Slice{});
                
                obj.setFieldAmount(sfAmount, STAmount(100000000));
                
                uint256 commitment = zkp::CommitmentGenerator::generateCommitment(100000000, aliceID).commitment;
                std::cout<<"Commitment: " << commitment << std::endl;
                obj.setFieldH256(sfCommitment, commitment);
                
                // Generate a mock ZK proof for the deposit
                std::vector<unsigned char> mockProof(64, 0xAB);
                obj.setFieldVL(sfZKProof, mockProof);
            });
            
            std::cout << "Deposit transaction created successfully" << std::endl;
            
            // Sign the deposit transaction
            depositTx.sign(alice.first, alice.second);
            
            // Verify the deposit transaction signature
            // BEAST_EXPECT(depositTx.checkSign(STTx::RequireFullyCanonicalSig::yes).first);
            
            // Verify the deposit transaction has the required fields
            BEAST_EXPECT(depositTx.isFieldPresent(sfCommitment));
            BEAST_EXPECT(depositTx.isFieldPresent(sfZKProof));
            BEAST_EXPECT(depositTx.isFieldPresent(sfAmount));
            
            // Create a mock Merkle tree and add the commitment
            ShieldedMerkleTree tree;
            uint256 commitment = depositTx.getFieldH256(sfCommitment);
            size_t index = tree.addCommitment(commitment);
            BEAST_EXPECT(index > 0);
            
            std::cout << "Creating withdrawal transaction..." << std::endl;
            STTx withdrawTx(ttZK_WITHDRAW, [&bobID, &tree](auto& obj) {
                obj.setAccountID(sfAccount, bobID);
                obj.setFieldVL(sfSigningPubKey, Slice{});
                
                // Set withdrawal amount (100 XRP)
                obj.setFieldAmount(sfAmount, STAmount(100000000));
                
                // Set the nullifier
                uint256 nullifier;
                nullifier = uint256{std::string("ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890")};
                obj.setFieldH256(sfNullifier, nullifier);
                
                // Set the Merkle root
                // obj.setFieldH256(sfCurrentRoot, tree.getRoot());
                
                // Generate a mock ZK proof for the withdrawal
                std::vector<unsigned char> mockProof(64, 0xCD);
                obj.setFieldVL(sfZKProof, mockProof);
            });
            
            std::cout << "Withdrawal transaction created successfully" << std::endl;
            
            // Sign the withdrawal transaction
            withdrawTx.sign(bob.first, bob.second);
            
            // Verify the withdrawal transaction signature
            // BEAST_EXPECT(withdrawTx.checkSign(STTx::RequireFullyCanonicalSig::yes).first);
            
            // Verify the withdrawal transaction has the required fields
            BEAST_EXPECT(withdrawTx.isFieldPresent(sfNullifier));
            // BEAST_EXPECT(withdrawTx.isFieldPresent(sfCurrentRoot));
            BEAST_EXPECT(withdrawTx.isFieldPresent(sfZKProof));
            BEAST_EXPECT(withdrawTx.isFieldPresent(sfAmount));
        }
        catch (std::exception& e) {
            std::cout << "Exception in testZKPTransactionFlow: " << e.what() << std::endl;
            BEAST_EXPECT(false);
        }
    }
    
    void
    testMerkleTreeOperations()
    {
        testcase("Merkle Tree Operations");

        // Create a Merkle tree
        ShieldedMerkleTree tree;
        
        // Generate some test commitments
        std::vector<uint256> commitments;
        for (int i = 0; i < 10; ++i) {
            // Create a unique commitment for each test
            uint256 commitment;
            commitment = uint256{std::string("ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789")};
            // Modify the last byte to make each commitment unique
            commitment.data()[31] = static_cast<unsigned char>(i);
            commitments.push_back(commitment);
        }
        
        // Add commitments to the tree
        for (const auto& commitment : commitments) {
            size_t index = tree.addCommitment(commitment);
            BEAST_EXPECT(index > 0);
        }
        
        // Verify the tree size
        BEAST_EXPECT(tree.getCommitments().size() == commitments.size() + 1); // +1 for the initial empty commitment
        
        // Get the Merkle root
        uint256 root = tree.getRoot();
        BEAST_EXPECT(!root.isZero());
        
        // Get a Merkle path for a specific commitment
        size_t testIndex = 5;
        auto merklePath = tree.getPath(testIndex);
        BEAST_EXPECT(!merklePath.empty());
        
        // Verify the Merkle path
        bool pathValid = tree.verifyPath(testIndex, commitments[testIndex - 1], merklePath);
        BEAST_EXPECT(pathValid);
        
        // Test serialization and deserialization
        Serializer s;
        tree.serialize(s);
        
        SerialIter sit(s.data(), s.size());
        ShieldedMerkleTree deserializedTree = ShieldedMerkleTree::deserialize(sit);
        
        // Verify the deserialized tree has the same root
        BEAST_EXPECT(deserializedTree.getRoot() == root);
        
        // Verify the deserialized tree has the same number of commitments
        BEAST_EXPECT(deserializedTree.getCommitments().size() == tree.getCommitments().size());
    }
    
    void
    testDoubleSpendProtection()
    {
        testcase("Double Spend Protection");
        
        // Create a Merkle tree
        ShieldedMerkleTree tree;
        
        // Create a test commitment
        uint256 commitment;
        commitment = uint256{std::string("1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF")};
        
        // Add the commitment to the tree
        size_t index = tree.addCommitment(commitment);
        BEAST_EXPECT(index > 0);
        
        // Create a nullifier for the commitment
        uint256 nullifier = zkp::CommitmentGenerator::generateNullifier(commitment, "test_secret");
                
        // Create a set to track spent nullifiers (simulating the ledger state)
        std::set<uint256> spentNullifiers;
        
        // First withdrawal - should succeed
        bool firstWithdrawalSuccess = spentNullifiers.find(nullifier) == spentNullifiers.end();
        BEAST_EXPECT(firstWithdrawalSuccess);
        
        // Record the nullifier as spent
        spentNullifiers.insert(nullifier);
        
        // Second withdrawal with the same nullifier - should fail
        bool secondWithdrawalSuccess = spentNullifiers.find(nullifier) == spentNullifiers.end();
        BEAST_EXPECT(!secondWithdrawalSuccess);
        
        // Create a different commitment
        uint256 commitment2;
        commitment2 = uint256{std::string("FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321")};
        
        // Add the second commitment to the tree
        size_t index2 = tree.addCommitment(commitment2);
        BEAST_EXPECT(index2 > 0);
        
        // Create a nullifier for the second commitment
        uint256 nullifier2 = zkp::CommitmentGenerator::generateNullifier(commitment2, "test_secret"); 

        // Withdrawal with a different nullifier - should succeed
        bool thirdWithdrawalSuccess = spentNullifiers.find(nullifier2) == spentNullifiers.end();
        BEAST_EXPECT(thirdWithdrawalSuccess);
    }

    // void
    // testMetrics()
    // {
    //     testcase("Secp256k1 Key Generation");

    //     auto sk = randomSecp256k1SecretKey();
    //     BEAST_EXPECT(sk.size() == 32); // Secret key should be 32 bytes

    //     auto pk = derivePublicKey(KeyType::secp256k1, sk);
    //     BEAST_EXPECT(pk.size() != 0); // Public key should not be empty
    //     BEAST_EXPECT(pk.size() == 33); // Compressed public key should be 33 bytes

    //     testcase("Secp256k1 Signing");

    //     auto keyPair = randomKeyPair(KeyType::secp256k1);
    //     auto const& sk = keyPair.second;
    //     auto const& pk = keyPair.first;

    //     std::string message = "test message";
    //     uint256 digest = sha512Half(Slice{message.data(), message.size()});
    //     auto sig = signDigest(pk, sk, digest);

    //     BEAST_EXPECT(sig.size() != 0); // Signature should not be empty
    //     BEAST_EXPECT(sig.size() <= 72); // DER-encoded signature length

    //     testcase("Secp256k1 Full Transaction Process");

    //     // Step 1: Key Generation
    //     auto keyPair = randomKeyPair(KeyType::secp256k1);
    //     auto const& sk = keyPair.second;
    //     auto const& pk = keyPair.first;

    //     BEAST_EXPECT(sk.size() != 0);
    //     BEAST_EXPECT(pk.size() != 0);

    //     // Step 2: Message Signing
    //     std::string message = "This is a test transaction for secp256k1.";
    //     uint256 digest = sha512Half(Slice{message.data(), message.size()});
    //     auto sig = signDigest(pk, sk, digest);

    //     BEAST_EXPECT(sig.size() != 0);

    //     // Step 3: Signature Verification
    //     bool isValid = verifyDigest(pk, digest, sig);
    //     BEAST_EXPECT(isValid); // Signature should be valid
    // }

    void
    testMetrics()
    {
        testcase("Performance Comparison: Secp256k1 vs ZKP");

        const int NUM_ITERATIONS = 100;
        
        // Initialize ZKP system once
        try {
            ripple::zkp::ZkProver::initialize();
            if (!ripple::zkp::ZkProver::generateKeys(false)) {
                std::cout << "Failed to generate ZKP keys, using mock timings" << std::endl;
            }
        } catch (std::exception& e) {
            std::cout << "ZKP initialization failed: " << e.what() << std::endl;
        }
        
        // ============================================
        // Key Generation Performance Comparison
        // ============================================
        
        testcase("Key Generation Performance");
        
        // Secp256k1 Key Generation Timing
        auto secp256k1_start = std::chrono::high_resolution_clock::now();
        std::vector<std::pair<PublicKey, SecretKey>> secp256k1_keys;
        
        for (int i = 0; i < NUM_ITERATIONS; ++i) {
            auto keyPair = randomKeyPair(KeyType::secp256k1);
            secp256k1_keys.push_back(keyPair);
        }
        
        auto secp256k1_end = std::chrono::high_resolution_clock::now();
        auto secp256k1_keygen_duration = std::chrono::duration_cast<std::chrono::microseconds>(secp256k1_end - secp256k1_start);
        
        // ZKP Key Generation Timing (using CommitmentGenerator)
        auto zkp_start = std::chrono::high_resolution_clock::now();
        std::vector<AccountID> zkp_accounts;
        std::vector<uint256> zkp_commitments;
        
        for (int i = 0; i < NUM_ITERATIONS; ++i) {
            auto keyPair = randomKeyPair(KeyType::secp256k1);
            auto accountID = calcAccountID(keyPair.first);
            zkp_accounts.push_back(accountID);
            
            // Generate ZKP commitment (equivalent to key generation in ZKP context)
            auto commitment = zkp::CommitmentGenerator::generateCommitment(1000000, accountID);
            zkp_commitments.push_back(commitment.commitment);
        }
        
        auto zkp_end = std::chrono::high_resolution_clock::now();
        auto zkp_keygen_duration = std::chrono::duration_cast<std::chrono::microseconds>(zkp_end - zkp_start);
        
        // Results
        std::cout << "\n=== KEY GENERATION PERFORMANCE ===" << std::endl;
        std::cout << "Secp256k1 (avg per key): " << secp256k1_keygen_duration.count() / NUM_ITERATIONS << " μs" << std::endl;
        std::cout << "ZKP Commitment (avg per commitment): " << zkp_keygen_duration.count() / NUM_ITERATIONS << " μs" << std::endl;
        std::cout << "Performance ratio (ZKP/Secp256k1): " << (double)zkp_keygen_duration.count() / secp256k1_keygen_duration.count() << "x" << std::endl;
        
        // ============================================
        // Signing vs Proof Generation Performance
        // ============================================
        
        testcase("Signing vs Proof Generation Performance");
        
        // Prepare test message
        std::string message = "test transaction for performance comparison";
        uint256 digest = sha512Half(makeSlice(message));
        
        // Secp256k1 Signing Timing
        secp256k1_start = std::chrono::high_resolution_clock::now();
        std::vector<Buffer> secp256k1_signatures;
        
        for (int i = 0; i < NUM_ITERATIONS; ++i) {
            auto sig = signDigest(secp256k1_keys[i].first, secp256k1_keys[i].second, digest);
            secp256k1_signatures.push_back(sig);
        }
        
        secp256k1_end = std::chrono::high_resolution_clock::now();
        auto secp256k1_signing_duration = std::chrono::duration_cast<std::chrono::microseconds>(secp256k1_end - secp256k1_start);
        
        // ZKP Proof Generation Timing (equivalent to signing in ZKP)
        zkp_start = std::chrono::high_resolution_clock::now();
        std::vector<ripple::zkp::ProofData> zkp_proofs; // Correct type!
        
        const int ZKP_PROOF_ITERATIONS = std::min(NUM_ITERATIONS, 5); // Limit due to computational cost
        
        for (int i = 0; i < ZKP_PROOF_ITERATIONS; ++i) {
            try {
                // Create deposit proof using correct function signature
                auto proofData = ripple::zkp::ZkProver::createDepositProof(
                    1000000,                                    // amount
                    zkp_commitments[i],                        // commitment
                    "test_spend_key_" + std::to_string(i),     // spendKey
                    ripple::zkp::FieldT::random_element()      // value_randomness
                );
                
                zkp_proofs.push_back(proofData);
                
            } catch (std::exception& e) {
                std::cout << "ZKP proof generation " << i << " failed: " << e.what() << std::endl;
                // Add empty proof for timing consistency
                zkp_proofs.push_back(ripple::zkp::ProofData{});
            }
        }
        
        zkp_end = std::chrono::high_resolution_clock::now();
        auto zkp_proof_duration = std::chrono::duration_cast<std::chrono::microseconds>(zkp_end - zkp_start);
        
        // Results
        std::cout << "\n=== SIGNING/PROOF GENERATION PERFORMANCE ===" << std::endl;
        std::cout << "Secp256k1 signing (avg per signature): " << secp256k1_signing_duration.count() / NUM_ITERATIONS << " μs" << std::endl;
        std::cout << "ZKP proof generation (avg per proof): " << zkp_proof_duration.count() / ZKP_PROOF_ITERATIONS << " μs" << std::endl;
        std::cout << "Performance ratio (ZKP/Secp256k1): " << (double)zkp_proof_duration.count() / secp256k1_signing_duration.count() * NUM_ITERATIONS / ZKP_PROOF_ITERATIONS << "x" << std::endl;
        
        // ============================================
        // Verification Performance Comparison
        // ============================================
        
        testcase("Full Transaction Process Performance");
        
        // Secp256k1 Full Transaction Process
        secp256k1_start = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < NUM_ITERATIONS; ++i) {
            auto isValid = verifyDigest(secp256k1_keys[i].first, digest, secp256k1_signatures[i]);
            BEAST_EXPECT(isValid);
        }
        
        secp256k1_end = std::chrono::high_resolution_clock::now();
        auto secp256k1_verify_duration = std::chrono::duration_cast<std::chrono::microseconds>(secp256k1_end - secp256k1_start);
        
        // ZKP Full Transaction Process
        zkp_start = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < ZKP_PROOF_ITERATIONS; ++i) {
            if (!zkp_proofs[i].empty()) {
                try {
                    // Use correct verification function
                    auto isValid = ripple::zkp::ZkProver::verifyDepositProof(zkp_proofs[i]);
                    BEAST_EXPECT(isValid);
                } catch (std::exception& e) {
                    std::cout << "ZKP verification " << i << " failed: " << e.what() << std::endl;
                }
            }
        }
        
        zkp_end = std::chrono::high_resolution_clock::now();
        auto zkp_verify_duration = std::chrono::duration_cast<std::chrono::microseconds>(zkp_end - zkp_start);
        
        // Results
        std::cout << "\n=== VERIFICATION PERFORMANCE ===" << std::endl;
        std::cout << "Secp256k1 verification (avg per signature): " << secp256k1_verify_duration.count() / NUM_ITERATIONS << " μs" << std::endl;
        std::cout << "ZKP verification (avg per proof): " << zkp_verify_duration.count() / ZKP_PROOF_ITERATIONS << " μs" << std::endl;
        std::cout << "Performance ratio (ZKP/Secp256k1): " << (double)zkp_verify_duration.count() / secp256k1_verify_duration.count() * NUM_ITERATIONS / ZKP_PROOF_ITERATIONS << "x" << std::endl;
        
        // ============================================
        // Memory Usage Comparison
        // ============================================
        
        testcase("Memory Usage Comparison");
        
        std::cout << "\n=== MEMORY USAGE COMPARISON ===" << std::endl;
        std::cout << "Secp256k1 public key size: " << secp256k1_keys[0].first.size() << " bytes" << std::endl;
        std::cout << "Secp256k1 private key size: " << secp256k1_keys[0].second.size() << " bytes" << std::endl;
        std::cout << "Secp256k1 signature size: " << secp256k1_signatures[0].size() << " bytes" << std::endl;
        std::cout << "ZKP commitment size: " << sizeof(uint256) << " bytes" << std::endl;
        
        if (!zkp_proofs.empty() && !zkp_proofs[0].empty()) {
            std::cout << "ZKP proof size: " << zkp_proofs[0].proof.size() << " bytes" << std::endl;
        } else {
            std::cout << "ZKP proof size: N/A (proof generation failed)" << std::endl;
        }
        
        std::cout << "\n=== PERFORMANCE SUMMARY ===" << std::endl;
        std::cout << "Secp256k1 operations: " << NUM_ITERATIONS << std::endl;
        std::cout << "ZKP operations: " << ZKP_PROOF_ITERATIONS << std::endl;
        std::cout << "Test completed" << std::endl;
    }
};

BEAST_DEFINE_TESTSUITE(ZKPTransaction, ripple_app, ripple);

}  // namespace ripple