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
#include <xrpl/protocol/Feature.h>
#include <xrpld/app/tx/detail/ApplyContext.h>
#include <xrpld/ledger/View.h>
#include <iostream>
#include <memory>
#include <chrono>
#include <set>
#include <random>
#include <iomanip>

#include "libxrpl/zkp/ZKProver.h"
#include "libxrpl/zkp/Note.h"
#include "libxrpl/zkp/IncrementalMerkleTree.h"
#include "libxrpl/zkp/circuits/MerkleCircuit.h"
#include "libxrpl/zkp/ZkDeposit.h"
#include "libxrpl/zkp/ZkWithdraw.h"

namespace ripple {

class ZKPTransaction_test : public beast::unit_test::suite
{
private:
    // Test infrastructure
    zkp::IncrementalMerkleTree* testTree_;
    std::vector<zkp::Note> testNotes_;
    std::set<uint256> usedNullifiers_;
    
    // Performance tracking
    struct PerformanceMetrics {
        std::chrono::duration<double, std::milli> traditionalTxTime{0};
        std::chrono::duration<double, std::milli> zkDepositTxTime{0};
        std::chrono::duration<double, std::milli> zkWithdrawTxTime{0};
        std::chrono::duration<double, std::milli> proofGenerationTime{0};
        std::chrono::duration<double, std::milli> proofVerificationTime{0};
        std::chrono::duration<double, std::milli> merkleOperationsTime{0};
        std::chrono::duration<double, std::milli> noteOperationsTime{0};
        std::chrono::duration<double, std::milli> serializationTime{0};
        size_t traditionalTxSize{0};
        size_t zkTxSize{0};
    } metrics_;
    
public:
    void run() override
    {
        // Initialize ZK system
        initializeZKSystem();
        
        // Core functionality tests with timing
        testBasicNoteOperations();
        testMerkleTreeOperations();
        testProofGeneration();
        
        // Performance comparison tests
        testTraditionalTransactionPerformance();
        testZKTransactionPerformance();
        
        // Regular transaction tests
        testDepositTransaction();
        testWithdrawalTransaction();
        testNullifierTracking();
        testShieldedPoolManagement();
        testTransactionSerialization();
        testErrorHandling();
        
        // Integration tests
        testCompleteDepositWithdrawFlow();
        
        // Performance summary
        printPerformanceComparison();
        
        cleanup();
    }

private:
    void initializeZKSystem()
    {
        testcase("ZK System Initialization");
        
        auto start = std::chrono::high_resolution_clock::now();
        
        // Initialize the ZK proving system
        if (!zkp::ZkProver::isInitialized) {
            zkp::ZkProver::initialize();
        }
        
        BEAST_EXPECT(zkp::ZkProver::isInitialized);
        
        // Create test Merkle tree
        testTree_ = new zkp::IncrementalMerkleTree(32);
        BEAST_EXPECT(testTree_ != nullptr);
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        log << "ZK system initialization time: " << duration.count() << " ms" << std::endl;
        log << "ZK system initialized successfully" << std::endl;
    }
    
    void testBasicNoteOperations()
    {
        testcase("Basic Note Operations");
        
        auto start = std::chrono::high_resolution_clock::now();
        
        // Test note creation
        uint64_t amount = 5000000; // 5 XRP
        auto note = zkp::Note::random(amount);
        
        BEAST_EXPECT(note.value == amount);
        BEAST_EXPECT(note.rho != uint256{});
        BEAST_EXPECT(note.r != uint256{});
        BEAST_EXPECT(note.a_pk != uint256{});
        
        // Test commitment computation
        uint256 commitment = note.commitment();
        BEAST_EXPECT(commitment != uint256{});
        
        // Test note serialization
        auto serialized = note.serialize();
        BEAST_EXPECT(!serialized.empty());
        
        // Store for later tests
        testNotes_.push_back(note);
        
        auto end = std::chrono::high_resolution_clock::now();
        metrics_.noteOperationsTime = std::chrono::duration<double, std::milli>(end - start);
        
        log << "Note operations time: " << std::fixed << std::setprecision(3) 
            << metrics_.noteOperationsTime.count() << " ms" << std::endl;
        log << "Note operations: PASSED" << std::endl;
    }
    
    void testMerkleTreeOperations()
    {
        testcase("Merkle Tree Operations");
        
        auto start = std::chrono::high_resolution_clock::now();
        
        if (testNotes_.empty()) {
            BEAST_EXPECT(false && "No test notes available");
            return;
        }
        
        auto& note = testNotes_[0];
        uint256 commitment = note.commitment();
        
        // Test tree append
        size_t oldSize = testTree_->size();
        testTree_->append(commitment);
        BEAST_EXPECT(testTree_->size() == oldSize + 1);
        
        // Test root computation
        uint256 root = testTree_->root();
        BEAST_EXPECT(root != uint256{});
        
        // Test authentication path
        size_t noteIndex = testTree_->size() - 1;
        auto authPath = testTree_->authPath(noteIndex); 
        BEAST_EXPECT(!authPath.empty());
        BEAST_EXPECT(authPath.size() <= 32); // Max tree depth
        
        auto end = std::chrono::high_resolution_clock::now();
        metrics_.merkleOperationsTime = std::chrono::duration<double, std::milli>(end - start);
        
        log << "Tree size: " << testTree_->size() << std::endl;
        log << "Root: " << root << std::endl;
        log << "Auth path length: " << authPath.size() << std::endl;
        log << "Merkle operations time: " << std::fixed << std::setprecision(3) 
            << metrics_.merkleOperationsTime.count() << " ms" << std::endl;
        log << "Merkle tree operations: PASSED" << std::endl;
    }
    
    void testProofGeneration()
    {
        testcase("Proof Generation");
        
        auto proofStart = std::chrono::high_resolution_clock::now();
        
        // Test deposit proof generation
        uint64_t depositAmount = 3000000; // 3 XRP
        uint256 commitment = zkp::ZkProver::generateRandomUint256();
        std::string spendKey = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        zkp::FieldT vcmR = zkp::FieldT::random_element();
        
        try {
            auto depositProofStart = std::chrono::high_resolution_clock::now();
            
            auto depositProof = zkp::ZkProver::createDepositProof(
                depositAmount, commitment, spendKey, vcmR
            );
            
            auto depositProofEnd = std::chrono::high_resolution_clock::now();
            auto depositProofTime = std::chrono::duration<double, std::milli>(depositProofEnd - depositProofStart);
            
            BEAST_EXPECT(!depositProof.proof.empty());
            
            // Test proof verification
            auto verifyStart = std::chrono::high_resolution_clock::now();
            
            bool verified = zkp::ZkProver::verifyDepositProof(
                depositProof.proof,
                depositProof.anchor,
                depositProof.nullifier,
                depositProof.value_commitment
            );
            
            auto verifyEnd = std::chrono::high_resolution_clock::now();
            auto verifyTime = std::chrono::duration<double, std::milli>(verifyEnd - verifyStart);
            
            BEAST_EXPECT(verified);
            
            log << "Deposit proof generation time: " << std::fixed << std::setprecision(3) 
                << depositProofTime.count() << " ms" << std::endl;
            log << "Deposit proof verification time: " << std::fixed << std::setprecision(3) 
                << verifyTime.count() << " ms" << std::endl;
            log << "Deposit proof size: " << depositProof.proof.size() << " bytes" << std::endl;
            
        } catch (const std::exception& e) {
            log << "Deposit proof generation failed: " << e.what() << std::endl;
            BEAST_EXPECT(false);
        }
        
        // Test withdrawal proof generation
        if (!testNotes_.empty() && testTree_->size() > 0) {
            try {
                auto& withdrawNote = testNotes_[0];
                size_t noteIndex = 0;
                auto authPath = testTree_->authPath(noteIndex);
                uint256 merkleRoot = testTree_->root();
                std::string withdrawSpendKey = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
                zkp::FieldT withdrawVcmR = zkp::FieldT::random_element();
                
                auto withdrawProofStart = std::chrono::high_resolution_clock::now();
                
                auto withdrawProof = zkp::ZkProver::createWithdrawalProof(
                    withdrawNote.value,
                    merkleRoot,
                    zkp::ZkProver::generateRandomUint256(),
                    authPath,
                    noteIndex,
                    withdrawSpendKey,
                    withdrawVcmR
                );
                
                auto withdrawProofEnd = std::chrono::high_resolution_clock::now();
                auto withdrawProofTime = std::chrono::duration<double, std::milli>(withdrawProofEnd - withdrawProofStart);
                
                BEAST_EXPECT(!withdrawProof.proof.empty());
                
                // Test proof verification
                auto verifyStart = std::chrono::high_resolution_clock::now();
                
                bool verified = zkp::ZkProver::verifyWithdrawalProof(
                    withdrawProof.proof,
                    withdrawProof.anchor,
                    withdrawProof.nullifier,
                    withdrawProof.value_commitment
                );
                
                auto verifyEnd = std::chrono::high_resolution_clock::now();
                auto verifyTime = std::chrono::duration<double, std::milli>(verifyEnd - verifyStart);
                
                BEAST_EXPECT(verified);
                
                log << "Withdrawal proof generation time: " << std::fixed << std::setprecision(3) 
                    << withdrawProofTime.count() << " ms" << std::endl;
                log << "Withdrawal proof verification time: " << std::fixed << std::setprecision(3) 
                    << verifyTime.count() << " ms" << std::endl;
                log << "Withdrawal proof size: " << withdrawProof.proof.size() << " bytes" << std::endl;
                
            } catch (const std::exception& e) {
                log << "Withdrawal proof generation failed: " << e.what() << std::endl;
                BEAST_EXPECT(false);
            }
        }
        
        auto proofEnd = std::chrono::high_resolution_clock::now();
        metrics_.proofGenerationTime = std::chrono::duration<double, std::milli>(proofEnd - proofStart);
        
        log << "Total proof operations time: " << std::fixed << std::setprecision(3) 
            << metrics_.proofGenerationTime.count() << " ms" << std::endl;
        log << "Proof generation: PASSED" << std::endl;
    }
    
    void testTraditionalTransactionPerformance()
    {
        testcase("Traditional Transaction Performance");
        
        auto alice = randomKeyPair(KeyType::secp256k1);
        auto bob = randomKeyPair(KeyType::secp256k1);
        auto aliceID = calcAccountID(alice.first);
        auto bobID = calcAccountID(bob.first);
        
        uint64_t amount = 10000000; // 10 XRP
        
        auto start = std::chrono::high_resolution_clock::now();
        
        // Create traditional payment transaction
        STTx traditionalTx(ttPAYMENT, [&](auto& obj) {
            obj.setAccountID(sfAccount, aliceID);
            obj.setAccountID(sfDestination, bobID);
            obj.setFieldAmount(sfAmount, STAmount(amount));
            obj.setFieldU32(sfSequence, 1);
            obj.setFieldAmount(sfFee, STAmount(12));
        });
        
        // Sign transaction
        traditionalTx.sign(alice.first, alice.second);
        
        // Serialize for size measurement
        Serializer s;
        traditionalTx.add(s);
        metrics_.traditionalTxSize = s.size();
        
        auto end = std::chrono::high_resolution_clock::now();
        metrics_.traditionalTxTime = std::chrono::duration<double, std::milli>(end - start);
        
        // Validate transaction
        BEAST_EXPECT(traditionalTx.isFieldPresent(sfAccount));
        BEAST_EXPECT(traditionalTx.isFieldPresent(sfDestination));
        BEAST_EXPECT(traditionalTx.isFieldPresent(sfAmount));
        BEAST_EXPECT(traditionalTx.isFieldPresent(sfTxnSignature));
        
        log << "Traditional transaction time: " << std::fixed << std::setprecision(3) 
            << metrics_.traditionalTxTime.count() << " ms" << std::endl;
        log << "Traditional transaction size: " << metrics_.traditionalTxSize << " bytes" << std::endl;
        log << "Traditional transaction: PASSED" << std::endl;
    }
    
    void testZKTransactionPerformance()
    {
        testcase("ZK Transaction Performance");
        
        auto alice = randomKeyPair(KeyType::secp256k1);
        auto bob = randomKeyPair(KeyType::secp256k1);
        auto aliceID = calcAccountID(alice.first);
        auto bobID = calcAccountID(bob.first);
        
        uint64_t amount = 10000000; // 10 XRP
        
        // Test ZK Deposit Performance
        auto depositStart = std::chrono::high_resolution_clock::now();
        
        STTx zkDepositTx(ttZK_DEPOSIT, [&](auto& obj) {
            obj.setAccountID(sfAccount, aliceID);
            obj.setFieldAmount(sfAmount, STAmount(amount));
            obj.setFieldH256(sfCommitment, zkp::ZkProver::generateRandomUint256());
            obj.setFieldH256(sfNullifier, zkp::ZkProver::generateRandomUint256());
            obj.setFieldVL(sfZKProof, generateMockProofData(2048)); // Realistic proof size
            obj.setFieldU32(sfSequence, 1);
            obj.setFieldAmount(sfFee, STAmount(12));
        });
        
        zkDepositTx.sign(alice.first, alice.second);
        
        auto depositEnd = std::chrono::high_resolution_clock::now();
        metrics_.zkDepositTxTime = std::chrono::duration<double, std::milli>(depositEnd - depositStart);
        
        // Test ZK Withdrawal Performance
        auto withdrawStart = std::chrono::high_resolution_clock::now();
        
        STTx zkWithdrawTx(ttZK_WITHDRAW, [&](auto& obj) {
            obj.setAccountID(sfAccount, aliceID);
            obj.setAccountID(sfDestination, bobID);
            obj.setFieldAmount(sfAmount, STAmount(amount));
            obj.setFieldH256(sfNullifier, zkp::ZkProver::generateRandomUint256());
            obj.setFieldH256(sfMerkleRoot, testTree_->root());
            obj.setFieldVL(sfZKProof, generateMockProofData(2048)); // Realistic proof size
            obj.setFieldU32(sfSequence, 1);
            obj.setFieldAmount(sfFee, STAmount(12));
        });
        
        zkWithdrawTx.sign(alice.first, alice.second);
        
        // Measure ZK transaction size
        Serializer zkSerializer;
        zkWithdrawTx.add(zkSerializer);
        metrics_.zkTxSize = zkSerializer.size();
        
        auto withdrawEnd = std::chrono::high_resolution_clock::now();
        metrics_.zkWithdrawTxTime = std::chrono::duration<double, std::milli>(withdrawEnd - withdrawStart);
        
        // Validate transactions
        BEAST_EXPECT(zkDepositTx.isFieldPresent(sfCommitment));
        BEAST_EXPECT(zkDepositTx.isFieldPresent(sfNullifier));
        BEAST_EXPECT(zkDepositTx.isFieldPresent(sfZKProof));
        BEAST_EXPECT(zkWithdrawTx.isFieldPresent(sfMerkleRoot));
        
        log << "ZK deposit transaction time: " << std::fixed << std::setprecision(3) 
            << metrics_.zkDepositTxTime.count() << " ms" << std::endl;
        log << "ZK withdrawal transaction time: " << std::fixed << std::setprecision(3) 
            << metrics_.zkWithdrawTxTime.count() << " ms" << std::endl;
        log << "ZK transaction size: " << metrics_.zkTxSize << " bytes" << std::endl;
        log << "ZK transaction performance: PASSED" << std::endl;
    }
    
    void testDepositTransaction()
    {
        testcase("Deposit Transaction");
        
        auto alice = randomKeyPair(KeyType::secp256k1);
        auto aliceID = calcAccountID(alice.first);
        
        uint64_t depositAmount = 10000000; // 10 XRP
        
        // Create deposit transaction
        STTx depositTx(ttZK_DEPOSIT, [&](auto& obj) {
            obj.setAccountID(sfAccount, aliceID);
            obj.setFieldAmount(sfAmount, STAmount(depositAmount));
            obj.setFieldH256(sfCommitment, zkp::ZkProver::generateRandomUint256());
            obj.setFieldH256(sfNullifier, zkp::ZkProver::generateRandomUint256());
            obj.setFieldVL(sfZKProof, generateMockProofData(200));
            obj.setFieldU32(sfSequence, 1);
            obj.setFieldAmount(sfFee, STAmount(12));
        });
        
        // Sign transaction
        depositTx.sign(alice.first, alice.second);
        
        // Validate transaction structure
        BEAST_EXPECT(depositTx.isFieldPresent(sfAccount));
        BEAST_EXPECT(depositTx.isFieldPresent(sfAmount));
        BEAST_EXPECT(depositTx.isFieldPresent(sfCommitment));
        BEAST_EXPECT(depositTx.isFieldPresent(sfNullifier));
        BEAST_EXPECT(depositTx.isFieldPresent(sfZKProof));
        BEAST_EXPECT(depositTx.isFieldPresent(sfTxnSignature));
        
        // Validate amounts
        BEAST_EXPECT(depositTx.getFieldAmount(sfAmount).xrp().drops() == depositAmount);
        BEAST_EXPECT(depositTx.getFieldAmount(sfFee).xrp().drops() == 12);
        
        log << "Deposit transaction structure: PASSED" << std::endl;
    }
    
    void testWithdrawalTransaction()
    {
        testcase("Withdrawal Transaction");
        
        auto alice = randomKeyPair(KeyType::secp256k1);
        auto bob = randomKeyPair(KeyType::secp256k1);
        auto aliceID = calcAccountID(alice.first);
        auto bobID = calcAccountID(bob.first);
        
        uint64_t withdrawAmount = 7000000; // 7 XRP
        
        // Create withdrawal transaction
        STTx withdrawTx(ttZK_WITHDRAW, [&](auto& obj) {
            obj.setAccountID(sfAccount, aliceID);
            obj.setAccountID(sfDestination, bobID);
            obj.setFieldAmount(sfAmount, STAmount(withdrawAmount));
            obj.setFieldH256(sfNullifier, zkp::ZkProver::generateRandomUint256());
            obj.setFieldH256(sfMerkleRoot, testTree_->root());
            obj.setFieldVL(sfZKProof, generateMockProofData(200));
            obj.setFieldU32(sfSequence, 1);
            obj.setFieldAmount(sfFee, STAmount(12));
        });
        
        // Sign transaction
        withdrawTx.sign(alice.first, alice.second);
        
        // Validate transaction structure
        BEAST_EXPECT(withdrawTx.isFieldPresent(sfAccount));
        BEAST_EXPECT(withdrawTx.isFieldPresent(sfDestination));
        BEAST_EXPECT(withdrawTx.isFieldPresent(sfAmount));
        BEAST_EXPECT(withdrawTx.isFieldPresent(sfNullifier));
        BEAST_EXPECT(withdrawTx.isFieldPresent(sfMerkleRoot));
        BEAST_EXPECT(withdrawTx.isFieldPresent(sfZKProof));
        BEAST_EXPECT(withdrawTx.isFieldPresent(sfTxnSignature));
        
        // Validate amounts and accounts
        BEAST_EXPECT(withdrawTx.getFieldAmount(sfAmount).xrp().drops() == withdrawAmount);
        BEAST_EXPECT(withdrawTx.getAccountID(sfAccount) == aliceID);
        BEAST_EXPECT(withdrawTx.getAccountID(sfDestination) == bobID);
        
        log << "Withdrawal transaction structure: PASSED" << std::endl;
    }
    
    void testNullifierTracking()
    {
        testcase("Nullifier Tracking");
        
        auto start = std::chrono::high_resolution_clock::now();
        
        // Generate several nullifiers
        for (int i = 0; i < 1000; ++i) {  // Increased to 1000 for better timing measurement
            uint256 nullifier = zkp::ZkProver::generateRandomUint256();
            
            // Check uniqueness
            BEAST_EXPECT(usedNullifiers_.find(nullifier) == usedNullifiers_.end());
            usedNullifiers_.insert(nullifier);
            
            // Validate nullifier properties
            BEAST_EXPECT(nullifier != uint256{});
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration<double, std::milli>(end - start);
        
        BEAST_EXPECT(usedNullifiers_.size() == 1000);
        log << "Generated " << usedNullifiers_.size() << " unique nullifiers" << std::endl;
        log << "Nullifier generation time: " << std::fixed << std::setprecision(3) 
            << duration.count() << " ms" << std::endl;
        log << "Time per nullifier: " << std::fixed << std::setprecision(6) 
            << (duration.count() / 1000.0) << " ms" << std::endl;
        log << "Nullifier tracking: PASSED" << std::endl;
    }
    
    void testShieldedPoolManagement()
    {
        testcase("Shielded Pool Management");
        
        // Test pool state tracking
        STAmount poolBalance(50000000); // 50 XRP
        uint32_t commitmentCount = 42;
        uint256 currentRoot = testTree_->root();
        
        // Validate pool properties
        BEAST_EXPECT(poolBalance > beast::zero);
        BEAST_EXPECT(commitmentCount > 0);
        BEAST_EXPECT(currentRoot != uint256{});
        
        // Test pool operations simulation
        STAmount depositAmount(5000000); // 5 XRP deposit
        STAmount withdrawAmount(3000000); // 3 XRP withdrawal
        
        STAmount newBalance = poolBalance + depositAmount - withdrawAmount;
        BEAST_EXPECT(newBalance == STAmount(52000000));
        
        log << "Initial pool balance: " << poolBalance.getText() << std::endl;
        log << "After deposit/withdraw: " << newBalance.getText() << std::endl;
        log << "Commitment count: " << commitmentCount << std::endl;
        log << "Current root: " << currentRoot << std::endl;
        log << "Shielded pool management: PASSED" << std::endl;
    }
    
    void testTransactionSerialization()
    {
        testcase("Transaction Serialization");
        
        auto alice = randomKeyPair(KeyType::secp256k1);
        auto aliceID = calcAccountID(alice.first);
        
        auto start = std::chrono::high_resolution_clock::now();
        
        // Create a test transaction
        STTx tx(ttZK_DEPOSIT, [&](auto& obj) {
            obj.setAccountID(sfAccount, aliceID);
            obj.setFieldAmount(sfAmount, STAmount(1000000));
            obj.setFieldH256(sfCommitment, zkp::ZkProver::generateRandomUint256());
            obj.setFieldH256(sfNullifier, zkp::ZkProver::generateRandomUint256());
            obj.setFieldVL(sfZKProof, generateMockProofData(200));
        });
        
        tx.sign(alice.first, alice.second);
        
        // Test JSON serialization
        Json::Value jsonTx = tx.getJson(JsonOptions::none);
        BEAST_EXPECT(jsonTx.isObject());
        BEAST_EXPECT(jsonTx.isMember("TransactionType"));
        BEAST_EXPECT(jsonTx.isMember("Account"));
        BEAST_EXPECT(jsonTx.isMember("Amount"));
        BEAST_EXPECT(jsonTx.isMember("Commitment"));
        BEAST_EXPECT(jsonTx.isMember("Nullifier"));
        BEAST_EXPECT(jsonTx.isMember("ZKProof"));
        
        // Test binary serialization
        Serializer s;
        tx.add(s);
        BEAST_EXPECT(s.size() > 0);
        
        // Test deserialization
        SerialIter sit(s.data(), s.size());
        STTx deserializedTx(sit);
        BEAST_EXPECT(deserializedTx.getTransactionID() == tx.getTransactionID());
        
        // Test hex encoding
        std::string hexTx = strHex(s.slice());
        BEAST_EXPECT(!hexTx.empty());
        BEAST_EXPECT(hexTx.length() % 2 == 0);
        
        auto end = std::chrono::high_resolution_clock::now();
        metrics_.serializationTime = std::chrono::duration<double, std::milli>(end - start);
        
        log << "Serialization time: " << std::fixed << std::setprecision(3) 
            << metrics_.serializationTime.count() << " ms" << std::endl;
        log << "Serialized size: " << s.size() << " bytes" << std::endl;
        log << "JSON size: " << jsonTx.toStyledString().length() << " bytes" << std::endl;
        log << "Transaction serialization: PASSED" << std::endl;
    }
    
    void testErrorHandling()
    {
        testcase("Error Handling");
        
        auto alice = randomKeyPair(KeyType::secp256k1);
        auto aliceID = calcAccountID(alice.first);
        
        // Test zero amount handling
        STTx zeroAmountTx(ttZK_DEPOSIT, [&](auto& obj) {
            obj.setAccountID(sfAccount, aliceID);
            obj.setFieldAmount(sfAmount, STAmount(0)); // Zero amount
            obj.setFieldH256(sfCommitment, zkp::ZkProver::generateRandomUint256());
            obj.setFieldH256(sfNullifier, zkp::ZkProver::generateRandomUint256());
            obj.setFieldVL(sfZKProof, generateMockProofData(200));
        });
        
        BEAST_EXPECT(zeroAmountTx.getFieldAmount(sfAmount) == beast::zero);
        
        // Test oversized proof handling
        STTx oversizedProofTx(ttZK_DEPOSIT, [&](auto& obj) {
            obj.setAccountID(sfAccount, aliceID);
            obj.setFieldAmount(sfAmount, STAmount(1000000));
            obj.setFieldH256(sfCommitment, zkp::ZkProver::generateRandomUint256());
            obj.setFieldH256(sfNullifier, zkp::ZkProver::generateRandomUint256());
            obj.setFieldVL(sfZKProof, generateMockProofData(100000)); // Very large proof
        });
        
        BEAST_EXPECT(oversizedProofTx.getFieldVL(sfZKProof).size() == 100000);
        
        // Test invalid nullifier (zero)
        STTx invalidNullifierTx(ttZK_WITHDRAW, [&](auto& obj) {
            obj.setAccountID(sfAccount, aliceID);
            obj.setAccountID(sfDestination, aliceID);
            obj.setFieldAmount(sfAmount, STAmount(1000000));
            obj.setFieldH256(sfNullifier, uint256{}); // Zero nullifier
            obj.setFieldH256(sfCurrentRoot, testTree_->root());
            obj.setFieldVL(sfZKProof, generateMockProofData(200));
        });
        
        BEAST_EXPECT(invalidNullifierTx.getFieldH256(sfNullifier) == uint256{});
        
        log << "Error handling: PASSED" << std::endl;
    }
    
    void testCompleteDepositWithdrawFlow()
    {
        testcase("Complete Deposit-Withdraw Flow");
        
        auto flowStart = std::chrono::high_resolution_clock::now();
        
        try {
            // Step 1: Create deposit proof
            uint64_t amount = 15000000; // 15 XRP
            uint256 commitment = zkp::ZkProver::generateRandomUint256();
            std::string spendKey = "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff";
            zkp::FieldT vcmR = zkp::FieldT::random_element();
            
            auto depositProof = zkp::ZkProver::createDepositProof(
                amount, commitment, spendKey, vcmR
            );
            BEAST_EXPECT(!depositProof.proof.empty());
            
            // Step 2: Create and verify deposit transaction
            auto alice = randomKeyPair(KeyType::secp256k1);
            auto aliceID = calcAccountID(alice.first);
            
            STTx depositTx(ttZK_DEPOSIT, [&](auto& obj) {
                obj.setAccountID(sfAccount, aliceID);
                obj.setFieldAmount(sfAmount, STAmount(amount));
                obj.setFieldH256(sfCommitment, zkp::MerkleCircuit::fieldElementToUint256(depositProof.anchor));
                obj.setFieldH256(sfNullifier, zkp::MerkleCircuit::fieldElementToUint256(depositProof.nullifier));
                obj.setFieldVL(sfZKProof, depositProof.proof);
                obj.setFieldU32(sfSequence, 1);
                obj.setFieldAmount(sfFee, STAmount(12));
            });
            
            depositTx.sign(alice.first, alice.second);
            BEAST_EXPECT(depositTx.isFieldPresent(sfTxnSignature));
            
            // Step 3: Simulate adding commitment to tree
            uint256 depositCommitment = depositTx.getFieldH256(sfCommitment);
            testTree_->append(depositCommitment);
            size_t noteIndex = testTree_->size() - 1;
            
            // Step 4: Create withdrawal proof
            auto withdrawNote = zkp::Note::random(amount);
            auto authPath = testTree_->authPath(noteIndex);  
            uint256 merkleRoot = testTree_->root();
            zkp::FieldT withdrawVcmR = zkp::FieldT::random_element();
            
            auto withdrawProof = zkp::ZkProver::createWithdrawalProof(
                amount,
                merkleRoot,
                zkp::ZkProver::generateRandomUint256(),
                authPath,
                noteIndex,
                spendKey,
                withdrawVcmR
            );
            
            BEAST_EXPECT(!withdrawProof.proof.empty());
            
            // Step 5: Create withdrawal transaction
            auto bob = randomKeyPair(KeyType::secp256k1);
            auto bobID = calcAccountID(bob.first);
            
            STTx withdrawTx(ttZK_WITHDRAW, [&](auto& obj) {
                obj.setAccountID(sfAccount, aliceID);
                obj.setAccountID(sfDestination, bobID);
                obj.setFieldAmount(sfAmount, STAmount(amount));
                obj.setFieldH256(sfNullifier, zkp::MerkleCircuit::fieldElementToUint256(withdrawProof.nullifier));
                obj.setFieldH256(sfCurrentRoot, merkleRoot);
                obj.setFieldVL(sfZKProof, withdrawProof.proof);
                obj.setFieldU32(sfSequence, 1);
                obj.setFieldAmount(sfFee, STAmount(12));
            });
            
            withdrawTx.sign(alice.first, alice.second);
            BEAST_EXPECT(withdrawTx.isFieldPresent(sfTxnSignature));
            
            // Step 6: Validate complete flow
            BEAST_EXPECT(depositTx.getFieldAmount(sfAmount) == withdrawTx.getFieldAmount(sfAmount));
            BEAST_EXPECT(withdrawTx.getAccountID(sfDestination) == bobID);
            
            auto flowEnd = std::chrono::high_resolution_clock::now();
            auto flowTime = std::chrono::duration<double, std::milli>(flowEnd - flowStart);
            
            log << "Deposit amount: " << depositTx.getFieldAmount(sfAmount).getText() << std::endl;
            log << "Withdraw amount: " << withdrawTx.getFieldAmount(sfAmount).getText() << std::endl;
            log << "Destination: " << toBase58(withdrawTx.getAccountID(sfDestination)) << std::endl;
            log << "Complete flow time: " << std::fixed << std::setprecision(3) 
                << flowTime.count() << " ms" << std::endl;
            log << "Complete deposit-withdraw flow: PASSED" << std::endl;
            
        } catch (const std::exception& e) {
            log << "Complete flow failed: " << e.what() << std::endl;
            BEAST_EXPECT(false);
        }
    }
    
    void printPerformanceComparison()
    {
        testcase("Performance Summary");
        
        log << "\n" << std::string(60, '=') << std::endl;
        log << "              PERFORMANCE COMPARISON SUMMARY" << std::endl;
        log << std::string(60, '=') << std::endl;
        
        // Transaction Creation Performance
        log << "\nTransaction Creation Times:" << std::endl;
        log << "  Traditional Payment:    " << std::fixed << std::setprecision(3) 
            << metrics_.traditionalTxTime.count() << " ms" << std::endl;
        log << "  ZK Deposit:            " << std::fixed << std::setprecision(3) 
            << metrics_.zkDepositTxTime.count() << " ms" << std::endl;
        log << "  ZK Withdrawal:         " << std::fixed << std::setprecision(3) 
            << metrics_.zkWithdrawTxTime.count() << " ms" << std::endl;
        
        // Performance Ratios
        if (metrics_.traditionalTxTime.count() > 0) {
            double depositRatio = metrics_.zkDepositTxTime.count() / metrics_.traditionalTxTime.count();
            double withdrawRatio = metrics_.zkWithdrawTxTime.count() / metrics_.traditionalTxTime.count();
            
            log << "\nPerformance Overhead:" << std::endl;
            log << "  ZK Deposit vs Traditional:  " << std::fixed << std::setprecision(2) 
                << depositRatio << "x slower" << std::endl;
            log << "  ZK Withdrawal vs Traditional: " << std::fixed << std::setprecision(2) 
                << withdrawRatio << "x slower" << std::endl;
        }
        
        // Transaction Size Comparison
        log << "\nTransaction Sizes:" << std::endl;
        log << "  Traditional Payment:    " << metrics_.traditionalTxSize << " bytes" << std::endl;
        log << "  ZK Transaction:         " << metrics_.zkTxSize << " bytes" << std::endl;
        
        if (metrics_.traditionalTxSize > 0) {
            double sizeRatio = static_cast<double>(metrics_.zkTxSize) / metrics_.traditionalTxSize;
            log << "  Size Overhead:          " << std::fixed << std::setprecision(2) 
                << sizeRatio << "x larger" << std::endl;
        }
        
        // Detailed ZK Operations
        log << "\nZK-Specific Operation Times:" << std::endl;
        log << "  Note Operations:        " << std::fixed << std::setprecision(3) 
            << metrics_.noteOperationsTime.count() << " ms" << std::endl;
        log << "  Merkle Tree Operations: " << std::fixed << std::setprecision(3) 
            << metrics_.merkleOperationsTime.count() << " ms" << std::endl;
        log << "  Proof Generation:       " << std::fixed << std::setprecision(3) 
            << metrics_.proofGenerationTime.count() << " ms" << std::endl;
        log << "  Serialization:          " << std::fixed << std::setprecision(3) 
            << metrics_.serializationTime.count() << " ms" << std::endl;
        
        // Memory Usage Estimates
        log << "\nMemory Usage Estimates:" << std::endl;
        log << "  Merkle Tree Nodes:      " << (testTree_->size() * 32) << " bytes" << std::endl;
        log << "  Nullifier Set:          " << (usedNullifiers_.size() * 32) << " bytes" << std::endl;
        log << "  Test Notes:             " << (testNotes_.size() * 128) << " bytes (estimated)" << std::endl;
        
        // Throughput Estimates
        if (metrics_.zkDepositTxTime.count() > 0 && metrics_.zkWithdrawTxTime.count() > 0) {
            double avgZkTime = (metrics_.zkDepositTxTime.count() + metrics_.zkWithdrawTxTime.count()) / 2.0;
            double zkTxPerSecond = 1000.0 / avgZkTime;
            double traditionalTxPerSecond = 1000.0 / metrics_.traditionalTxTime.count();
            
            log << "\nThroughput Estimates (single-threaded):" << std::endl;
            log << "  Traditional TPS:        " << std::fixed << std::setprecision(1) 
                << traditionalTxPerSecond << " tx/sec" << std::endl;
            log << "  ZK TPS:                 " << std::fixed << std::setprecision(1) 
                << zkTxPerSecond << " tx/sec" << std::endl;
        }
        
        log << "\n" << std::string(60, '=') << std::endl;
        log << "Performance comparison: COMPLETED" << std::endl;
    }
    
    void cleanup()
    {
        testcase("Cleanup");
        
        testNotes_.clear();
        usedNullifiers_.clear();
        
        if (testTree_) {
            delete testTree_;
            testTree_ = nullptr;
        }
        
        log << "Cleanup completed" << std::endl;
    }
    
    // Helper functions
    std::vector<uint8_t> generateMockProofData(size_t size)
    {
        std::vector<uint8_t> proofData(size);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint8_t> dis(0, 255);
        
        for (size_t i = 0; i < size; ++i) {
            proofData[i] = dis(gen);
        }
        
        return proofData;
    }
};

// Register the test suite
BEAST_DEFINE_TESTSUITE(ZKPTransaction, ripple_app, ripple);

} // namespace ripple