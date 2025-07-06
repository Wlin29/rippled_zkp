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

#include "libxrpl/zkp/ZKProver.h"
#include "libxrpl/zkp/Note.h"
#include "libxrpl/zkp/IncrementalMerkleTree.h"
#include "libxrpl/zkp/circuits/MerkleCircuit.h"
#include "libxrpl/zkp/ZkDeposit.h"
#include "libxrpl/zkp/ZkWithdraw.h"

namespace ripple {

class ZKTransaction_test : public beast::unit_test::suite
{
private:
    // Test data storage
    std::vector<zkp::Note> testNotes_;
    std::vector<uint256> testCommitments_;
    std::vector<uint256> testNullifiers_;
    std::vector<std::string> testSpendKeys_;
    zkp::IncrementalMerkleTree* testTree_;
    
public:
    void run() override
    {
        testcase("=== ZK TRANSACTION TEST SUITE ===");

        if (!zkp::ZkProver::isInitialized) {
            zkp::ZkProver::initialize();
        }
        
        // testTransactionCreationPerformance();
        // testProofGenerationPerformance();
        // testTransactionValidationPerformance();
        // testSerializationPerformance();
        // testTransactionThroughput();
        testProofAndInputSizeAnalysis();    
    }

private:
    void testTransactionCreationPerformance()
    {
        testcase("Transaction Creation Performance Comparison");
        
        auto keyPair = generateKeyPair(KeyType::secp256k1, generateSeed("perf"));
        auto aliceID = calcAccountID(keyPair.first);
        auto bobID = calcAccountID(generateKeyPair(KeyType::secp256k1, generateSeed("bob")).first);
        
        std::vector<uint64_t> amounts = {1000000};
        
        for (auto amount : amounts) {
            // Traditional transaction creation
            auto startTraditional = std::chrono::high_resolution_clock::now();
            
            for (int i = 0; i < 5; ++i) {
                STTx traditionalTx(ttPAYMENT, [&](STObject& obj) {
                    obj.setAccountID(sfAccount, aliceID);
                    obj.setAccountID(sfDestination, bobID);
                    obj.setFieldAmount(sfAmount, STAmount{amount});
                    obj.setFieldU32(sfSequence, i + 1);
                    obj.setFieldAmount(sfFee, STAmount{10ULL});
                    obj.setFieldVL(sfSigningPubKey, keyPair.first.slice());
                });
                traditionalTx.sign(keyPair.first, keyPair.second);
            }
            
            auto traditionalTime = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::high_resolution_clock::now() - startTraditional);
            
            // ZKP deposit transaction creation
            auto startZkp = std::chrono::high_resolution_clock::now();
            
            for (int i = 0; i < 5; ++i) {
                // Create ZKP proof first
                auto proofData = ZkDeposit::createDepositProof(amount, "test_key_" + std::to_string(i));
                
                if (!proofData.empty()) {
                    STTx zkpTx(ttZK_DEPOSIT, [&](STObject& obj) {
                        obj.setAccountID(sfAccount, aliceID);
                        obj.setFieldAmount(sfAmount, STAmount{amount});
                        obj.setFieldU32(sfSequence, i + 1);
                        obj.setFieldAmount(sfFee, STAmount{50ULL});
                        obj.setFieldVL(sfSigningPubKey, keyPair.first.slice());
                        
                        obj.setFieldH256(sfCommitment, uint256{});
                        obj.setFieldH256(sfNullifier, uint256{});
                        obj.setFieldVL(sfZKProof, proofData.proof);
                    });
                    zkpTx.sign(keyPair.first, keyPair.second);
                }
            }
            
            auto zkpTime = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::high_resolution_clock::now() - startZkp);
            
            log << "Amount: " << amount << " drops" << std::endl;
            log << "Traditional: " << traditionalTime.count() << " μs" << std::endl;
            log << "ZKP: " << zkpTime.count() << " μs" << std::endl;
            log << "Ratio: " << static_cast<double>(zkpTime.count()) / traditionalTime.count() << "x" << std::endl;
            log << "---" << std::endl;
        }
    }

    void testProofGenerationPerformance()
    {
        testcase("ZKP Proof Generation Performance");
        
        if (!zkp::ZkProver::isInitialized) {
            zkp::ZkProver::initialize();
        }
        
        std::vector<uint64_t> amounts = {1000000};
        std::vector<int> iterations = {5};
        
        for (auto amount : amounts) {
            for (auto iter : iterations) {
                // Deposit proof generation
                auto startDeposit = std::chrono::high_resolution_clock::now();
                
                int successfulDeposits = 0;
                for (int i = 0; i < iter; ++i) {
                    auto proofData = ZkDeposit::createDepositProof(amount, "key_" + std::to_string(i));
                    if (!proofData.empty()) {
                        successfulDeposits++;
                    }
                }
                
                auto depositTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::high_resolution_clock::now() - startDeposit);
                
                // Withdrawal proof generation
                zkp::IncrementalMerkleTree tree(32);
                uint256 testCommitment = zkp::ZkProver::generateRandomUint256();
                tree.append(testCommitment);
                
                auto startWithdrawal = std::chrono::high_resolution_clock::now();
                
                int successfulWithdrawals = 0;
                for (int i = 0; i < iter; ++i) {
                    auto proofData = zkp::ZkProver::createWithdrawalProof(
                        amount,
                        tree.root(),
                        zkp::ZkProver::generateRandomUint256(),
                        tree.authPath(0),
                        0,
                        "key_" + std::to_string(i),
                        zkp::FieldT::random_element()
                    );
                    if (!proofData.empty()) {
                        successfulWithdrawals++;
                    }
                }
                
                auto withdrawalTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::high_resolution_clock::now() - startWithdrawal);
                
                log << "Amount: " << amount << ", Iterations: " << iter << std::endl;
                log << "Deposit proofs: " << successfulDeposits << "/" << iter 
                    << " (" << depositTime.count() << "ms)" << std::endl;
                log << "Withdrawal proofs: " << successfulWithdrawals << "/" << iter 
                    << " (" << withdrawalTime.count() << "ms)" << std::endl;
                
                if (iter > 0) {
                    log << "Avg deposit: " << depositTime.count() / iter << "ms" << std::endl;
                    log << "Avg withdrawal: " << withdrawalTime.count() / iter << "ms" << std::endl;
                }
                log << "---" << std::endl;
            }
        }
    }

    void testTransactionValidationPerformance()
    {
        testcase("Transaction Validation Performance");
        
        auto keyPair = generateKeyPair(KeyType::secp256k1, generateSeed("validation"));
        auto account = calcAccountID(keyPair.first);
        
        // Create test transactions
        std::vector<STTx> traditionalTxs;
        std::vector<STTx> zkpTxs;
        
        for (int i = 0; i < 5; ++i) {
            // Traditional transaction
            STTx tradTx(ttPAYMENT, [&](STObject& obj) {
                obj.setAccountID(sfAccount, account);
                obj.setAccountID(sfDestination, account);
                obj.setFieldAmount(sfAmount, STAmount{1000000ULL});
                obj.setFieldU32(sfSequence, i + 1);
                obj.setFieldAmount(sfFee, STAmount{10ULL});
                obj.setFieldVL(sfSigningPubKey, keyPair.first.slice());
            });
            tradTx.sign(keyPair.first, keyPair.second);
            traditionalTxs.push_back(std::move(tradTx));
            
            // ZKP transaction
            STTx zkpTx(ttZK_DEPOSIT, [&](STObject& obj) {
                obj.setAccountID(sfAccount, account);
                obj.setFieldAmount(sfAmount, STAmount{1000000ULL});
                obj.setFieldU32(sfSequence, i + 1);
                obj.setFieldAmount(sfFee, STAmount{50ULL});
                obj.setFieldVL(sfSigningPubKey, keyPair.first.slice());
                
                obj.setFieldH256(sfCommitment, zkp::ZkProver::generateRandomUint256());
                obj.setFieldH256(sfNullifier, zkp::ZkProver::generateRandomUint256());
                obj.setFieldVL(sfZKProof, std::vector<unsigned char>(200, 0x42));
            });
            zkpTx.sign(keyPair.first, keyPair.second);
            zkpTxs.push_back(std::move(zkpTx));
        }
        
        // Validate traditional transactions
        auto startTrad = std::chrono::high_resolution_clock::now();
        for (auto& tx : traditionalTxs) {
            std::unordered_set<uint256, beast::uhash<>> const presets;
            Rules const defaultRules{presets};
            auto validResult = tx.checkSign(STTx::RequireFullyCanonicalSig::yes, defaultRules);
            bool valid = static_cast<bool>(validResult);
            (void)valid; // Suppress unused warning
        }
        auto tradValidationTime = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - startTrad);
        
        // Validate ZKP transactions
        auto startZkp = std::chrono::high_resolution_clock::now();
        for (auto& tx : zkpTxs) {
            std::unordered_set<uint256, beast::uhash<>> const presets;
            Rules const defaultRules{presets};
            auto validResult = tx.checkSign(STTx::RequireFullyCanonicalSig::yes, defaultRules);
            bool valid = static_cast<bool>(validResult);
            (void)valid; // Suppress unused warning
        }
        auto zkpValidationTime = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - startZkp);
        
        log << "Traditional validation (50 tx): " << tradValidationTime.count() << " μs" << std::endl;
        log << "ZKP validation (50 tx): " << zkpValidationTime.count() << " μs" << std::endl;
        log << "Avg traditional: " << tradValidationTime.count() / 50 << " μs/tx" << std::endl;
        log << "Avg ZKP: " << zkpValidationTime.count() / 50 << " μs/tx" << std::endl;
    }

    void testSerializationPerformance()
    {
        testcase("Transaction Serialization Performance");
        
        auto keyPair = generateKeyPair(KeyType::secp256k1, generateSeed("serial"));
        auto account = calcAccountID(keyPair.first);
        
        // Test different proof sizes to show scaling impact
        std::vector<size_t> proofSizes = {128, 512, 1024, 2048, 4096};
        const int ITERATIONS = 20; // More iterations for better accuracy
        
        log << "=== SERIALIZATION/DESERIALIZATION PERFORMANCE COMPARISON ===" << std::endl;
        log << "Testing " << ITERATIONS << " iterations per test" << std::endl;
        log << "---" << std::endl;
        
        for (auto proofSize : proofSizes) {
            // Traditional transaction
            STTx tradTx(ttPAYMENT, [&](STObject& obj) {
                obj.setAccountID(sfAccount, account);
                obj.setAccountID(sfDestination, account);
                obj.setFieldAmount(sfAmount, STAmount{1000000ULL});
                obj.setFieldU32(sfSequence, 1);
                obj.setFieldAmount(sfFee, STAmount{10ULL});
                obj.setFieldVL(sfSigningPubKey, keyPair.first.slice());
            });
            tradTx.sign(keyPair.first, keyPair.second);
            
            // ZKP transaction
            STTx zkpTx(ttZK_DEPOSIT, [&](STObject& obj) {
                obj.setAccountID(sfAccount, account);
                obj.setFieldAmount(sfAmount, STAmount{1000000ULL});
                obj.setFieldU32(sfSequence, 1);
                obj.setFieldAmount(sfFee, STAmount{50ULL});
                obj.setFieldVL(sfSigningPubKey, keyPair.first.slice());
                
                obj.setFieldH256(sfCommitment, zkp::ZkProver::generateRandomUint256());
                obj.setFieldH256(sfNullifier, zkp::ZkProver::generateRandomUint256());
                obj.setFieldVL(sfZKProof, std::vector<unsigned char>(proofSize, 0x42));
            });
            zkpTx.sign(keyPair.first, keyPair.second);
            
            // === SERIALIZATION PERFORMANCE ===
            log << "Proof size: " << proofSize << " bytes" << std::endl;
            
            // Traditional serialization
            auto startTradSer = std::chrono::high_resolution_clock::now();
            std::vector<Serializer> tradSerializers;
            for (int i = 0; i < ITERATIONS; ++i) {
                Serializer ser;
                tradTx.add(ser);
                tradSerializers.push_back(std::move(ser));
            }
            auto tradSerTime = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::high_resolution_clock::now() - startTradSer);
            
            // ZKP serialization
            auto startZkpSer = std::chrono::high_resolution_clock::now();
            std::vector<Serializer> zkpSerializers;
            for (int i = 0; i < ITERATIONS; ++i) {
                Serializer ser;
                zkpTx.add(ser);
                zkpSerializers.push_back(std::move(ser));
            }
            auto zkpSerTime = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::high_resolution_clock::now() - startZkpSer);
            
            // === DESERIALIZATION PERFORMANCE ===
            
            // Get serialized data for deserialization tests
            Serializer tradSer, zkpSer;
            tradTx.add(tradSer);
            zkpTx.add(zkpSer);
            
            // Traditional deserialization
            auto startTradDeser = std::chrono::high_resolution_clock::now();
            std::vector<STTx> tradDeserTxs;
            for (int i = 0; i < ITERATIONS; ++i) {
                SerialIter sit(tradSer.slice());
                tradDeserTxs.emplace_back(sit);
            }
            auto tradDeserTime = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::high_resolution_clock::now() - startTradDeser);
            
            // ZKP deserialization
            auto startZkpDeser = std::chrono::high_resolution_clock::now();
            std::vector<STTx> zkpDeserTxs;
            for (int i = 0; i < ITERATIONS; ++i) {
                SerialIter sit(zkpSer.slice());
                zkpDeserTxs.emplace_back(sit);
            }
            auto zkpDeserTime = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::high_resolution_clock::now() - startZkpDeser);
            
            // === CALCULATE METRICS ===
            
            double tradSerPerTx = static_cast<double>(tradSerTime.count()) / ITERATIONS;
            double zkpSerPerTx = static_cast<double>(zkpSerTime.count()) / ITERATIONS;
            double tradDeserPerTx = static_cast<double>(tradDeserTime.count()) / ITERATIONS;
            double zkpDeserPerTx = static_cast<double>(zkpDeserTime.count()) / ITERATIONS;
            
            double serializationOverhead = zkpSerPerTx / tradSerPerTx;
            double deserializationOverhead = zkpDeserPerTx / tradDeserPerTx;
            
            size_t tradSize = tradSer.size();
            size_t zkpSize = zkpSer.size();
            double sizeOverhead = static_cast<double>(zkpSize) / tradSize;
            
            // Calculate throughput (transactions per second)
            double tradSerThroughput = 1000000.0 / tradSerPerTx; // μs to TPS
            double zkpSerThroughput = 1000000.0 / zkpSerPerTx;
            double tradDeserThroughput = 1000000.0 / tradDeserPerTx;
            double zkpDeserThroughput = 1000000.0 / zkpDeserPerTx;
            
            // === OUTPUT RESULTS ===
            
            log << "  Transaction Sizes:" << std::endl;
            log << "    Traditional: " << tradSize << " bytes" << std::endl;
            log << "    ZKP: " << zkpSize << " bytes" << std::endl;
            log << "    Size overhead: " << std::fixed << std::setprecision(2) << sizeOverhead << "x" << std::endl;
            
            log << "  Serialization Performance:" << std::endl;
            log << "    Traditional: " << std::fixed << std::setprecision(2) << tradSerPerTx << " μs/tx (" 
                << static_cast<int>(tradSerThroughput) << " TPS)" << std::endl;
            log << "    ZKP: " << std::fixed << std::setprecision(2) << zkpSerPerTx << " μs/tx (" 
                << static_cast<int>(zkpSerThroughput) << " TPS)" << std::endl;
            log << "    Serialization overhead: " << std::fixed << std::setprecision(2) << serializationOverhead << "x" << std::endl;
            
            log << "  Deserialization Performance:" << std::endl;
            log << "    Traditional: " << std::fixed << std::setprecision(2) << tradDeserPerTx << " μs/tx (" 
                << static_cast<int>(tradDeserThroughput) << " TPS)" << std::endl;
            log << "    ZKP: " << std::fixed << std::setprecision(2) << zkpDeserPerTx << " μs/tx (" 
                << static_cast<int>(zkpDeserThroughput) << " TPS)" << std::endl;
            log << "    Deserialization overhead: " << std::fixed << std::setprecision(2) << deserializationOverhead << "x" << std::endl;
            
            // === DETAILED FIELD ANALYSIS (for largest proof size) ===
            if (proofSize == proofSizes.back()) {
                log << "  Detailed Field Analysis (largest proof):" << std::endl;
                
                // Calculate field contribution to size
                size_t zkpFieldsSize = proofSize + // sfZKProof
                                      32 +         // sfCommitment
                                      32 +         // sfNullifier  
                                      32 +         // sfValueCommitment
                                      32 +         // sfMerkleRoot
                                      (32 * 20);   // sfAuthPath
                
                size_t baseTransactionSize = zkpSize - zkpFieldsSize;
                double zkpFieldsPercentage = static_cast<double>(zkpFieldsSize) / zkpSize * 100.0;
                
                log << "    Base transaction size: " << baseTransactionSize << " bytes" << std::endl;
                log << "    ZKP fields size: " << zkpFieldsSize << " bytes (" 
                    << std::fixed << std::setprecision(1) << zkpFieldsPercentage << "%)" << std::endl;
                log << "    ZKP proof alone: " << proofSize << " bytes (" 
                    << std::fixed << std::setprecision(1) << (static_cast<double>(proofSize) / zkpSize * 100.0) << "%)" << std::endl;
            }
            
            log << "---" << std::endl;
        }
        
        // === BATCH SERIALIZATION TEST ===
        log << "\n=== BATCH SERIALIZATION TEST ===" << std::endl;
        
        const int BATCH_SIZE = 100;
        std::vector<STTx> tradBatch, zkpBatch;
        
        // Create batch of transactions
        for (int i = 0; i < BATCH_SIZE; ++i) {
            STTx tradTx(ttPAYMENT, [&](STObject& obj) {
                obj.setAccountID(sfAccount, account);
                obj.setAccountID(sfDestination, account);
                obj.setFieldAmount(sfAmount, STAmount{1000000ULL + i});
                obj.setFieldU32(sfSequence, i + 1);
                obj.setFieldAmount(sfFee, STAmount{10ULL});
                obj.setFieldVL(sfSigningPubKey, keyPair.first.slice());
            });
            tradTx.sign(keyPair.first, keyPair.second);
            tradBatch.push_back(std::move(tradTx));
            
            STTx zkpTx(ttZK_DEPOSIT, [&](STObject& obj) {
                obj.setAccountID(sfAccount, account);
                obj.setFieldAmount(sfAmount, STAmount{1000000ULL + i});
                obj.setFieldU32(sfSequence, i + 1);
                obj.setFieldAmount(sfFee, STAmount{50ULL});
                obj.setFieldVL(sfSigningPubKey, keyPair.first.slice());
                obj.setFieldH256(sfCommitment, zkp::ZkProver::generateRandomUint256());
                obj.setFieldH256(sfNullifier, zkp::ZkProver::generateRandomUint256());
                obj.setFieldVL(sfZKProof, std::vector<unsigned char>(1024, 0x42));
            });
            zkpTx.sign(keyPair.first, keyPair.second);
            zkpBatch.push_back(std::move(zkpTx));
        }
        
        // Batch serialization timing
        auto startBatchTrad = std::chrono::high_resolution_clock::now();
        std::vector<Serializer> tradBatchSer;
        for (const auto& tx : tradBatch) {
            Serializer ser;
            tx.add(ser);
            tradBatchSer.push_back(std::move(ser));
        }
        auto tradBatchTime = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - startBatchTrad);
        
        auto startBatchZkp = std::chrono::high_resolution_clock::now();
        std::vector<Serializer> zkpBatchSer;
        for (const auto& tx : zkpBatch) {
            Serializer ser;
            tx.add(ser);
            zkpBatchSer.push_back(std::move(ser));
        }
        auto zkpBatchTime = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - startBatchZkp);
        
        // Calculate total sizes
        size_t tradBatchSize = 0, zkpBatchSize = 0;
        for (const auto& ser : tradBatchSer) tradBatchSize += ser.size();
        for (const auto& ser : zkpBatchSer) zkpBatchSize += ser.size();
        
        log << "Batch of " << BATCH_SIZE << " transactions:" << std::endl;
        log << "  Traditional batch: " << tradBatchTime.count() << " μs (" 
            << tradBatchTime.count() / BATCH_SIZE << " μs/tx)" << std::endl;
        log << "  ZKP batch: " << zkpBatchTime.count() << " μs (" 
            << zkpBatchTime.count() / BATCH_SIZE << " μs/tx)" << std::endl;
        log << "  Traditional batch size: " << tradBatchSize << " bytes (" 
            << tradBatchSize / BATCH_SIZE << " bytes/tx)" << std::endl;
        log << "  ZKP batch size: " << zkpBatchSize << " bytes (" 
            << zkpBatchSize / BATCH_SIZE << " bytes/tx)" << std::endl;
        log << "  Batch overhead: " << std::fixed << std::setprecision(2) 
            << static_cast<double>(zkpBatchTime.count()) / tradBatchTime.count() << "x time, "
            << static_cast<double>(zkpBatchSize) / tradBatchSize << "x size" << std::endl;
        
        // === NETWORK IMPACT SIMULATION ===
        log << "\n=== NETWORK IMPACT SIMULATION ===" << std::endl;
        
        // Simulate network conditions
        const double NETWORK_SPEEDS[] = {1.0, 10.0, 100.0, 1000.0}; // Mbps
        const char* NETWORK_NAMES[] = {"Dial-up", "Broadband", "Fast Broadband", "Gigabit"};
        
        size_t avgTradSize = tradBatchSize / BATCH_SIZE;
        size_t avgZkpSize = zkpBatchSize / BATCH_SIZE;
        
        log << "Transaction transmission times:" << std::endl;
        for (size_t i = 0; i < 4; ++i) {
            double speedBytesPerSec = (NETWORK_SPEEDS[i] * 1000000.0) / 8.0; // Mbps to bytes/sec
            
            double tradTransmitTime = (avgTradSize * 8.0) / (NETWORK_SPEEDS[i] * 1000000.0) * 1000.0; // ms
            double zkpTransmitTime = (avgZkpSize * 8.0) / (NETWORK_SPEEDS[i] * 1000000.0) * 1000.0; // ms
            
            log << "  " << NETWORK_NAMES[i] << " (" << NETWORK_SPEEDS[i] << " Mbps):" << std::endl;
            log << "    Traditional: " << std::fixed << std::setprecision(2) << tradTransmitTime << " ms" << std::endl;
            log << "    ZKP: " << std::fixed << std::setprecision(2) << zkpTransmitTime << " ms" << std::endl;
            log << "    Overhead: " << std::fixed << std::setprecision(1) 
                << zkpTransmitTime / tradTransmitTime << "x slower" << std::endl;
        }
    }


    void testTransactionThroughput()
    {
        testcase("Transaction Throughput Analysis");
        
        auto keyPair = generateKeyPair(KeyType::secp256k1, generateSeed("throughput"));
        auto account = calcAccountID(keyPair.first);
        
        std::vector<int> batchSizes = {5};
        
        for (auto batchSize : batchSizes) {
            // Traditional transaction throughput
            auto startTrad = std::chrono::high_resolution_clock::now();
            
            for (int i = 0; i < batchSize; ++i) {
                STTx tx(ttPAYMENT, [&](STObject& obj) {
                    obj.setAccountID(sfAccount, account);
                    obj.setAccountID(sfDestination, account);
                    obj.setFieldAmount(sfAmount, STAmount{1000000ULL});
                    obj.setFieldU32(sfSequence, i + 1);
                    obj.setFieldAmount(sfFee, STAmount{10ULL});
                    obj.setFieldVL(sfSigningPubKey, keyPair.first.slice());
                });
                tx.sign(keyPair.first, keyPair.second);
                
                // Simulate validation
                Serializer ser;
                tx.add(ser);
                SerialIter sit(ser.slice());
                STTx deserTx(sit);
            }
            
            auto tradTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now() - startTrad);
            
            // ZKP transaction throughput (without proof generation)
            auto startZkp = std::chrono::high_resolution_clock::now();
            
            for (int i = 0; i < batchSize; ++i) {
                STTx tx(ttZK_DEPOSIT, [&](STObject& obj) {
                    obj.setAccountID(sfAccount, account);
                    obj.setFieldAmount(sfAmount, STAmount{1000000ULL});
                    obj.setFieldU32(sfSequence, i + 1);
                    obj.setFieldAmount(sfFee, STAmount{50ULL});
                    obj.setFieldVL(sfSigningPubKey, keyPair.first.slice());
                    
                    obj.setFieldH256(sfCommitment, zkp::ZkProver::generateRandomUint256());
                    obj.setFieldH256(sfNullifier, zkp::ZkProver::generateRandomUint256());
                    obj.setFieldVL(sfZKProof, std::vector<unsigned char>(1024, 0x42));
                });
                tx.sign(keyPair.first, keyPair.second);
                
                // Simulate validation
                Serializer ser;
                tx.add(ser);
                SerialIter sit(ser.slice());
                STTx deserTx(sit);
            }
            
            auto zkpTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now() - startZkp);
            
            double tradThroughput = static_cast<double>(batchSize) / tradTime.count() * 1000.0; // tx/sec
            double zkpThroughput = static_cast<double>(batchSize) / zkpTime.count() * 1000.0; // tx/sec
            
            log << "Batch size: " << batchSize << std::endl;
            log << "Traditional: " << tradTime.count() << "ms (" << tradThroughput << " tx/sec)" << std::endl;
            log << "ZKP: " << zkpTime.count() << "ms (" << zkpThroughput << " tx/sec)" << std::endl;
            log << "Throughput ratio: " << zkpThroughput / tradThroughput << std::endl;
            log << "---" << std::endl;
        }
    }
    
    void testProofAndInputSizeAnalysis()
    {
        testcase("Traditional vs ZKP Proof and Input Size Analysis");
        
        auto keyPair = generateKeyPair(KeyType::secp256k1, generateSeed("size_analysis"));
        auto account = calcAccountID(keyPair.first);
        
        log << "=== PROOF AND INPUT SIZE ANALYSIS ===" << std::endl;
        
        // === TRADITIONAL TRANSACTION ANALYSIS ===
        log << "\n=== TRADITIONAL TRANSACTION BREAKDOWN ===" << std::endl;
        
        STTx tradTx(ttPAYMENT, [&](STObject& obj) {
            obj.setAccountID(sfAccount, account);
            obj.setAccountID(sfDestination, account);
            obj.setFieldAmount(sfAmount, STAmount{1000000ULL});
            obj.setFieldU32(sfSequence, 1);
            obj.setFieldAmount(sfFee, STAmount{10ULL});
            obj.setFieldVL(sfSigningPubKey, keyPair.first.slice());
        });
        tradTx.sign(keyPair.first, keyPair.second);
        
        // Analyze traditional transaction components
        Serializer tradSer;
        tradTx.add(tradSer);
        
        // Calculate component sizes
        size_t tradTotalSize = tradSer.size();
        size_t tradPubKeySize = keyPair.first.size();
        size_t tradSignatureSize = tradTx.getFieldVL(sfTxnSignature).size();
        size_t tradInputDataSize = tradTotalSize - tradSignatureSize - tradPubKeySize - 10; // Approximate other overhead
        
        log << "Traditional Transaction Components:" << std::endl;
        log << "  Total transaction size: " << tradTotalSize << " bytes" << std::endl;
        log << "  Public key size: " << tradPubKeySize << " bytes" << std::endl;
        log << "  Signature size: " << tradSignatureSize << " bytes (" 
            << std::fixed << std::setprecision(1) << (static_cast<double>(tradSignatureSize) / tradTotalSize * 100) << "%)" << std::endl;
        log << "  Input data size: " << tradInputDataSize << " bytes (" 
            << std::fixed << std::setprecision(1) << (static_cast<double>(tradInputDataSize) / tradTotalSize * 100) << "%)" << std::endl;
        log << "  Field headers/overhead: " << (tradTotalSize - tradPubKeySize - tradSignatureSize - tradInputDataSize) 
            << " bytes" << std::endl;
        
        // Traditional transaction has NO ZKP proof
        log << "  ZKP proof size: 0 bytes (not applicable)" << std::endl;
        log << "  Proof percentage: 0% (digital signatures only)" << std::endl;
        
        // === ZKP TRANSACTION ANALYSIS ===
        log << "\n=== ZKP TRANSACTION BREAKDOWN ===" << std::endl;
        
        // Test multiple ZKP proof sizes with detailed analysis
        std::vector<size_t> zkpProofSizes = {128, 256, 512, 1024, 2048, 4096};
        
        for (auto proofSize : zkpProofSizes) {
            log << "\n--- ZKP Proof Size: " << proofSize << " bytes ---" << std::endl;
            
            // Create ZKP transaction
            STTx zkpTx(ttZK_DEPOSIT, [&](STObject& obj) {
                obj.setAccountID(sfAccount, account);
                obj.setFieldAmount(sfAmount, STAmount{1000000ULL});
                obj.setFieldU32(sfSequence, 1);
                obj.setFieldAmount(sfFee, STAmount{50ULL});
                obj.setFieldVL(sfSigningPubKey, keyPair.first.slice());
                
                // ZKP-specific fields
                obj.setFieldH256(sfCommitment, zkp::ZkProver::generateRandomUint256());
                obj.setFieldH256(sfNullifier, zkp::ZkProver::generateRandomUint256());
                obj.setFieldVL(sfZKProof, std::vector<unsigned char>(proofSize, 0x42));
                obj.setFieldU32(sfTreeDepth, 32);
                obj.setFieldU64(sfLeafIndex, 12345);
            });
            zkpTx.sign(keyPair.first, keyPair.second);
            
            // Analyze ZKP transaction components
            Serializer zkpSer;
            zkpTx.add(zkpSer);
            
            size_t zkpTotalSize = zkpSer.size();
            size_t zkpPubKeySize = keyPair.first.size();
            size_t zkpSignatureSize = zkpTx.getFieldVL(sfTxnSignature).size();
            size_t zkpProofActualSize = zkpTx.getFieldVL(sfZKProof).size();
            
            // Calculate ZKP-specific field sizes
            size_t commitmentSize = 32; // sfCommitment
            size_t nullifierSize = 32;  // sfNullifier
            size_t valueCommitmentSize = zkpTx.getFieldVL(sfValueCommitment).size();
            size_t merkleRootSize = 32; // sfMerkleRoot
            size_t randomnessSize = 32; // sfRandomness
            size_t noteValueSize = 8;   // sfNoteValue
            size_t treeDepthSize = 4;   // sfTreeDepth
            size_t leafIndexSize = 8;   // sfLeafIndex
            
            size_t zkpFieldsTotal = commitmentSize + nullifierSize + zkpProofActualSize + 
                                valueCommitmentSize + merkleRootSize + randomnessSize + 
                                noteValueSize + treeDepthSize + leafIndexSize;
            
            size_t baseTransactionSize = zkpTotalSize - zkpFieldsTotal;
            size_t fieldHeaders = zkpTotalSize - baseTransactionSize - zkpFieldsTotal;
            
            // Output detailed breakdown
            log << "ZKP Transaction Components:" << std::endl;
            log << "  Total transaction size: " << zkpTotalSize << " bytes" << std::endl;
            log << "  Base transaction size: " << baseTransactionSize << " bytes (" 
                << std::fixed << std::setprecision(1) << (static_cast<double>(baseTransactionSize) / zkpTotalSize * 100) << "%)" << std::endl;
            
            log << "  ZKP-specific fields:" << std::endl;
            log << "    ZKP proof: " << zkpProofActualSize << " bytes (" 
                << std::fixed << std::setprecision(1) << (static_cast<double>(zkpProofActualSize) / zkpTotalSize * 100) << "%)" << std::endl;
            log << "    Commitment: " << commitmentSize << " bytes" << std::endl;
            log << "    Nullifier: " << nullifierSize << " bytes" << std::endl;
            log << "    Value commitment: " << valueCommitmentSize << " bytes" << std::endl;
            log << "    Merkle root: " << merkleRootSize << " bytes" << std::endl;
            log << "    Randomness: " << randomnessSize << " bytes" << std::endl;
            log << "    Note value: " << noteValueSize << " bytes" << std::endl;
            log << "    Tree depth: " << treeDepthSize << " bytes" << std::endl;
            log << "    Leaf index: " << leafIndexSize << " bytes" << std::endl;
            log << "    ZKP fields total: " << zkpFieldsTotal << " bytes (" 
                << std::fixed << std::setprecision(1) << (static_cast<double>(zkpFieldsTotal) / zkpTotalSize * 100) << "%)" << std::endl;
            
            log << "  Cryptographic components:" << std::endl;
            log << "    Public key: " << zkpPubKeySize << " bytes" << std::endl;
            log << "    Digital signature: " << zkpSignatureSize << " bytes" << std::endl;
            log << "    Field headers/overhead: " << fieldHeaders << " bytes" << std::endl;
            
            // Calculate input vs proof ratios
            size_t zkpInputSize = baseTransactionSize + (zkpFieldsTotal - zkpProofActualSize);
            double proofToInputRatio = static_cast<double>(zkpProofActualSize) / zkpInputSize;
            double proofToTotalRatio = static_cast<double>(zkpProofActualSize) / zkpTotalSize;
            
            log << "  Size ratios:" << std::endl;
            log << "    Proof vs input data: " << std::fixed << std::setprecision(2) << proofToInputRatio << ":1" << std::endl;
            log << "    Proof vs total transaction: " << std::fixed << std::setprecision(2) << proofToTotalRatio << ":1 (" 
                << std::fixed << std::setprecision(1) << (proofToTotalRatio * 100) << "%)" << std::endl;
            
            // Comparison with traditional
            double sizeOverhead = static_cast<double>(zkpTotalSize) / tradTotalSize;
            double proofOverhead = static_cast<double>(zkpProofActualSize) / tradSignatureSize;
            
            log << "  vs Traditional transaction:" << std::endl;
            log << "    Total size overhead: " << std::fixed << std::setprecision(2) << sizeOverhead << "x larger" << std::endl;
            log << "    ZKP proof vs signature: " << std::fixed << std::setprecision(2) << proofOverhead 
                << "x larger (" << zkpProofActualSize << " vs " << tradSignatureSize << " bytes)" << std::endl;
        }
        
        // === INPUT DATA SCALING ANALYSIS ===
        log << "\n=== INPUT DATA SCALING ANALYSIS ===" << std::endl;
        
        // Test how input data size affects total transaction size
        std::vector<size_t> inputSizes = {10, 50, 100, 500, 1000}; // bytes of additional input data
        const size_t FIXED_PROOF_SIZE = 256; // Use fixed proof size for this test
        
        for (auto inputSize : inputSizes) {
            // Create transaction with variable input data size
            std::vector<unsigned char> extraData(inputSize, 0x55);
            
            STTx zkpTx(ttZK_DEPOSIT, [&](STObject& obj) {
                obj.setAccountID(sfAccount, account);
                obj.setFieldAmount(sfAmount, STAmount{1000000ULL});
                obj.setFieldU32(sfSequence, 1);
                obj.setFieldAmount(sfFee, STAmount{50ULL});
                obj.setFieldVL(sfSigningPubKey, keyPair.first.slice());
                
                // Fixed ZKP fields
                obj.setFieldH256(sfCommitment, zkp::ZkProver::generateRandomUint256());
                obj.setFieldH256(sfNullifier, zkp::ZkProver::generateRandomUint256());
                obj.setFieldVL(sfZKProof, std::vector<unsigned char>(FIXED_PROOF_SIZE, 0x42));
                
                // Variable input data
                obj.setFieldVL(sfMemoData, extraData); // Use memo field for extra input data
            });
            zkpTx.sign(keyPair.first, keyPair.second);
            
            Serializer ser;
            zkpTx.add(ser);
            
            size_t totalSize = ser.size();
            double inputToProofRatio = static_cast<double>(inputSize) / FIXED_PROOF_SIZE;
            double inputPercentage = static_cast<double>(inputSize) / totalSize * 100;
            
            log << "Input size: " << inputSize << " bytes → Total: " << totalSize 
                << " bytes, Input/Proof ratio: " << std::fixed << std::setprecision(2) << inputToProofRatio 
                << ", Input: " << std::fixed << std::setprecision(1) << inputPercentage << "%" << std::endl;
        }
        
        // === NETWORK EFFICIENCY ANALYSIS ===
        log << "\n=== NETWORK EFFICIENCY ANALYSIS ===" << std::endl;
        
        // Calculate efficiency metrics
        log << "Efficiency metrics (Traditional baseline = 100%):" << std::endl;
        
        for (auto proofSize : zkpProofSizes) {
            // Create minimal ZKP transaction for efficiency calculation
            STTx zkpTx(ttZK_DEPOSIT, [&](STObject& obj) {
                obj.setAccountID(sfAccount, account);
                obj.setFieldAmount(sfAmount, STAmount{1000000ULL});
                obj.setFieldU32(sfSequence, 1);
                obj.setFieldAmount(sfFee, STAmount{50ULL});
                obj.setFieldVL(sfSigningPubKey, keyPair.first.slice());
                obj.setFieldH256(sfCommitment, zkp::ZkProver::generateRandomUint256());
                obj.setFieldH256(sfNullifier, zkp::ZkProver::generateRandomUint256());
                obj.setFieldVL(sfZKProof, std::vector<unsigned char>(proofSize, 0x42));
            });
            zkpTx.sign(keyPair.first, keyPair.second);
            
            Serializer zkpSer;
            zkpTx.add(zkpSer);
            
            // Calculate efficiency metrics
            double storageEfficiency = static_cast<double>(tradTotalSize) / zkpSer.size() * 100;
            double bandwidthEfficiency = storageEfficiency; // Same as storage for this analysis
            double bytesPerPrivacyBit = static_cast<double>(zkpSer.size() - tradTotalSize) / (proofSize * 8); // Assume 1 bit privacy per proof bit
            
            log << "  " << proofSize << "-byte proof:" << std::endl;
            log << "    Storage efficiency: " << std::fixed << std::setprecision(1) << storageEfficiency << "%" << std::endl;
            log << "    Bandwidth efficiency: " << std::fixed << std::setprecision(1) << bandwidthEfficiency << "%" << std::endl;
            log << "    Bytes per privacy bit: " << std::fixed << std::setprecision(3) << bytesPerPrivacyBit << std::endl;
            log << "    Privacy cost: " << (zkpSer.size() - tradTotalSize) << " extra bytes" << std::endl;
        }
        
        // === SUMMARY TABLE ===
        log << "\n=== SUMMARY COMPARISON TABLE ===" << std::endl;
        log << "| Proof Size | Total Size | vs Traditional | Proof % | Input % | Efficiency |" << std::endl;
        log << "|------------|------------|----------------|---------|---------|------------|" << std::endl;
        log << "| Traditional| " << tradTotalSize << " bytes | 1.0x | 0% | 100% | 100% |" << std::endl;
        
        for (auto proofSize : zkpProofSizes) {
            STTx zkpTx(ttZK_DEPOSIT, [&](STObject& obj) {
                obj.setAccountID(sfAccount, account);
                obj.setFieldAmount(sfAmount, STAmount{1000000ULL});
                obj.setFieldU32(sfSequence, 1);
                obj.setFieldAmount(sfFee, STAmount{50ULL});
                obj.setFieldVL(sfSigningPubKey, keyPair.first.slice());
                obj.setFieldH256(sfCommitment, zkp::ZkProver::generateRandomUint256());
                obj.setFieldH256(sfNullifier, zkp::ZkProver::generateRandomUint256());
                obj.setFieldVL(sfZKProof, std::vector<unsigned char>(proofSize, 0x42));
            });
            zkpTx.sign(keyPair.first, keyPair.second);
            
            Serializer zkpSer;
            zkpTx.add(zkpSer);
            
            double sizeRatio = static_cast<double>(zkpSer.size()) / tradTotalSize;
            double proofPercent = static_cast<double>(proofSize) / zkpSer.size() * 100;
            double inputPercent = static_cast<double>(zkpSer.size() - proofSize) / zkpSer.size() * 100;
            double efficiency = static_cast<double>(tradTotalSize) / zkpSer.size() * 100;
            
            log << "| " << proofSize << " bytes | " << zkpSer.size() << " bytes | " 
                << std::fixed << std::setprecision(1) << sizeRatio << "x | " 
                << std::fixed << std::setprecision(0) << proofPercent << "% | " 
                << std::fixed << std::setprecision(0) << inputPercent << "% | " 
                << std::fixed << std::setprecision(0) << efficiency << "% |" << std::endl;
        }
    }
};

BEAST_DEFINE_TESTSUITE(ZKTransaction, ripple_app, ripple);

} // namespace ripple
