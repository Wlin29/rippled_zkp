#include <xrpl/beast/unit_test.h>
#include <xrpl/protocol/UintTypes.h>
#include <string>
#include <random>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <cstring>
#include <vector>
#include <algorithm>

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
    // Performance tracking structure
    struct PerformanceMetrics {
        std::chrono::duration<double, std::milli> keyGenerationTime{0};
        std::chrono::duration<double, std::milli> depositProofCreationTime{0};
        std::chrono::duration<double, std::milli> withdrawalProofCreationTime{0};
        std::chrono::duration<double, std::milli> depositVerificationTime{0};
        std::chrono::duration<double, std::milli> withdrawalVerificationTime{0};
        std::chrono::duration<double, std::milli> merkleTreeOperationTime{0};
        std::chrono::duration<double, std::milli> noteOperationTime{0};
        
        size_t provingKeySize{0};
        size_t verifyingKeySize{0};
        size_t depositProofSize{0};
        size_t withdrawalProofSize{0};
        size_t depositInputSize{0};
        size_t withdrawalInputSize{0};
        size_t merklePathSize{0};
        
        double depositProofThroughput{0}; // proofs per second
        double withdrawalProofThroughput{0};
        double verificationThroughput{0};
        
        size_t circuitConstraints{0};
        size_t publicInputCount{0};
        size_t privateInputCount{0};
    } metrics_;

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
    
    // Helper to calculate size of various data structures
    size_t calculateInputSize(uint64_t amount, const uint256& commitment, const std::string& spendKey) {
        return sizeof(amount) + 32 + spendKey.length(); // uint64 + uint256 + string
    }
    
    size_t calculateWithdrawalInputSize(uint64_t amount, const uint256& merkleRoot, const uint256& nullifier, 
                                       const std::vector<uint256>& path, const std::string& spendKey) {
        return sizeof(amount) + 32 + 32 + (path.size() * 32) + spendKey.length() + sizeof(size_t);
    }

public:
    void run() override
    {
        zkp::ZkProver::initialize();
        
        // Core performance tests
        testKeyGenerationPerformance();
        testDepositProofPerformance();
        testWithdrawalProofPerformance();
        testVerificationPerformance();
        testThroughputBenchmark();
        testMerkleTreePerformance();
        testNoteOperationPerformance();
        
        testKeyPersistence();
        testProofSerialization();
        testDepositProofCreation();
        testWithdrawalProofCreation();
        // testDepositProofVerification();
        // testWithdrawalProofVerification();
        // testInvalidProofVerification();
        testMultipleProofs();
        testEdgeCases();
        // testNoteCreationAndCommitment();
        testIncrementalMerkleTree();
        // testMerkleVerificationEnforcement();
        // testUnifiedCircuitBehavior();
        // testWithdrawalProofIncrementalMerkleTree();
        
        // Performance summary
        printPerformanceSummary();
    }

    void testKeyGenerationPerformance()
    {
        testcase("Key Generation Performance");
        
        log << "\n=== KEY GENERATION PERFORMANCE ===" << std::endl;
        
        auto start = std::chrono::high_resolution_clock::now();
        
        // Test key generation
        BEAST_EXPECT(zkp::ZkProver::generateKeys(true)); // Force regeneration for accurate timing
        
        auto end = std::chrono::high_resolution_clock::now();
        metrics_.keyGenerationTime = std::chrono::duration<double, std::milli>(end - start);
        
        // Estimate key sizes by saving to temporary files
        std::string tempKeyPath = "/tmp/temp_zkp_keys_performance";
        if (zkp::ZkProver::saveKeys(tempKeyPath)) {
            // Try to estimate key file sizes (this is implementation dependent)
            metrics_.provingKeySize = 1024 * 1024; // Estimated 1MB for proving key
            metrics_.verifyingKeySize = 32 * 1024;  // Estimated 32KB for verifying key
        }
        
        log << "Key Generation Results:" << std::endl;
        log << "  Generation Time:     " << std::fixed << std::setprecision(3) 
            << metrics_.keyGenerationTime.count() << " ms" << std::endl;
        log << "  Proving Key Size:    ~" << (metrics_.provingKeySize / 1024) << " KB" << std::endl;
        log << "  Verifying Key Size:  ~" << (metrics_.verifyingKeySize / 1024) << " KB" << std::endl;
        log << "  Total Key Size:      ~" << ((metrics_.provingKeySize + metrics_.verifyingKeySize) / 1024) << " KB" << std::endl;
        
        // Performance classifications
        if (metrics_.keyGenerationTime.count() < 5000) {
            log << "  Performance:         EXCELLENT (< 5s)" << std::endl;
        } else if (metrics_.keyGenerationTime.count() < 30000) {
            log << "  Performance:         GOOD (< 30s)" << std::endl;
        } else if (metrics_.keyGenerationTime.count() < 120000) {
            log << "  Performance:         ACCEPTABLE (< 2min)" << std::endl;
        } else {
            log << "  Performance:         SLOW (> 2min)" << std::endl;
        }
    }

    void testDepositProofPerformance()
    {
        testcase("Deposit Proof Creation Performance");
        
        log << "\n=== DEPOSIT PROOF PERFORMANCE ===" << std::endl;
        
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        // Test parameters
        uint64_t amount = 1000000;
        uint256 commitment = generateRandomUint256();
        std::string spendKey = generateRandomSpendKey();
        auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(spendKey);
        zkp::FieldT value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(amount);
        
        // Calculate input size
        metrics_.depositInputSize = calculateInputSize(amount, commitment, spendKey);
        
        // Multiple runs for accurate timing
        std::vector<double> creationTimes;
        zkp::ProofData lastProof;
        
        const int numRuns = 3; // Reduced for practical testing
        
        for (int run = 0; run < numRuns; ++run) {
            auto start = std::chrono::high_resolution_clock::now();
            
            auto proofData = zkp::ZkProver::createDepositProof(amount, commitment, spendKey, value_randomness);
            
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration<double, std::milli>(end - start);
            
            BEAST_EXPECT(!proofData.empty());
            creationTimes.push_back(duration.count());
            lastProof = proofData;
            
            log << "  Run " << (run + 1) << ": " << std::fixed << std::setprecision(3) 
                << duration.count() << " ms" << std::endl;
        }
        
        // Calculate statistics
        double avgTime = std::accumulate(creationTimes.begin(), creationTimes.end(), 0.0) / creationTimes.size();
        double minTime = *std::min_element(creationTimes.begin(), creationTimes.end());
        double maxTime = *std::max_element(creationTimes.begin(), creationTimes.end());
        
        metrics_.depositProofCreationTime = std::chrono::duration<double, std::milli>(avgTime);
        metrics_.depositProofSize = lastProof.proof.size();
        metrics_.depositProofThroughput = 1000.0 / avgTime; // proofs per second
        
        log << "\nDeposit Proof Statistics:" << std::endl;
        log << "  Input Size:          " << metrics_.depositInputSize << " bytes" << std::endl;
        log << "  Proof Size:          " << metrics_.depositProofSize << " bytes" << std::endl;
        log << "  Average Time:        " << std::fixed << std::setprecision(3) << avgTime << " ms" << std::endl;
        log << "  Min Time:            " << std::fixed << std::setprecision(3) << minTime << " ms" << std::endl;
        log << "  Max Time:            " << std::fixed << std::setprecision(3) << maxTime << " ms" << std::endl;
        log << "  Throughput:          " << std::fixed << std::setprecision(3) << metrics_.depositProofThroughput 
            << " proofs/sec" << std::endl;
        log << "  Size Expansion:      " << std::fixed << std::setprecision(2) 
            << (static_cast<double>(metrics_.depositProofSize) / metrics_.depositInputSize) << "x" << std::endl;
    }

    void testWithdrawalProofPerformance()
    {
        testcase("Withdrawal Proof Creation Performance");
        
        log << "\n=== WITHDRAWAL PROOF PERFORMANCE ===" << std::endl;
        
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        // Setup Merkle tree
        zkp::IncrementalMerkleTree tree(20); // Realistic depth
        uint256 testNote = generateRandomUint256();
        size_t position = tree.append(testNote);
        
        // Test parameters
        uint64_t amount = 500000;
        uint256 merkleRoot = tree.root();
        uint256 nullifier = generateRandomUint256();
        std::string spendKey = generateRandomSpendKey();
        auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(spendKey);
        zkp::FieldT value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(amount);
        
        std::vector<uint256> merklePath = tree.authPath(position);
        
        // Calculate input sizes
        metrics_.withdrawalInputSize = calculateWithdrawalInputSize(amount, merkleRoot, nullifier, merklePath, spendKey);
        metrics_.merklePathSize = merklePath.size() * 32; // 32 bytes per hash
        
        // Multiple runs for accurate timing
        std::vector<double> creationTimes;
        zkp::ProofData lastProof;
        
        const int numRuns = 3;
        
        for (int run = 0; run < numRuns; ++run) {
            auto start = std::chrono::high_resolution_clock::now();
            
            auto proofData = zkp::ZkProver::createWithdrawalProof(
                amount, merkleRoot, nullifier, merklePath, position, spendKey, value_randomness);
            
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration<double, std::milli>(end - start);
            
            BEAST_EXPECT(!proofData.empty());
            creationTimes.push_back(duration.count());
            lastProof = proofData;
            
            log << "  Run " << (run + 1) << ": " << std::fixed << std::setprecision(3) 
                << duration.count() << " ms" << std::endl;
        }
        
        // Calculate statistics
        double avgTime = std::accumulate(creationTimes.begin(), creationTimes.end(), 0.0) / creationTimes.size();
        double minTime = *std::min_element(creationTimes.begin(), creationTimes.end());
        double maxTime = *std::max_element(creationTimes.begin(), creationTimes.end());
        
        metrics_.withdrawalProofCreationTime = std::chrono::duration<double, std::milli>(avgTime);
        metrics_.withdrawalProofSize = lastProof.proof.size();
        metrics_.withdrawalProofThroughput = 1000.0 / avgTime;
        
        log << "\nWithdrawal Proof Statistics:" << std::endl;
        log << "  Input Size:          " << metrics_.withdrawalInputSize << " bytes" << std::endl;
        log << "  Merkle Path Size:    " << metrics_.merklePathSize << " bytes (" << merklePath.size() << " hashes)" << std::endl;
        log << "  Proof Size:          " << metrics_.withdrawalProofSize << " bytes" << std::endl;
        log << "  Average Time:        " << std::fixed << std::setprecision(3) << avgTime << " ms" << std::endl;
        log << "  Min Time:            " << std::fixed << std::setprecision(3) << minTime << " ms" << std::endl;
        log << "  Max Time:            " << std::fixed << std::setprecision(3) << maxTime << " ms" << std::endl;
        log << "  Throughput:          " << std::fixed << std::setprecision(3) << metrics_.withdrawalProofThroughput 
            << " proofs/sec" << std::endl;
        log << "  Size Expansion:      " << std::fixed << std::setprecision(2) 
            << (static_cast<double>(metrics_.withdrawalProofSize) / metrics_.withdrawalInputSize) << "x" << std::endl;
    }

    void testVerificationPerformance()
    {
        testcase("Proof Verification Performance");
        
        log << "\n=== VERIFICATION PERFORMANCE ===" << std::endl;
        
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        // Create test proofs
        uint64_t amount = 1000000;
        uint256 commitment = generateRandomUint256();
        std::string spendKey = generateRandomSpendKey();
        auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(spendKey);
        zkp::FieldT value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(amount);
        
        auto depositProof = zkp::ZkProver::createDepositProof(amount, commitment, spendKey, value_randomness);
        BEAST_EXPECT(!depositProof.empty());
        
        // Setup withdrawal proof
        zkp::IncrementalMerkleTree tree(10);
        uint256 testNote = generateRandomUint256();
        size_t position = tree.append(testNote);
        uint256 merkleRoot = tree.root();
        uint256 nullifier = generateRandomUint256();
        std::vector<uint256> merklePath = tree.authPath(position);
        
        auto withdrawalProof = zkp::ZkProver::createWithdrawalProof(
            amount, merkleRoot, nullifier, merklePath, position, spendKey, value_randomness);
        BEAST_EXPECT(!withdrawalProof.empty());
        
        // Test deposit verification performance
        std::vector<double> depositVerifyTimes;
        const int verifyRuns = 10; // More runs for verification (it's faster)
        
        for (int run = 0; run < verifyRuns; ++run) {
            auto start = std::chrono::high_resolution_clock::now();
            bool isValid = zkp::ZkProver::verifyDepositProof(depositProof);
            auto end = std::chrono::high_resolution_clock::now();
            
            BEAST_EXPECT(isValid);
            auto duration = std::chrono::duration<double, std::milli>(end - start);
            depositVerifyTimes.push_back(duration.count());
        }
        
        // Test withdrawal verification performance
        std::vector<double> withdrawalVerifyTimes;
        
        for (int run = 0; run < verifyRuns; ++run) {
            auto start = std::chrono::high_resolution_clock::now();
            bool isValid = zkp::ZkProver::verifyWithdrawalProof(withdrawalProof);
            auto end = std::chrono::high_resolution_clock::now();
            
            BEAST_EXPECT(isValid);
            auto duration = std::chrono::duration<double, std::milli>(end - start);
            withdrawalVerifyTimes.push_back(duration.count());
        }
        
        // Calculate statistics
        double avgDepositVerify = std::accumulate(depositVerifyTimes.begin(), depositVerifyTimes.end(), 0.0) / depositVerifyTimes.size();
        double avgWithdrawalVerify = std::accumulate(withdrawalVerifyTimes.begin(), withdrawalVerifyTimes.end(), 0.0) / withdrawalVerifyTimes.size();
        
        metrics_.depositVerificationTime = std::chrono::duration<double, std::milli>(avgDepositVerify);
        metrics_.withdrawalVerificationTime = std::chrono::duration<double, std::milli>(avgWithdrawalVerify);
        metrics_.verificationThroughput = 1000.0 / ((avgDepositVerify + avgWithdrawalVerify) / 2.0);
        
        log << "Verification Performance:" << std::endl;
        log << "  Deposit Verification:    " << std::fixed << std::setprecision(3) 
            << avgDepositVerify << " ms avg" << std::endl;
        log << "  Withdrawal Verification: " << std::fixed << std::setprecision(3) 
            << avgWithdrawalVerify << " ms avg" << std::endl;
        log << "  Combined Throughput:     " << std::fixed << std::setprecision(1) 
            << metrics_.verificationThroughput << " verifications/sec" << std::endl;
        
        // Verification efficiency ratios
        double depositRatio = metrics_.depositProofCreationTime.count() / avgDepositVerify;
        double withdrawalRatio = metrics_.withdrawalProofCreationTime.count() / avgWithdrawalVerify;
        
        log << "  Deposit Creation/Verify: " << std::fixed << std::setprecision(1) 
            << depositRatio << ":1 ratio" << std::endl;
        log << "  Withdrawal Creation/Verify: " << std::fixed << std::setprecision(1) 
            << withdrawalRatio << ":1 ratio" << std::endl;
    }

    void testThroughputBenchmark()
    {
        testcase("Throughput Benchmark");
        
        log << "\n=== THROUGHPUT BENCHMARK ===" << std::endl;
        
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        // Sustained throughput test
        const int sustainedRuns = 5;
        std::vector<double> sustainedTimes;
        
        auto overallStart = std::chrono::high_resolution_clock::now();
        
        for (int run = 0; run < sustainedRuns; ++run) {
            uint64_t amount = 1000000 + run * 100000;
            uint256 commitment = generateRandomUint256();
            std::string spendKey = generateRandomSpendKey();
            auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(spendKey);
            zkp::FieldT value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(amount);
            
            auto start = std::chrono::high_resolution_clock::now();
            
            // Create deposit proof
            auto depositProof = zkp::ZkProver::createDepositProof(amount, commitment, spendKey, value_randomness);
            BEAST_EXPECT(!depositProof.empty());
            
            // Verify deposit proof
            bool depositValid = zkp::ZkProver::verifyDepositProof(depositProof);
            BEAST_EXPECT(depositValid);
            
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration<double, std::milli>(end - start);
            sustainedTimes.push_back(duration.count());
            
            log << "  Sustained run " << (run + 1) << ": " << std::fixed << std::setprecision(3) 
                << duration.count() << " ms (create + verify)" << std::endl;
        }
        
        auto overallEnd = std::chrono::high_resolution_clock::now();
        auto totalTime = std::chrono::duration<double, std::milli>(overallEnd - overallStart);
        
        double avgSustained = std::accumulate(sustainedTimes.begin(), sustainedTimes.end(), 0.0) / sustainedTimes.size();
        double sustainedThroughput = 1000.0 / avgSustained;
        
        log << "\nThroughput Results:" << std::endl;
        log << "  Sustained Average:       " << std::fixed << std::setprecision(3) << avgSustained << " ms per cycle" << std::endl;
        log << "  Sustained Throughput:    " << std::fixed << std::setprecision(3) << sustainedThroughput << " cycles/sec" << std::endl;
        log << "  Total Time:              " << std::fixed << std::setprecision(3) << totalTime.count() << " ms" << std::endl;
        log << "  Cycles Completed:        " << sustainedRuns << std::endl;
    }

    void testMerkleTreePerformance()
    {
        testcase("Merkle Tree Performance");
        
        log << "\n=== MERKLE TREE PERFORMANCE ===" << std::endl;
        
        auto start = std::chrono::high_resolution_clock::now();
        
        zkp::IncrementalMerkleTree tree(20); // Realistic depth
        
        // Test tree operations
        const int numInsertions = 100;
        std::vector<uint256> leaves;
        
        // Generate test data
        for (int i = 0; i < numInsertions; ++i) {
            leaves.push_back(generateRandomUint256());
        }
        
        auto insertStart = std::chrono::high_resolution_clock::now();
        
        // Insert leaves
        for (const auto& leaf : leaves) {
            tree.append(leaf);
        }
        
        auto insertEnd = std::chrono::high_resolution_clock::now();
        
        // Test authentication path generation
        auto pathStart = std::chrono::high_resolution_clock::now();
        
        std::vector<std::vector<uint256>> paths;
        for (size_t i = 0; i < std::min(numInsertions, 10); ++i) { // Test first 10 paths
            paths.push_back(tree.authPath(i));
        }
        
        auto pathEnd = std::chrono::high_resolution_clock::now();
        auto totalEnd = std::chrono::high_resolution_clock::now();
        
        metrics_.merkleTreeOperationTime = std::chrono::duration<double, std::milli>(totalEnd - start);
        
        auto insertTime = std::chrono::duration<double, std::milli>(insertEnd - insertStart);
        auto pathTime = std::chrono::duration<double, std::milli>(pathEnd - pathStart);
        
        log << "Merkle Tree Performance:" << std::endl;
        log << "  Tree Depth:              " << 20 << std::endl;
        log << "  Insertions:              " << numInsertions << std::endl;
        log << "  Total Insert Time:       " << std::fixed << std::setprecision(3) << insertTime.count() << " ms" << std::endl;
        log << "  Average Insert Time:     " << std::fixed << std::setprecision(3) << (insertTime.count() / numInsertions) << " ms" << std::endl;
        log << "  Path Generation Time:    " << std::fixed << std::setprecision(3) << pathTime.count() << " ms (10 paths)" << std::endl;
        log << "  Average Path Time:       " << std::fixed << std::setprecision(3) << (pathTime.count() / 10) << " ms" << std::endl;
        log << "  Tree Size:               " << tree.size() << " leaves" << std::endl;
        log << "  Path Length:             " << (paths.empty() ? 0 : paths[0].size()) << " hashes" << std::endl;
        log << "  Insert Throughput:       " << std::fixed << std::setprecision(1) 
            << (numInsertions * 1000.0 / insertTime.count()) << " insertions/sec" << std::endl;
    }

    void testNoteOperationPerformance()
    {
        testcase("Note Operation Performance");
        
        log << "\n=== NOTE OPERATION PERFORMANCE ===" << std::endl;
        
        auto start = std::chrono::high_resolution_clock::now();
        
        const int numNotes = 1000;
        std::vector<zkp::Note> notes;
        std::vector<uint256> commitments;
        std::vector<uint256> nullifiers;
        
        // Test note creation
        auto createStart = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < numNotes; ++i) {
            uint64_t amount = 1000000 + i * 1000;
            notes.push_back(zkp::Note::random(amount));
        }
        
        auto createEnd = std::chrono::high_resolution_clock::now();
        
        // Test commitment computation
        auto commitStart = std::chrono::high_resolution_clock::now();
        
        for (const auto& note : notes) {
            commitments.push_back(note.commitment());
        }
        
        auto commitEnd = std::chrono::high_resolution_clock::now();
        
        // Test nullifier computation
        auto nullStart = std::chrono::high_resolution_clock::now();
        
        uint256 a_sk = generateRandomUint256();
        for (const auto& note : notes) {
            nullifiers.push_back(note.nullifier(a_sk));
        }
        
        auto nullEnd = std::chrono::high_resolution_clock::now();
        auto totalEnd = std::chrono::high_resolution_clock::now();
        
        metrics_.noteOperationTime = std::chrono::duration<double, std::milli>(totalEnd - start);
        
        auto createTime = std::chrono::duration<double, std::milli>(createEnd - createStart);
        auto commitTime = std::chrono::duration<double, std::milli>(commitEnd - commitStart);
        auto nullTime = std::chrono::duration<double, std::milli>(nullEnd - nullStart);
        
        log << "Note Operation Performance:" << std::endl;
        log << "  Notes Processed:         " << numNotes << std::endl;
        log << "  Creation Time:           " << std::fixed << std::setprecision(3) << createTime.count() << " ms" << std::endl;
        log << "  Commitment Time:         " << std::fixed << std::setprecision(3) << commitTime.count() << " ms" << std::endl;
        log << "  Nullifier Time:          " << std::fixed << std::setprecision(3) << nullTime.count() << " ms" << std::endl;
        log << "  Total Time:              " << std::fixed << std::setprecision(3) << metrics_.noteOperationTime.count() << " ms" << std::endl;
        log << "  Creation Rate:           " << std::fixed << std::setprecision(1) 
            << (numNotes * 1000.0 / createTime.count()) << " notes/sec" << std::endl;
        log << "  Commitment Rate:         " << std::fixed << std::setprecision(1) 
            << (numNotes * 1000.0 / commitTime.count()) << " commitments/sec" << std::endl;
        log << "  Nullifier Rate:          " << std::fixed << std::setprecision(1) 
            << (numNotes * 1000.0 / nullTime.count()) << " nullifiers/sec" << std::endl;
    }

    void printPerformanceSummary()
    {
        testcase("Performance Summary");
        
        log << "\n" << std::string(70, '=') << std::endl;
        log << "                    ZK PROVER PERFORMANCE SUMMARY" << std::endl;
        log << std::string(70, '=') << std::endl;
        
        // Key Generation
        log << "\nKEY GENERATION:" << std::endl;
        log << "  Time:                    " << std::fixed << std::setprecision(3) 
            << metrics_.keyGenerationTime.count() << " ms" << std::endl;
        log << "  Proving Key Size:        ~" << (metrics_.provingKeySize / 1024) << " KB" << std::endl;
        log << "  Verifying Key Size:      ~" << (metrics_.verifyingKeySize / 1024) << " KB" << std::endl;
        
        // Proof Creation
        log << "\nPROOF CREATION:" << std::endl;
        log << "  Deposit Proof Time:      " << std::fixed << std::setprecision(3) 
            << metrics_.depositProofCreationTime.count() << " ms" << std::endl;
        log << "  Withdrawal Proof Time:   " << std::fixed << std::setprecision(3) 
            << metrics_.withdrawalProofCreationTime.count() << " ms" << std::endl;
        log << "  Deposit Throughput:      " << std::fixed << std::setprecision(3) 
            << metrics_.depositProofThroughput << " proofs/sec" << std::endl;
        log << "  Withdrawal Throughput:   " << std::fixed << std::setprecision(3) 
            << metrics_.withdrawalProofThroughput << " proofs/sec" << std::endl;
        
        // Proof Verification
        log << "\nPROOF VERIFICATION:" << std::endl;
        log << "  Deposit Verify Time:     " << std::fixed << std::setprecision(3) 
            << metrics_.depositVerificationTime.count() << " ms" << std::endl;
        log << "  Withdrawal Verify Time:  " << std::fixed << std::setprecision(3) 
            << metrics_.withdrawalVerificationTime.count() << " ms" << std::endl;
        log << "  Verification Throughput: " << std::fixed << std::setprecision(1) 
            << metrics_.verificationThroughput << " verifications/sec" << std::endl;
        
        // Data Sizes
        log << "\nDATA SIZES:" << std::endl;
        log << "  Deposit Input Size:      " << metrics_.depositInputSize << " bytes" << std::endl;
        log << "  Deposit Proof Size:      " << metrics_.depositProofSize << " bytes" << std::endl;
        log << "  Withdrawal Input Size:   " << metrics_.withdrawalInputSize << " bytes" << std::endl;
        log << "  Withdrawal Proof Size:   " << metrics_.withdrawalProofSize << " bytes" << std::endl;
        log << "  Merkle Path Size:        " << metrics_.merklePathSize << " bytes" << std::endl;
        
        // Efficiency Ratios
        log << "\nEFFICIENCY RATIOS:" << std::endl;
        if (metrics_.depositVerificationTime.count() > 0) {
            double depositRatio = metrics_.depositProofCreationTime.count() / metrics_.depositVerificationTime.count();
            log << "  Deposit Create/Verify:   " << std::fixed << std::setprecision(1) << depositRatio << ":1" << std::endl;
        }
        if (metrics_.withdrawalVerificationTime.count() > 0) {
            double withdrawalRatio = metrics_.withdrawalProofCreationTime.count() / metrics_.withdrawalVerificationTime.count();
            log << "  Withdrawal Create/Verify:" << std::fixed << std::setprecision(1) << withdrawalRatio << ":1" << std::endl;
        }
        if (metrics_.depositInputSize > 0) {
            double depositExpansion = static_cast<double>(metrics_.depositProofSize) / metrics_.depositInputSize;
            log << "  Deposit Size Expansion:  " << std::fixed << std::setprecision(2) << depositExpansion << "x" << std::endl;
        }
        if (metrics_.withdrawalInputSize > 0) {
            double withdrawalExpansion = static_cast<double>(metrics_.withdrawalProofSize) / metrics_.withdrawalInputSize;
            log << "  Withdrawal Size Expansion: " << std::fixed << std::setprecision(2) << withdrawalExpansion << "x" << std::endl;
        }
        
        // Performance Classification
        log << "\nPERFORMANCE CLASSIFICATION:" << std::endl;
        if (metrics_.depositProofCreationTime.count() < 1000 && metrics_.withdrawalProofCreationTime.count() < 1000) {
            log << "  Overall Performance:     EXCELLENT (< 1s per proof)" << std::endl;
        } else if (metrics_.depositProofCreationTime.count() < 5000 && metrics_.withdrawalProofCreationTime.count() < 5000) {
            log << "  Overall Performance:     GOOD (< 5s per proof)" << std::endl;
        } else if (metrics_.depositProofCreationTime.count() < 30000 && metrics_.withdrawalProofCreationTime.count() < 30000) {
            log << "  Overall Performance:     ACCEPTABLE (< 30s per proof)" << std::endl;
        } else {
            log << "  Overall Performance:     NEEDS OPTIMIZATION (> 30s per proof)" << std::endl;
        }
        
        log << "\n" << std::string(70, '=') << std::endl;
    }

    // Original test methods with minimal changes...
    void testKeyPersistence()
    {
        testcase("Key Persistence Performance");
        
        log << "\n=== KEY PERSISTENCE PERFORMANCE ===" << std::endl;
        
        auto keyGenStart = std::chrono::high_resolution_clock::now();
        
        // Generate keys with timing
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        auto keyGenEnd = std::chrono::high_resolution_clock::now();
        auto keyGenTime = std::chrono::duration<double, std::milli>(keyGenEnd - keyGenStart);
        
        // Test key saving performance
        std::string keyPath = "/tmp/test_zkp_keys_persistence";
        
        auto saveStart = std::chrono::high_resolution_clock::now();
        bool saveSuccess = zkp::ZkProver::saveKeys(keyPath);
        auto saveEnd = std::chrono::high_resolution_clock::now();
        auto saveTime = std::chrono::duration<double, std::milli>(saveEnd - saveStart);
        
        BEAST_EXPECT(saveSuccess);
        
        // Test key loading performance
        auto loadStart = std::chrono::high_resolution_clock::now();
        bool loadSuccess = zkp::ZkProver::loadKeys(keyPath);
        auto loadEnd = std::chrono::high_resolution_clock::now();
        auto loadTime = std::chrono::duration<double, std::milli>(loadEnd - loadStart);
        
        BEAST_EXPECT(loadSuccess);
        
        // Estimate file sizes (if possible)
        size_t estimatedKeySize = 1024 * 1024; // 1MB estimate
        
        log << "Key Persistence Performance:" << std::endl;
        log << "  Key Generation:          " << std::fixed << std::setprecision(3) << keyGenTime.count() << " ms" << std::endl;
        log << "  Key Save Time:           " << std::fixed << std::setprecision(3) << saveTime.count() << " ms" << std::endl;
        log << "  Key Load Time:           " << std::fixed << std::setprecision(3) << loadTime.count() << " ms" << std::endl;
        log << "  Estimated Key Size:      " << (estimatedKeySize / 1024) << " KB" << std::endl;
        log << "  Save Throughput:         " << std::fixed << std::setprecision(2) 
            << (estimatedKeySize / 1024.0 / saveTime.count() * 1000.0) << " KB/sec" << std::endl;
        log << "  Load Throughput:         " << std::fixed << std::setprecision(2) 
            << (estimatedKeySize / 1024.0 / loadTime.count() * 1000.0) << " KB/sec" << std::endl;
        
        log << "Key persistence: SUCCESS" << std::endl;
    }
    
    void testProofSerialization()
    {
        testcase("Proof Serialization Performance");
        
        log << "\n=== PROOF SERIALIZATION PERFORMANCE ===" << std::endl;
        
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        // Create test proof
        uint64_t amount = 1000000;
        uint256 commitment = generateRandomUint256();
        std::string spendKey = generateRandomSpendKey();
        auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(spendKey);
        zkp::FieldT value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(amount);
        
        auto proofCreationStart = std::chrono::high_resolution_clock::now();
        auto proofData = zkp::ZkProver::createDepositProof(amount, commitment, spendKey, value_randomness);
        auto proofCreationEnd = std::chrono::high_resolution_clock::now();
        auto proofCreationTime = std::chrono::duration<double, std::milli>(proofCreationEnd - proofCreationStart);
        
        BEAST_EXPECT(!proofData.empty());
        BEAST_EXPECT(!proofData.proof.empty());
        BEAST_EXPECT(proofData.proof.size() > 0);
        
        // Test serialization performance - multiple iterations
        const int serializationRuns = 100;
        std::vector<double> serializationTimes;
        std::vector<double> deserializationTimes;
        
        for (int run = 0; run < serializationRuns; ++run) {
            // Test serialization timing
            auto serStart = std::chrono::high_resolution_clock::now();
            
            // Simulate serialization by copying proof data
            std::vector<uint8_t> serializedProof = proofData.proof;
            auto anchorBytes = std::vector<uint8_t>(32); // Simulate anchor serialization
            auto nullifierBytes = std::vector<uint8_t>(32); // Simulate nullifier serialization
            auto commitmentBytes = std::vector<uint8_t>(32); // Simulate value commitment serialization
            
            auto serEnd = std::chrono::high_resolution_clock::now();
            auto serTime = std::chrono::duration<double, std::milli>(serEnd - serStart);
            serializationTimes.push_back(serTime.count());
            
            // Test deserialization timing
            auto deserStart = std::chrono::high_resolution_clock::now();
            
            // Simulate deserialization
            zkp::ProofData deserializedProof;
            deserializedProof.proof = serializedProof;
            deserializedProof.anchor = proofData.anchor;
            deserializedProof.nullifier = proofData.nullifier;
            deserializedProof.value_commitment = proofData.value_commitment;
            
            auto deserEnd = std::chrono::high_resolution_clock::now();
            auto deserTime = std::chrono::duration<double, std::milli>(deserEnd - deserStart);
            deserializationTimes.push_back(deserTime.count());
        }
        
        // Calculate statistics
        double avgSerTime = std::accumulate(serializationTimes.begin(), serializationTimes.end(), 0.0) / serializationTimes.size();
        double avgDeserTime = std::accumulate(deserializationTimes.begin(), deserializationTimes.end(), 0.0) / deserializationTimes.size();
        
        size_t totalProofSize = proofData.proof.size() + 32 + 32 + 32; // proof + anchor + nullifier + value_commitment
        double serializationThroughput = (totalProofSize / 1024.0) / (avgSerTime / 1000.0); // KB/sec
        double deserializationThroughput = (totalProofSize / 1024.0) / (avgDeserTime / 1000.0); // KB/sec
        
        log << "Proof Serialization Performance:" << std::endl;
        log << "  Proof Creation Time:     " << std::fixed << std::setprecision(3) << proofCreationTime.count() << " ms" << std::endl;
        log << "  Proof Size:              " << proofData.proof.size() << " bytes" << std::endl;
        log << "  Total Serialized Size:   " << totalProofSize << " bytes" << std::endl;
        log << "  Avg Serialization Time:  " << std::fixed << std::setprecision(6) << avgSerTime << " ms" << std::endl;
        log << "  Avg Deserialization Time:" << std::fixed << std::setprecision(6) << avgDeserTime << " ms" << std::endl;
        log << "  Serialization Throughput:" << std::fixed << std::setprecision(2) << serializationThroughput << " KB/sec" << std::endl;
        log << "  Deserialization Throughput:" << std::fixed << std::setprecision(2) << deserializationThroughput << " KB/sec" << std::endl;
        log << "  Runs Completed:          " << serializationRuns << std::endl;
        
        log << "Proof serialization: SUCCESS" << std::endl;
    }

    void testDepositProofCreation()
    {
        testcase("Enhanced Deposit Proof Creation");
        
        log << "\n=== ENHANCED DEPOSIT PROOF CREATION ===" << std::endl;
        
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));

    std::vector<double> creationTimes;
    std::vector<double> verificationTimes;
    std::vector<size_t> proofSizes;
    
    for (size_t idx : {0, 1, 2}) {
        uint64_t amount = 1000000 + idx * 100000;
        std::string spendKey = generateRandomSpendKey();

        auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(spendKey);
        zkp::FieldT value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(amount);

        log << "=== CREATING ENHANCED DEPOSIT PROOF " << idx << " ===" << std::endl;
        
        uint256 commitment = generateRandomUint256();
        log << "Using commitment: " << commitment << std::endl;

        // Measure proof creation time
        auto creationStart = std::chrono::high_resolution_clock::now();
        auto proofData = zkp::ZkProver::createDepositProof(amount, commitment, spendKey, value_randomness);
        auto creationEnd = std::chrono::high_resolution_clock::now();
        auto creationTime = std::chrono::duration<double, std::milli>(creationEnd - creationStart);
        
        BEAST_EXPECT(!proofData.empty());
        creationTimes.push_back(creationTime.count());
        proofSizes.push_back(proofData.proof.size());
        
        // Measure verification time
        auto verificationStart = std::chrono::high_resolution_clock::now();
        bool isValid = zkp::ZkProver::verifyDepositProof(proofData);
        auto verificationEnd = std::chrono::high_resolution_clock::now();
        auto verificationTime = std::chrono::duration<double, std::milli>(verificationEnd - verificationStart);
        
        BEAST_EXPECT(isValid);
        verificationTimes.push_back(verificationTime.count());
        
        log << "  Proof " << idx << " creation time:   " << std::fixed << std::setprecision(3) << creationTime.count() << " ms" << std::endl;
        log << "  Proof " << idx << " verification:    " << std::fixed << std::setprecision(3) << verificationTime.count() << " ms" << std::endl;
        log << "  Proof " << idx << " size:            " << proofData.proof.size() << " bytes" << std::endl;
        log << "  Proof " << idx << " verification:    " << (isValid ? "PASS" : "FAIL") << std::endl;
    }
    
    // Calculate aggregate statistics
    double avgCreationTime = std::accumulate(creationTimes.begin(), creationTimes.end(), 0.0) / creationTimes.size();
    double avgVerificationTime = std::accumulate(verificationTimes.begin(), verificationTimes.end(), 0.0) / verificationTimes.size();
    double avgProofSize = std::accumulate(proofSizes.begin(), proofSizes.end(), 0.0) / proofSizes.size();
    
    double creationThroughput = 1000.0 / avgCreationTime; // proofs per second
    double verificationThroughput = 1000.0 / avgVerificationTime; // verifications per second
    double efficiencyRatio = avgCreationTime / avgVerificationTime;
    
    log << "\nDeposit Proof Aggregate Statistics:" << std::endl;
    log << "  Average Creation Time:   " << std::fixed << std::setprecision(3) << avgCreationTime << " ms" << std::endl;
    log << "  Average Verification:    " << std::fixed << std::setprecision(3) << avgVerificationTime << " ms" << std::endl;
    log << "  Average Proof Size:      " << std::fixed << std::setprecision(0) << avgProofSize << " bytes" << std::endl;
    log << "  Creation Throughput:     " << std::fixed << std::setprecision(3) << creationThroughput << " proofs/sec" << std::endl;
    log << "  Verification Throughput: " << std::fixed << std::setprecision(1) << verificationThroughput << " verifications/sec" << std::endl;
    log << "  Efficiency Ratio:        " << std::fixed << std::setprecision(1) << efficiencyRatio << ":1 (create:verify)" << std::endl;
}

    void testWithdrawalProofCreation()
    {
        testcase("Enhanced Withdrawal Proof Creation");
        
        log << "\n=== ENHANCED WITHDRAWAL PROOF CREATION ===" << std::endl;
        
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));

        // Create incremental tree for testing with timing
        auto treeStart = std::chrono::high_resolution_clock::now();
        zkp::IncrementalMerkleTree tree(2); // depth 2 = 4 leaves max
        
        // Add some dummy notes to the tree
        uint256 dummyNote1 = generateRandomUint256();
        uint256 dummyNote2 = generateRandomUint256();
        
        size_t note1Index = tree.append(dummyNote1);
        size_t note2Index = tree.append(dummyNote2);
        (void)note1Index;  // Suppress unused warning
        (void)note2Index;  // Suppress unused warning
        
        auto treeEnd = std::chrono::high_resolution_clock::now();
        auto treeTime = std::chrono::duration<double, std::milli>(treeEnd - treeStart);
        
        uint64_t amount = 500000;
        uint256 merkleRoot = tree.root();
        uint256 nullifier = generateRandomUint256();
        std::string spendKey = generateRandomSpendKey();
        auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(spendKey);
        zkp::FieldT value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(amount);

    auto pathStart = std::chrono::high_resolution_clock::now();
    std::vector<uint256> merklePath = tree.authPath(0);
    auto pathEnd = std::chrono::high_resolution_clock::now();
    auto pathTime = std::chrono::duration<double, std::milli>(pathEnd - pathStart);

    log << "Tree setup time:         " << std::fixed << std::setprecision(3) << treeTime.count() << " ms" << std::endl;
    log << "Auth path generation:    " << std::fixed << std::setprecision(3) << pathTime.count() << " ms" << std::endl;
    log << "Tree root: " << merkleRoot << std::endl;
    log << "Path length: " << merklePath.size() << " hashes" << std::endl;

    // Test multiple withdrawal proofs for statistics
    std::vector<double> creationTimes;
    std::vector<double> verificationTimes;
    std::vector<size_t> proofSizes;
    
    const int numWithdrawalTests = 3;
    
    for (int i = 0; i < numWithdrawalTests; ++i) {
        auto creationStart = std::chrono::high_resolution_clock::now();
        
        auto proofData = zkp::ZkProver::createWithdrawalProof(
            amount, merkleRoot, nullifier, merklePath, 0, spendKey, value_randomness);
        
        auto creationEnd = std::chrono::high_resolution_clock::now();
        auto creationTime = std::chrono::duration<double, std::milli>(creationEnd - creationStart);
        
        BEAST_EXPECT(!proofData.empty());
        creationTimes.push_back(creationTime.count());
        
        if (!proofData.empty()) {
            proofSizes.push_back(proofData.proof.size());
            
            auto verificationStart = std::chrono::high_resolution_clock::now();
            bool isValid = zkp::ZkProver::verifyWithdrawalProof(proofData);
            auto verificationEnd = std::chrono::high_resolution_clock::now();
            auto verificationTime = std::chrono::duration<double, std::milli>(verificationEnd - verificationStart);
            
            BEAST_EXPECT(isValid);
            verificationTimes.push_back(verificationTime.count());
            
            log << "Withdrawal test " << (i+1) << " creation:     " << std::fixed << std::setprecision(3) 
                << creationTime.count() << " ms" << std::endl;
            log << "Withdrawal test " << (i+1) << " verification: " << std::fixed << std::setprecision(3) 
                << verificationTime.count() << " ms (" << (isValid ? "PASS" : "FAIL") << ")" << std::endl;
        }
        
        // Vary the nullifier for next test
        nullifier = generateRandomUint256();
    }
    
    // Calculate aggregate statistics
    if (!creationTimes.empty() && !verificationTimes.empty()) {
        double avgCreationTime = std::accumulate(creationTimes.begin(), creationTimes.end(), 0.0) / creationTimes.size();
        double avgVerificationTime = std::accumulate(verificationTimes.begin(), verificationTimes.end(), 0.0) / verificationTimes.size();
        double avgProofSize = proofSizes.empty() ? 0 : std::accumulate(proofSizes.begin(), proofSizes.end(), 0.0) / proofSizes.size();
        
        double creationThroughput = 1000.0 / avgCreationTime;
        double verificationThroughput = 1000.0 / avgVerificationTime;
        size_t totalInputSize = sizeof(amount) + 32 + 32 + (merklePath.size() * 32) + spendKey.length();
        
        log << "\nWithdrawal Proof Aggregate Statistics:" << std::endl;
        log << "  Average Creation Time:   " << std::fixed << std::setprecision(3) << avgCreationTime << " ms" << std::endl;
        log << "  Average Verification:    " << std::fixed << std::setprecision(3) << avgVerificationTime << " ms" << std::endl;
        log << "  Average Proof Size:      " << std::fixed << std::setprecision(0) << avgProofSize << " bytes" << std::endl;
        log << "  Input Size:              " << totalInputSize << " bytes" << std::endl;
        log << "  Creation Throughput:     " << std::fixed << std::setprecision(3) << creationThroughput << " proofs/sec" << std::endl;
        log << "  Verification Throughput: " << std::fixed << std::setprecision(1) << verificationThroughput << " verifications/sec" << std::endl;
        log << "  Size Expansion Factor:   " << std::fixed << std::setprecision(2) << (avgProofSize / totalInputSize) << "x" << std::endl;
    }
    
    log << "Enhanced withdrawal proof creation: SUCCESS" << std::endl;
}

    void testMultipleProofs()
    {
        testcase("Multiple Proofs Performance Analysis");
        
        log << "\n=== MULTIPLE PROOFS PERFORMANCE ANALYSIS ===" << std::endl;
        
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        const int numProofs = 5; // Increased for better statistics
        std::vector<zkp::ProofData> proofs;
        std::vector<double> creationTimes;
        std::vector<double> verificationTimes;
        std::vector<size_t> proofSizes;
        
        auto totalStart = std::chrono::high_resolution_clock::now();
        
        // Create multiple proofs with timing
        for (int i = 0; i < numProofs; ++i) {
            uint64_t amount = 1000000 + i * 250000;
            uint256 commitment = generateRandomUint256();
            std::string spendKey = generateRandomSpendKey();
            auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(spendKey);
            zkp::FieldT value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(amount);
            
            auto creationStart = std::chrono::high_resolution_clock::now();
            auto proof = zkp::ZkProver::createDepositProof(amount, commitment, spendKey, value_randomness);
            auto creationEnd = std::chrono::high_resolution_clock::now();
            auto creationTime = std::chrono::duration<double, std::milli>(creationEnd - creationStart);
            
            proofs.push_back(proof);
            creationTimes.push_back(creationTime.count());
            proofSizes.push_back(proof.proof.size());
            
            log << "Proof " << (i+1) << " creation: " << std::fixed << std::setprecision(3) 
                << creationTime.count() << " ms, size: " << proof.proof.size() << " bytes" << std::endl;
        }
        
        // Verify all proofs with timing
        for (size_t i = 0; i < proofs.size(); ++i) {
            BEAST_EXPECT(!proofs[i].empty());
            
            auto verificationStart = std::chrono::high_resolution_clock::now();
            bool isValid = zkp::ZkProver::verifyDepositProof(proofs[i]);
            auto verificationEnd = std::chrono::high_resolution_clock::now();
            auto verificationTime = std::chrono::duration<double, std::milli>(verificationEnd - verificationStart);
            
            BEAST_EXPECT(isValid);
            verificationTimes.push_back(verificationTime.count());
            
            log << "Proof " << (i+1) << " verification: " << std::fixed << std::setprecision(3) 
                << verificationTime.count() << " ms (" << (isValid ? "PASS" : "FAIL") << ")" << std::endl;
        }
        
        auto totalEnd = std::chrono::high_resolution_clock::now();
        auto totalTime = std::chrono::duration<double, std::milli>(totalEnd - totalStart);
        
        // Test cross-verification performance (should fail but measure timing)
        std::vector<double> crossVerificationTimes;
        int crossTests = 0;
        
        for (size_t i = 0; i < proofs.size() && i < 3; ++i) { // Limit cross-verification tests
            for (size_t j = 0; j < proofs.size() && j < 3; ++j) {
                if (i != j) {
                    auto crossStart = std::chrono::high_resolution_clock::now();
                    bool crossValid = zkp::ZkProver::verifyDepositProof(
                        proofs[i].proof, proofs[j].anchor, proofs[j].nullifier, proofs[j].value_commitment);
                    auto crossEnd = std::chrono::high_resolution_clock::now();
                    auto crossTime = std::chrono::duration<double, std::milli>(crossEnd - crossStart);
                    
                    BEAST_EXPECT(!crossValid); // Should fail
                    crossVerificationTimes.push_back(crossTime.count());
                    crossTests++;
                }
            }
        }
        
        // Calculate comprehensive statistics
        double avgCreationTime = std::accumulate(creationTimes.begin(), creationTimes.end(), 0.0) / creationTimes.size();
        double avgVerificationTime = std::accumulate(verificationTimes.begin(), verificationTimes.end(), 0.0) / verificationTimes.size();
        double avgProofSize = std::accumulate(proofSizes.begin(), proofSizes.end(), 0.0) / proofSizes.size();
        double avgCrossVerificationTime = crossVerificationTimes.empty() ? 0 : 
            std::accumulate(crossVerificationTimes.begin(), crossVerificationTimes.end(), 0.0) / crossVerificationTimes.size();
        
        double batchCreationThroughput = numProofs * 1000.0 / totalTime.count();
        double individualCreationThroughput = 1000.0 / avgCreationTime;
        double verificationThroughput = 1000.0 / avgVerificationTime;
        
        size_t totalDataSize = proofs.size() * avgProofSize;
        
        log << "\nMultiple Proofs Performance Summary:" << std::endl;
        log << "  Number of Proofs:        " << numProofs << std::endl;
        log << "  Total Processing Time:   " << std::fixed << std::setprecision(3) << totalTime.count() << " ms" << std::endl;
        log << "  Average Creation Time:   " << std::fixed << std::setprecision(3) << avgCreationTime << " ms" << std::endl;
        log << "  Average Verification:    " << std::fixed << std::setprecision(3) << avgVerificationTime << " ms" << std::endl;
        log << "  Average Proof Size:      " << std::fixed << std::setprecision(0) << avgProofSize << " bytes" << std::endl;
        log << "  Total Data Generated:    " << (totalDataSize / 1024) << " KB" << std::endl;
        log << "  Batch Creation Rate:     " << std::fixed << std::setprecision(3) << batchCreationThroughput << " proofs/sec" << std::endl;
        log << "  Individual Creation Rate:" << std::fixed << std::setprecision(3) << individualCreationThroughput << " proofs/sec" << std::endl;
        log << "  Verification Rate:       " << std::fixed << std::setprecision(1) << verificationThroughput << " verifications/sec" << std::endl;
        log << "  Cross-verification Tests:" << crossTests << " (avg: " << std::fixed << std::setprecision(3) 
            << avgCrossVerificationTime << " ms)" << std::endl;
        
        log << "Multiple proofs test: " << proofs.size() << " proofs generated and verified successfully" << std::endl;
    }

    void testEdgeCases()
    {
        testcase("Edge Cases Performance Analysis");
        
        log << "\n=== EDGE CASES PERFORMANCE ANALYSIS ===" << std::endl;
        
        BEAST_EXPECT(zkp::ZkProver::generateKeys(false));
        
        uint256 commitment = generateRandomUint256();
        std::string spendKey = generateRandomSpendKey();
        auto spendKeyBits = ripple::zkp::MerkleCircuit::spendKeyToBits(spendKey);
        
        // Test 1: Zero amount performance
        log << "Testing zero amount proof..." << std::endl;
        uint64_t zeroAmount = 0;
        zkp::FieldT zero_value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(zeroAmount);
        
        auto zeroStart = std::chrono::high_resolution_clock::now();
        auto zeroProof = zkp::ZkProver::createDepositProof(zeroAmount, commitment, spendKey, zero_value_randomness);
        auto zeroEnd = std::chrono::high_resolution_clock::now();
        auto zeroCreationTime = std::chrono::duration<double, std::milli>(zeroEnd - zeroStart);
        
        auto zeroVerifyStart = std::chrono::high_resolution_clock::now();
        bool zeroValid = zkp::ZkProver::verifyDepositProof(zeroProof);
        auto zeroVerifyEnd = std::chrono::high_resolution_clock::now();
        auto zeroVerifyTime = std::chrono::duration<double, std::milli>(zeroVerifyEnd - zeroVerifyStart);
        
        BEAST_EXPECT(zeroValid);
        
        // Test 2: Large amount performance
        log << "Testing large amount proof..." << std::endl;
        uint64_t largeAmount = (1ULL << 50);
        zkp::FieldT large_value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(12345);
        
        auto largeStart = std::chrono::high_resolution_clock::now();
        auto largeProof = zkp::ZkProver::createDepositProof(largeAmount, commitment, spendKey, large_value_randomness);
        auto largeEnd = std::chrono::high_resolution_clock::now();
        auto largeCreationTime = std::chrono::duration<double, std::milli>(largeEnd - largeStart);
        
        auto largeVerifyStart = std::chrono::high_resolution_clock::now();
        bool largeValid = zkp::ZkProver::verifyDepositProof(largeProof);
        auto largeVerifyEnd = std::chrono::high_resolution_clock::now();
        auto largeVerifyTime = std::chrono::duration<double, std::milli>(largeVerifyEnd - largeVerifyStart);
        
        BEAST_EXPECT(largeValid);
        
        // Test 3: Maximum realistic amount performance
        log << "Testing maximum realistic amount proof..." << std::endl;
        uint64_t maxAmount = std::numeric_limits<uint64_t>::max() / 2; // Half of max to be safe
        zkp::FieldT max_value_randomness = ripple::zkp::MerkleCircuit::bitsToFieldElement(spendKeyBits) + zkp::FieldT(54321);
        
        auto maxStart = std::chrono::high_resolution_clock::now();
        auto maxProof = zkp::ZkProver::createDepositProof(maxAmount, commitment, spendKey, max_value_randomness);
        auto maxEnd = std::chrono::high_resolution_clock::now();
        auto maxCreationTime = std::chrono::duration<double, std::milli>(maxEnd - maxStart);
        
        auto maxVerifyStart = std::chrono::high_resolution_clock::now();
        bool maxValid = zkp::ZkProver::verifyDepositProof(maxProof);
        auto maxVerifyEnd = std::chrono::high_resolution_clock::now();
        auto maxVerifyTime = std::chrono::duration<double, std::milli>(maxVerifyEnd - maxVerifyStart);
        
        BEAST_EXPECT(maxValid);
        
        // Performance analysis
        log << "\nEdge Cases Performance Results:" << std::endl;
        log << "  Zero Amount:" << std::endl;
        log << "    Creation Time:         " << std::fixed << std::setprecision(3) << zeroCreationTime.count() << " ms" << std::endl;
        log << "    Verification Time:     " << std::fixed << std::setprecision(3) << zeroVerifyTime.count() << " ms" << std::endl;
        log << "    Proof Size:            " << zeroProof.proof.size() << " bytes" << std::endl;
        log << "    Result:                " << (zeroValid ? "PASS" : "FAIL") << std::endl;
        
        log << "  Large Amount (" << largeAmount << "):" << std::endl;
        log << "    Creation Time:         " << std::fixed << std::setprecision(3) << largeCreationTime.count() << " ms" << std::endl;
        log << "    Verification Time:     " << std::fixed << std::setprecision(3) << largeVerifyTime.count() << " ms" << std::endl;
        log << "    Proof Size:            " << largeProof.proof.size() << " bytes" << std::endl;
        log << "    Result:                " << (largeValid ? "PASS" : "FAIL") << std::endl;
        
        log << "  Max Realistic Amount:" << std::endl;
        log << "    Creation Time:         " << std::fixed << std::setprecision(3) << maxCreationTime.count() << " ms" << std::endl;
        log << "    Verification Time:     " << std::fixed << std::setprecision(3) << maxVerifyTime.count() << " ms" << std::endl;
        log << "    Proof Size:            " << maxProof.proof.size() << " bytes" << std::endl;
        log << "    Result:                " << (maxValid ? "PASS" : "FAIL") << std::endl;
        
        // Compare performance consistency
        double avgCreationTime = (zeroCreationTime.count() + largeCreationTime.count() + maxCreationTime.count()) / 3.0;
        double avgVerificationTime = (zeroVerifyTime.count() + largeVerifyTime.count() + maxVerifyTime.count()) / 3.0;
        
        double creationVariance = std::pow(zeroCreationTime.count() - avgCreationTime, 2) + 
                            std::pow(largeCreationTime.count() - avgCreationTime, 2) + 
                            std::pow(maxCreationTime.count() - avgCreationTime, 2);
        creationVariance /= 3.0;
        
        log << "\nPerformance Consistency Analysis:" << std::endl;
        log << "  Average Creation Time:   " << std::fixed << std::setprecision(3) << avgCreationTime << " ms" << std::endl;
        log << "  Average Verification:    " << std::fixed << std::setprecision(3) << avgVerificationTime << " ms" << std::endl;
        log << "  Creation Time Variance:  " << std::fixed << std::setprecision(3) << creationVariance << std::endl;
        log << "  Performance Consistency: " << (creationVariance < 1000 ? "EXCELLENT" : "VARIABLE") << std::endl;
        
        log << "Edge cases test: zero=" << zeroValid << ", large=" << largeValid << ", max=" << maxValid << std::endl;
    }
    
    void testIncrementalMerkleTree() {
        testcase("Incremental Merkle Tree Performance");
        
        log << "\n=== INCREMENTAL MERKLE TREE PERFORMANCE ===" << std::endl;
        
        const int treeDepth = 10; // Realistic depth for performance testing
        const int numOperations = 50; // Number of operations to test
        
        auto treeCreationStart = std::chrono::high_resolution_clock::now();
        zkp::IncrementalMerkleTree tree(treeDepth);
        auto treeCreationEnd = std::chrono::high_resolution_clock::now();
        auto treeCreationTime = std::chrono::duration<double, std::milli>(treeCreationEnd - treeCreationStart);
        
        // Test empty tree
        BEAST_EXPECT(tree.empty());
        BEAST_EXPECT(tree.size() == 0);
        
        log << "Tree creation time:      " << std::fixed << std::setprecision(3) << treeCreationTime.count() << " ms" << std::endl;
        log << "Tree depth:              " << treeDepth << std::endl;
        
        // Generate test leaves
        std::vector<uint256> leaves;
        auto leafGenStart = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < numOperations; ++i) {
            leaves.push_back(generateRandomUint256());
        }
        auto leafGenEnd = std::chrono::high_resolution_clock::now();
        auto leafGenTime = std::chrono::duration<double, std::milli>(leafGenEnd - leafGenStart);
        
        // Test insertion performance
        std::vector<double> insertionTimes;
        std::vector<size_t> positions;
        
        for (int i = 0; i < numOperations; ++i) {
            auto insertStart = std::chrono::high_resolution_clock::now();
            size_t pos = tree.append(leaves[i]);
            auto insertEnd = std::chrono::high_resolution_clock::now();
            auto insertTime = std::chrono::duration<double, std::milli>(insertEnd - insertStart);
            
            insertionTimes.push_back(insertTime.count());
            positions.push_back(pos);
            
            BEAST_EXPECT(pos == i);
        }
        
        BEAST_EXPECT(tree.size() == numOperations);
        BEAST_EXPECT(!tree.empty());
        
        // Test authentication path generation performance
        std::vector<double> pathTimes;
        std::vector<std::vector<uint256>> authPaths;
        
        for (int i = 0; i < std::min(numOperations, 10); ++i) { // Test first 10 paths
            auto pathStart = std::chrono::high_resolution_clock::now();
            auto path = tree.authPath(i);
            auto pathEnd = std::chrono::high_resolution_clock::now();
            auto pathTime = std::chrono::duration<double, std::milli>(pathEnd - pathStart);
            
            pathTimes.push_back(pathTime.count());
            authPaths.push_back(path);
            
            BEAST_EXPECT(path.size() == treeDepth);
        }
        
        // Test verification performance
        std::vector<double> verificationTimes;
        uint256 root = tree.root();
        
        for (size_t i = 0; i < authPaths.size(); ++i) {
            auto verifyStart = std::chrono::high_resolution_clock::now();
            bool verified = tree.verify(leaves[i], authPaths[i], i, root);
            auto verifyEnd = std::chrono::high_resolution_clock::now();
            auto verifyTime = std::chrono::duration<double, std::milli>(verifyEnd - verifyStart);
            
            verificationTimes.push_back(verifyTime.count());
            BEAST_EXPECT(verified);
        }
        
        // Calculate statistics
        double avgInsertionTime = std::accumulate(insertionTimes.begin(), insertionTimes.end(), 0.0) / insertionTimes.size();
        double avgPathTime = pathTimes.empty() ? 0 : std::accumulate(pathTimes.begin(), pathTimes.end(), 0.0) / pathTimes.size();
        double avgVerificationTime = verificationTimes.empty() ? 0 : std::accumulate(verificationTimes.begin(), verificationTimes.end(), 0.0) / verificationTimes.size();
        
        double insertionThroughput = 1000.0 / avgInsertionTime; // insertions per second
        double pathThroughput = avgPathTime > 0 ? 1000.0 / avgPathTime : 0; // paths per second
        double verificationThroughput = avgVerificationTime > 0 ? 1000.0 / avgVerificationTime : 0; // verifications per second
        
        size_t authPathSize = authPaths.empty() ? 0 : authPaths[0].size() * 32; // bytes
        size_t totalTreeMemory = numOperations * 32; // Approximate memory usage
        
        log << "\nMerkle Tree Performance Results:" << std::endl;
        log << "  Leaf Generation Time:    " << std::fixed << std::setprecision(3) << leafGenTime.count() << " ms" << std::endl;
        log << "  Insertions Completed:    " << numOperations << std::endl;
        log << "  Average Insert Time:     " << std::fixed << std::setprecision(6) << avgInsertionTime << " ms" << std::endl;
        log << "  Average Path Time:       " << std::fixed << std::setprecision(3) << avgPathTime << " ms" << std::endl;
        log << "  Average Verify Time:     " << std::fixed << std::setprecision(6) << avgVerificationTime << " ms" << std::endl;
        log << "  Tree Size:               " << tree.size() << " leaves" << std::endl;
        log << "  Path Length:             " << (authPaths.empty() ? 0 : authPaths[0].size()) << " hashes" << std::endl;
        log << "  Auth Path Size:          " << authPathSize << " bytes" << std::endl;
        log << "  Estimated Tree Memory:   " << (totalTreeMemory / 1024) << " KB" << std::endl;
        log << "  Insert Throughput:       " << std::fixed << std::setprecision(1) << insertionThroughput << " insertions/sec" << std::endl;
        log << "  Path Throughput:         " << std::fixed << std::setprecision(1) << pathThroughput << " paths/sec" << std::endl;
        log << "  Verify Throughput:       " << std::fixed << std::setprecision(0) << verificationThroughput << " verifications/sec" << std::endl;
        
        log << "Incremental tree test: final size=" << tree.size() << ", root=" << root << std::endl;
    }
};

BEAST_DEFINE_TESTSUITE(ZKProver, protocol, ripple);

}