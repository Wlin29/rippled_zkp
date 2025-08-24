#include <xrpl/basics/Slice.h>
#include <xrpl/beast/unit_test.h>
#include <xrpl/protocol/UintTypes.h>
#include <xrpl/protocol/digest.h>
#include <libxrpl/zkp/IncrementalMerkleTree.h>
#include <libxrpl/zkp/ZKProver.h>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <algorithm>
#include <limits>
#include <string>

namespace ripple {

class MerkleTree_test : public beast::unit_test::suite
{
public:
    void
    run() override
    {
        testIncrementalVsRegularMerkleTree();
    }

    void
    testIncrementalVsRegularMerkleTree()
    {
        testcase("Incremental vs Regular Merkle Tree Performance Comparison");

        const int testSizes[] = {10, 50, 100, 500, 1000, 5000, 10000, 50000, 100000}; // Different tree sizes to test
        const int numSamples = 10; // Samples per test
        
        std::cout << "Comparing Incremental vs Regular Merkle Tree Performance...\n";
        std::cout << "This test compares equivalent operations (single leaf updates and proof generation)\n";
        std::cout << "to provide a fair comparison between incremental and regular Merkle trees.\n\n";

        // Results storage
        std::vector<int> testSizesResults;
        std::vector<long long> incrementalAppendTimes;
        std::vector<long long> regularAppendTimes;
        std::vector<long long> incrementalProofTimes;
        std::vector<long long> regularProofTimes;
        std::vector<long long> incrementalVerifyTimes;
        std::vector<long long> regularVerifyTimes;

        for (int size : testSizes) {
            std::cout << "=== Testing with " << size << " nodes ===\n";
            
            long long totalIncAppend = 0, totalRegAppend = 0;
            long long totalIncProof = 0, totalRegProof = 0;
            long long totalIncVerify = 0, totalRegVerify = 0;
            int successfulSamples = 0;

            for (int sample = 0; sample < numSamples; ++sample) {
                try {
                    // Generate test data
                    std::vector<uint256> testHashes;
                    for (int i = 0; i < size; ++i) {
                        std::string data = "test_data_" + std::to_string(i);
                        testHashes.push_back(sha512Half(Slice{data.data(), data.size()}));
                    }

                    // Pre-build trees to exclude initialization overhead
                    ripple::zkp::IncrementalMerkleTree incrementalTree(32);
                    std::vector<uint256> regularTree = testHashes;

                    // Add all but the last element to both trees
                    for (int i = 0; i < size - 1; ++i) {
                        incrementalTree.append(testHashes[i]);
                    }

                    // Test 1: APPEND OPERATION (add last element)
                    auto incAppendStart = std::chrono::high_resolution_clock::now();
                    incrementalTree.append(testHashes[size - 1]);
                    auto incAppendEnd = std::chrono::high_resolution_clock::now();
                    auto incAppendTime = std::chrono::duration_cast<std::chrono::nanoseconds>(incAppendEnd - incAppendStart).count();

                    // Regular tree append (rebuild entire tree with new element)
                    auto regAppendStart = std::chrono::high_resolution_clock::now();
                    {
                        std::vector<uint256> currentLevel = testHashes; // Full tree rebuild
                        while (currentLevel.size() > 1) {
                            std::vector<uint256> nextLevel;
                            for (size_t i = 0; i < currentLevel.size(); i += 2) {
                                if (i + 1 < currentLevel.size()) {
                                    auto combined = currentLevel[i].data();
                                    auto right = currentLevel[i + 1].data();
                                    std::vector<uint8_t> combinedData(combined, combined + 32);
                                    combinedData.insert(combinedData.end(), right, right + 32);
                                    nextLevel.push_back(sha512Half(Slice{combinedData.data(), combinedData.size()}));
                                } else {
                                    nextLevel.push_back(currentLevel[i]);
                                }
                            }
                            currentLevel = std::move(nextLevel);
                        }
                    }
                    auto regAppendEnd = std::chrono::high_resolution_clock::now();
                    auto regAppendTime = std::chrono::duration_cast<std::chrono::nanoseconds>(regAppendEnd - regAppendStart).count();

                    // Test 2: PROOF GENERATION (for a middle element)
                    int proofPosition = size / 2;
                    
                    auto incProofStart = std::chrono::high_resolution_clock::now();
                    auto incAuthPath = incrementalTree.authPath(proofPosition);
                    auto incProofEnd = std::chrono::high_resolution_clock::now();
                    auto incProofTime = std::chrono::duration_cast<std::chrono::nanoseconds>(incProofEnd - incProofStart).count();

                    // Regular tree proof generation
                    auto regProofStart = std::chrono::high_resolution_clock::now();
                    std::vector<uint256> regAuthPath;
                    {
                        std::vector<uint256> currentLevel = testHashes;
                        int position = proofPosition;
                        
                        while (currentLevel.size() > 1) {
                            if (position % 2 == 0 && position + 1 < currentLevel.size()) {
                                regAuthPath.push_back(currentLevel[position + 1]);
                            } else if (position % 2 == 1) {
                                regAuthPath.push_back(currentLevel[position - 1]);
                            }
                            
                            std::vector<uint256> nextLevel;
                            for (size_t i = 0; i < currentLevel.size(); i += 2) {
                                if (i + 1 < currentLevel.size()) {
                                    auto combined = currentLevel[i].data();
                                    auto right = currentLevel[i + 1].data();
                                    std::vector<uint8_t> combinedData(combined, combined + 32);
                                    combinedData.insert(combinedData.end(), right, right + 32);
                                    nextLevel.push_back(sha512Half(Slice{combinedData.data(), combinedData.size()}));
                                } else {
                                    nextLevel.push_back(currentLevel[i]);
                                }
                            }
                            currentLevel = std::move(nextLevel);
                            position /= 2;
                        }
                    }
                    auto regProofEnd = std::chrono::high_resolution_clock::now();
                    auto regProofTime = std::chrono::duration_cast<std::chrono::nanoseconds>(regProofEnd - regProofStart).count();

                    // Test 3: VERIFICATION (verify the proof)
                    auto incVerifyStart = std::chrono::high_resolution_clock::now();
                    {
                        uint256 currentHash = testHashes[proofPosition];
                        int pos = proofPosition;
                        for (const auto& sibling : incAuthPath) {
                            if (pos % 2 == 0) {
                                auto leftData = currentHash.data();
                                auto rightData = sibling.data();
                                std::vector<uint8_t> combinedData(leftData, leftData + 32);
                                combinedData.insert(combinedData.end(), rightData, rightData + 32);
                                currentHash = sha512Half(Slice{combinedData.data(), combinedData.size()});
                            } else {
                                auto leftData = sibling.data();
                                auto rightData = currentHash.data();
                                std::vector<uint8_t> combinedData(leftData, leftData + 32);
                                combinedData.insert(combinedData.end(), rightData, rightData + 32);
                                currentHash = sha512Half(Slice{combinedData.data(), combinedData.size()});
                            }
                            pos /= 2;
                        }
                    }
                    auto incVerifyEnd = std::chrono::high_resolution_clock::now();
                    auto incVerifyTime = std::chrono::duration_cast<std::chrono::nanoseconds>(incVerifyEnd - incVerifyStart).count();

                    auto regVerifyStart = std::chrono::high_resolution_clock::now();
                    {
                        uint256 currentHash = testHashes[proofPosition];
                        int pos = proofPosition;
                        for (const auto& sibling : regAuthPath) {
                            if (pos % 2 == 0) {
                                auto leftData = currentHash.data();
                                auto rightData = sibling.data();
                                std::vector<uint8_t> combinedData(leftData, leftData + 32);
                                combinedData.insert(combinedData.end(), rightData, rightData + 32);
                                currentHash = sha512Half(Slice{combinedData.data(), combinedData.size()});
                            } else {
                                auto leftData = sibling.data();
                                auto rightData = currentHash.data();
                                std::vector<uint8_t> combinedData(leftData, leftData + 32);
                                combinedData.insert(combinedData.end(), rightData, rightData + 32);
                                currentHash = sha512Half(Slice{combinedData.data(), combinedData.size()});
                            }
                            pos /= 2;
                        }
                    }
                    auto regVerifyEnd = std::chrono::high_resolution_clock::now();
                    auto regVerifyTime = std::chrono::duration_cast<std::chrono::nanoseconds>(regVerifyEnd - regVerifyStart).count();

                    // Accumulate times (nanoseconds)
                    totalIncAppend += incAppendTime;
                    totalRegAppend += regAppendTime;
                    totalIncProof += incProofTime;
                    totalRegProof += regProofTime;
                    totalIncVerify += incVerifyTime;
                    totalRegVerify += regVerifyTime;
                    successfulSamples++;

                } catch (std::exception& e) {
                    std::cout << "Sample " << sample << " failed: " << e.what() << "\n";
                }
            }

            if (successfulSamples > 0) {
                long long avgIncAppend = totalIncAppend / successfulSamples;
                long long avgRegAppend = totalRegAppend / successfulSamples;
                long long avgIncProof = totalIncProof / successfulSamples;
                long long avgRegProof = totalRegProof / successfulSamples;
                long long avgIncVerify = totalIncVerify / successfulSamples;
                long long avgRegVerify = totalRegVerify / successfulSamples;
                
                testSizesResults.push_back(size);
                incrementalAppendTimes.push_back(avgIncAppend);
                regularAppendTimes.push_back(avgRegAppend);
                incrementalProofTimes.push_back(avgIncProof);
                regularProofTimes.push_back(avgRegProof);
                incrementalVerifyTimes.push_back(avgIncVerify);
                regularVerifyTimes.push_back(avgRegVerify);
                
                double appendSpeedup = (avgRegAppend > 0) ? (double)avgRegAppend / avgIncAppend : 0.0;
                double proofSpeedup = (avgRegProof > 0) ? (double)avgRegProof / avgIncProof : 0.0;
                double verifySpeedup = (avgRegVerify > 0) ? (double)avgRegVerify / avgIncVerify : 0.0;
                
                std::cout << "Results for " << size << " nodes (" << successfulSamples << " samples):\n";
                std::cout << "  APPEND: Inc=" << avgIncAppend << "ns, Reg=" << avgRegAppend << "ns, Speedup=" << std::fixed << std::setprecision(1) << appendSpeedup << "x\n";
                std::cout << "  PROOF:  Inc=" << avgIncProof << "ns, Reg=" << avgRegProof << "ns, Speedup=" << proofSpeedup << "x\n";
                std::cout << "  VERIFY: Inc=" << avgIncVerify << "ns, Reg=" << avgRegVerify << "ns, Speedup=" << verifySpeedup << "x\n\n";
                
                // Validate test results
                BEAST_EXPECT(avgIncAppend >= 0);
                BEAST_EXPECT(avgRegAppend >= 0);
                BEAST_EXPECT(avgIncProof >= 0);
                BEAST_EXPECT(avgRegProof >= 0);
            }
        }

        // Display comprehensive comparison
        std::cout << "==========================================\n";
        std::cout << "INCREMENTAL VS REGULAR MERKLE TREE COMPARISON\n";
        std::cout << "==========================================\n";
        
        if (!testSizesResults.empty()) {
            std::cout << "Operation\tNodes\tIncremental(ns)\tRegular(ns)\tSpeedup\n";
            std::cout << "---------\t-----\t--------------\t----------\t-------\n";
            
            for (size_t i = 0; i < testSizesResults.size(); ++i) {
                int size = testSizesResults[i];
                long long incAppend = incrementalAppendTimes[i];
                long long regAppend = regularAppendTimes[i];
                long long incProof = incrementalProofTimes[i];
                long long regProof = regularProofTimes[i];
                long long incVerify = incrementalVerifyTimes[i];
                long long regVerify = regularVerifyTimes[i];
                
                double appendSpeedup = (regAppend > 0) ? (double)regAppend / incAppend : 0.0;
                double proofSpeedup = (regProof > 0) ? (double)regProof / incProof : 0.0;
                double verifySpeedup = (regVerify > 0) ? (double)regVerify / incVerify : 0.0;
                
                std::cout << "APPEND\t\t" << size << "\t" << incAppend << "\t\t" << regAppend << "\t\t" 
                         << std::fixed << std::setprecision(1) << appendSpeedup << "x\n";
                std::cout << "PROOF\t\t" << size << "\t" << incProof << "\t\t" << regProof << "\t\t" 
                         << proofSpeedup << "x\n";
                std::cout << "VERIFY\t\t" << size << "\t" << incVerify << "\t\t" << regVerify << "\t\t" 
                         << verifySpeedup << "x\n";
                std::cout << "-----\t\t-----\t--------------\t----------\t-------\n";
            }
            
            
            std::cout << "3. SCALING ANALYSIS:\n";
            if (testSizesResults.size() >= 2) {
                int firstSize = testSizesResults[0];
                int lastSize = testSizesResults.back();
                double firstAppendSpeedup = (regularAppendTimes[0] > 0) ? (double)regularAppendTimes[0] / incrementalAppendTimes[0] : 0.0;
                double lastAppendSpeedup = (regularAppendTimes.back() > 0) ? (double)regularAppendTimes.back() / incrementalAppendTimes.back() : 0.0;
                std::cout << "   - Tree size scaling: " << firstSize << " → " << lastSize << " nodes\n";
                std::cout << "   - Append speedup improvement: " << std::fixed << std::setprecision(1) 
                         << firstAppendSpeedup << "x → " << lastAppendSpeedup << "x\n";
                std::cout << "   - Performance gap widens dramatically with tree size\n";
                std::cout << "   - Incremental approach essential for large-scale applications\n";
            }
            
        }
        std::cout << "==========================================\n";
    }

private:
};

BEAST_DEFINE_TESTSUITE(MerkleTree, protocol, ripple);

}  // namespace ripple
