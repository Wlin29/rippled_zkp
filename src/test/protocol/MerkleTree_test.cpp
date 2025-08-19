#include <xrpl/basics/Slice.h>
#include <xrpl/beast/unit_test.h>
#include <xrpl/protocol/UintTypes.h>
#include <xrpl/protocol/digest.h>
#include <libxrpl/zkp/IncrementalMerkleTree.h>
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
        testPositionalPerformanceComparison();
    }

    void
    testPositionalPerformanceComparison()
    {
        testcase("Merkle Tree Positional Performance Comparison: Regular vs Incremental");

        // 2^32, 2^40
        const std::vector<long int> treeSizes = {4294967296, 1099511627776};
        const int numSamples = 5;
        
        std::cout << "Comparing Regular vs Incremental Merkle Tree Performance\n";
        std::cout << "Testing performance at first, middle, and last leaf positions\n\n";

        struct PositionResults {
            long long regularInsertTime = 0;
            long long regularProofTime = 0;
            long long regularVerifyTime = 0;
            long long incrementalInsertTime = 0;
            long long incrementalProofTime = 0;
            long long incrementalVerifyTime = 0;
            int successfulSamples = 0;
        };

        for (long int size : treeSizes) {
            std::cout << "=== Testing with " << size << " nodes ===\n";
            
            PositionResults firstResults, middleResults, lastResults;
            
            // Define test positions
            int firstPos = 0;
            int middlePos = size / 2;
            int lastPos = size - 1;

            for (int sample = 0; sample < numSamples; ++sample) {
                try {
                    // Generate test data
                    std::vector<uint256> testHashes;
                    testHashes.reserve(size);
                    for (int i = 0; i < size; ++i) {
                        std::string data = "node_" + std::to_string(i) + "_size_" + std::to_string(size);
                        testHashes.push_back(sha512Half(Slice{data.data(), data.size()}));
                    }

                    auto testPosition = [&](int position, PositionResults& results, const std::string& posName) {
                        // ================================================
                        // REGULAR MERKLE TREE TESTING
                        // ================================================
                        
                        // Build complete tree from scratch (regular approach)
                        auto regInsertStart = std::chrono::high_resolution_clock::now();
                        std::vector<std::vector<uint256>> tree;
                        tree.push_back(testHashes); // Leaf level
                        
                        // Build tree levels bottom-up
                        for (size_t level = 0; tree[level].size() > 1; ++level) {
                            std::vector<uint256> nextLevel;
                            const auto& currentLevel = tree[level];
                            
                            for (size_t i = 0; i < currentLevel.size(); i += 2) {
                                if (i + 1 < currentLevel.size()) {
                                    // Hash two nodes together
                                    auto leftData = currentLevel[i].data();
                                    auto rightData = currentLevel[i + 1].data();
                                    std::vector<uint8_t> combinedData(leftData, leftData + 32);
                                    combinedData.insert(combinedData.end(), rightData, rightData + 32);
                                    nextLevel.push_back(sha512Half(Slice{combinedData.data(), combinedData.size()}));
                                } else {
                                    // Odd number, promote single node
                                    nextLevel.push_back(currentLevel[i]);
                                }
                            }
                            tree.push_back(nextLevel);
                        }
                        auto regInsertEnd = std::chrono::high_resolution_clock::now();
                        long long regInsertTime = std::chrono::duration_cast<std::chrono::microseconds>(regInsertEnd - regInsertStart).count();
                        
                        // Generate authentication path for position
                        auto regProofStart = std::chrono::high_resolution_clock::now();
                        std::vector<uint256> authPath;
                        int currentPos = position;
                        
                        for (size_t level = 0; level < tree.size() - 1; ++level) {
                            if (currentPos % 2 == 0) {
                                // Current node is left child, sibling is right
                                if (currentPos + 1 < tree[level].size()) {
                                    authPath.push_back(tree[level][currentPos + 1]);
                                } else {
                                    // No right sibling, use zero hash
                                    authPath.push_back(uint256{});
                                }
                            } else {
                                // Current node is right child, sibling is left
                                authPath.push_back(tree[level][currentPos - 1]);
                            }
                            currentPos /= 2;
                        }
                        uint256 regularRoot = tree.back()[0];
                        auto regProofEnd = std::chrono::high_resolution_clock::now();
                        long long regProofTime = std::chrono::duration_cast<std::chrono::microseconds>(regProofEnd - regProofStart).count();
                        
                        // Verify authentication path
                        auto regVerifyStart = std::chrono::high_resolution_clock::now();
                        uint256 currentHash = testHashes[position];
                        int pos = position;
                        
                        for (const auto& sibling : authPath) {
                            if (sibling == uint256{}) {
                                pos /= 2;
                                continue;
                            }
                            
                            if (pos % 2 == 0) {
                                // Current is left, sibling is right
                                auto leftData = currentHash.data();
                                auto rightData = sibling.data();
                                std::vector<uint8_t> combinedData(leftData, leftData + 32);
                                combinedData.insert(combinedData.end(), rightData, rightData + 32);
                                currentHash = sha512Half(Slice{combinedData.data(), combinedData.size()});
                            } else {
                                // Current is right, sibling is left
                                auto leftData = sibling.data();
                                auto rightData = currentHash.data();
                                std::vector<uint8_t> combinedData(leftData, leftData + 32);
                                combinedData.insert(combinedData.end(), rightData, rightData + 32);
                                currentHash = sha512Half(Slice{combinedData.data(), combinedData.size()});
                            }
                            pos /= 2;
                        }
                        
                        bool regularProofValid = (currentHash == regularRoot);
                        auto regVerifyEnd = std::chrono::high_resolution_clock::now();
                        long long regVerifyTime = std::chrono::duration_cast<std::chrono::microseconds>(regVerifyEnd - regVerifyStart).count();
                        
                        BEAST_EXPECT(regularProofValid);
                        
                        // ================================================
                        // INCREMENTAL MERKLE TREE TESTING
                        // ================================================
                        
                        auto incInsertStart = std::chrono::high_resolution_clock::now();
                        ripple::zkp::IncrementalMerkleTree incrementalTree(32);
                        
                        // Insert all nodes
                        for (const auto& hash : testHashes) {
                            incrementalTree.append(hash);
                        }
                        auto incInsertEnd = std::chrono::high_resolution_clock::now();
                        long long incInsertTime = std::chrono::duration_cast<std::chrono::microseconds>(incInsertEnd - incInsertStart).count();
                        
                        // Generate authentication path
                        auto incProofStart = std::chrono::high_resolution_clock::now();
                        auto incAuthPath = incrementalTree.authPath(position);
                        auto incRoot = incrementalTree.root();
                        auto incProofEnd = std::chrono::high_resolution_clock::now();
                        long long incProofTime = std::chrono::duration_cast<std::chrono::microseconds>(incProofEnd - incProofStart).count();
                        
                        // Verify authentication path
                        auto incVerifyStart = std::chrono::high_resolution_clock::now();
                        bool incProofValid = incrementalTree.verify(testHashes[position], incAuthPath, position, incRoot);
                        auto incVerifyEnd = std::chrono::high_resolution_clock::now();
                        long long incVerifyTime = std::chrono::duration_cast<std::chrono::microseconds>(incVerifyEnd - incVerifyStart).count();
                        
                        BEAST_EXPECT(incProofValid);
                        
                        // Update results
                        results.regularInsertTime += regInsertTime;
                        results.regularProofTime += regProofTime;
                        results.regularVerifyTime += regVerifyTime;
                        results.incrementalInsertTime += incInsertTime;
                        results.incrementalProofTime += incProofTime;
                        results.incrementalVerifyTime += incVerifyTime;
                        
                        std::cout << "  " << posName << " (" << position << "): "
                                 << "Reg=" << (regInsertTime + regProofTime + regVerifyTime) << "μs, "
                                 << "Inc=" << (incInsertTime + incProofTime + incVerifyTime) << "μs, "
                                 << "Speedup=" << std::fixed << std::setprecision(1) 
                                 << ((double)(regInsertTime + regProofTime + regVerifyTime) / (incInsertTime + incProofTime + incVerifyTime)) << "x\n";
                    };
                    
                    testPosition(firstPos, firstResults, "First");
                    testPosition(middlePos, middleResults, "Middle");
                    testPosition(lastPos, lastResults, "Last");
                    
                    // Update success counts
                    firstResults.successfulSamples++;
                    middleResults.successfulSamples++;
                    lastResults.successfulSamples++;
                    
                } catch (std::exception& e) {
                    std::cout << "Sample " << sample << " failed: " << e.what() << "\n";
                }
            }

            // Display results for this tree size
            auto displayResults = [&](const PositionResults& results, const std::string& position, int pos) {
                if (results.successfulSamples > 0) {
                    long long avgRegInsert = results.regularInsertTime / results.successfulSamples;
                    long long avgRegProof = results.regularProofTime / results.successfulSamples;
                    long long avgRegVerify = results.regularVerifyTime / results.successfulSamples;
                    long long avgRegTotal = avgRegInsert + avgRegProof + avgRegVerify;
                    
                    long long avgIncInsert = results.incrementalInsertTime / results.successfulSamples;
                    long long avgIncProof = results.incrementalProofTime / results.successfulSamples;
                    long long avgIncVerify = results.incrementalVerifyTime / results.successfulSamples;
                    long long avgIncTotal = avgIncInsert + avgIncProof + avgIncVerify;
                    
                    double totalSpeedup = (double)avgRegTotal / avgIncTotal;
                    double insertSpeedup = avgRegInsert > 0 ? (double)avgRegInsert / avgIncInsert : 0.0;
                    double proofSpeedup = avgRegProof > 0 ? (double)avgRegProof / avgIncProof : 0.0;
                    double verifySpeedup = avgRegVerify > 0 ? (double)avgRegVerify / avgIncVerify : 0.0;
                    
                    std::cout << "\n--- " << position << " Position (index " << pos << ") Results ---\n";
                    std::cout << "Regular Tree:     Insert=" << avgRegInsert << "μs, Proof=" << avgRegProof 
                             << "μs, Verify=" << avgRegVerify << "μs, Total=" << avgRegTotal << "μs\n";
                    std::cout << "Incremental Tree: Insert=" << avgIncInsert << "μs, Proof=" << avgIncProof 
                             << "μs, Verify=" << avgIncVerify << "μs, Total=" << avgIncTotal << "μs\n";
                    std::cout << "Speedup:          Insert=" << std::fixed << std::setprecision(1) << insertSpeedup 
                             << "x, Proof=" << proofSpeedup << "x, Verify=" << verifySpeedup 
                             << "x, Total=" << totalSpeedup << "x\n";
                }
            };
            
            std::cout << "\n" << std::string(60, '=') << "\n";
            std::cout << "RESULTS FOR " << size << " NODES\n";
            std::cout << std::string(60, '=') << "\n";
            
            displayResults(firstResults, "FIRST", firstPos);
            displayResults(middleResults, "MIDDLE", middlePos);
            displayResults(lastResults, "LAST", lastPos);
            
            std::cout << "\n";
        }
    }
};

BEAST_DEFINE_TESTSUITE(MerkleTree, protocol, ripple);

}  // namespace ripple
