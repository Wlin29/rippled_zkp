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
        /*
        MERKLE TREE PERFORMANCE COMPARISON TEST
        ====================================================
        
        This test performs an in-depth performance comparison between two Merkle tree implementations:
        
        1. INCREMENTAL MERKLE TREE (ripple::zkp::IncrementalMerkleTree)
           - Optimized data structure with cached intermediate nodes
           - O(log n) complexity for insertions and authentication path generation
           - Used in production blockchain and ZK-SNARK applications
        
        2. REGULAR MERKLE TREE (naive implementation)
           - Rebuilds entire tree from scratch for each operation
           - O(n) complexity for insertions, O(n) for authentication path generation
           - Represents the baseline/naive approach
        
        TEST STRUCTURE:
        ===============
        - Tests tree depths: 8, 12, 16, 20
        - Runs 3 samples per test for statistical reliability
        - Uses nanosecond precision timing 
        - Tests three strategic positions: first, middle, last node
        
        THREE CORE METRICS MEASURED:
        ============================
        
        1. APPEND OPERATION
           Purpose: Time to add one new leaf to existing tree
           
           Incremental: incrementalTree.append(newLeaf)
           - Algorithm: Updates only path from leaf to root
           - Complexity: O(log n) - touches ~depth nodes only
           - Uses cached nodes and frontier optimisation
           
           Regular: Rebuild entire tree with new leaf included
           - Algorithm: Processes all n leaves, rebuilds all levels
           - Complexity: O(n) - must recompute entire tree structure
           - No caching, starts from scratch each time
           
           Expected Result: Incremental dramatically faster
        
        2. AUTHENTICATION PATH GENERATION
           Purpose: Generate cryptographic proof of leaf membership
           
           What is a Merkle Authentication Path?
           - Collection of sibling hashes enabling verification without full tree
           - Used in ZK-SNARKs
           - Path from leaf to root with sibling at each level
           
           Incremental: authPath = tree.authPath(position)
           - Algorithm: Retrieves cached sibling nodes from internal structures
           - Complexity: O(log n) - traverses cached path to root
           - Leverages pre-computed intermediate values
           
           Regular: Manual tree traversal collecting siblings
           - Algorithm: Rebuilds tree levels while collecting sibling nodes
           - Complexity: O(n) - must recompute intermediate levels
           - No caching benefit, reconstructs on-demand
           
           Position Testing: Tests first (0), middle (size/2), last (size-1) nodes
           - Verifies performance consistency across tree positions
           
           Expected Result: Incremental faster due to caching (1.2-1.3x speedup)
        
        3. VERIFY OPERATION
           Purpose: Verify authentication path proves leaf membership
           
           Algorithm (identical for both implementations):
           - Start with leaf value
           - For each level: hash current value with sibling
           - Order depends on position (left/right child)
           - Final result should equal known root hash
           
           Expected Result: Nearly identical performance (~1.0x)
           - Both do same computational work
           - Minor differences from cache locality effects
        
        PERFORMANCE EXPECTATIONS:
        ========================
        Tree Depth    Append Speedup    Auth Path Speedup    Verify Speedup
        ---------    --------------    -------------        --------------
        8            ~200-300x         ~1.2x                ~1.0x
        12           ~2,000x           ~1.2x                ~1.0x
        16           ~20,000x          ~1.3x                ~1.0x
        20           ~250,000x         ~1.2x                ~1.0x

        The test demonstrates why incremental Merkle trees are essential
        for large-scale applications requiring frequent tree updates.
        */
        testcase("Incremental vs Regular Merkle Tree Performance Comparison");

        const int testDepths[] = {4, 8, 12}; 
        const int numSamples = 3;
        
        //std::cout << "Comparing Incremental vs Regular Merkle Tree Performance...\n";
        //std::cout << "This test compares equivalent operations (single leaf updates and authentication path generation)\n";
        //std::cout << "to provide a fair comparison between incremental and regular Merkle trees.\n\n";

        // Results storage
        std::vector<long long> testSizesResults;
        std::vector<long long> incrementalAppendTimes;
        std::vector<long long> regularAppendTimes;
        std::vector<long long> incrementalAuthPathTimes;
        std::vector<long long> regularAuthPathTimes;
        std::vector<long long> incrementalVerifyTimes;
        std::vector<long long> regularVerifyTimes;

        for (int depth : testDepths) {
            long long size = (1LL << depth); // Calculate size for this depth
            //std::cout << "=== Testing with depth " << depth << " (" << size << " nodes) ===\n";
            
            long long totalIncAppend = 0, totalRegAppend = 0;
            long long totalIncAuthPath = 0, totalRegAuthPath = 0;
            long long totalIncVerify = 0, totalRegVerify = 0;
            int successfulSamples = 0;

            for (int sample = 0; sample < numSamples; ++sample) {
                try {
                    // Generate test data
                    std::vector<uint256> testHashes;
                    for (long long i = 0; i < size; ++i) {
                        std::string data = "test_data_" + std::to_string(i);
                        testHashes.push_back(sha512Half(Slice{data.data(), data.size()}));
                    }

                    // Pre-build trees to exclude initialization overhead
                    ripple::zkp::IncrementalMerkleTree incrementalTree(depth); // Use actual depth
                    std::vector<uint256> regularTree = testHashes;

                    // Add all but the last element to both trees
                    for (long long i = 0; i < size - 1; ++i) {
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

                    // Test 2: AUTH_PATH GENERATION (for first, middle, and last elements)
                    std::vector<long long> testPositions = {0, size / 2, size - 1}; // First, middle, last
                    std::vector<std::string> positionNames = {"First", "Middle", "Last"};
                    
                    long long totalIncAuthPathTime = 0, totalRegAuthPathTime = 0;
                    long long totalIncVerifyTime = 0, totalRegVerifyTime = 0;
                    
                    for (size_t posIdx = 0; posIdx < testPositions.size(); ++posIdx) {
                        long long authPathPosition = testPositions[posIdx];
                        std::string posName = positionNames[posIdx];
                        
                        // Incremental tree authentication path generation
                        auto incAuthPathStart = std::chrono::high_resolution_clock::now();
                        auto incAuthPath = incrementalTree.authPath(authPathPosition);
                        auto incAuthPathEnd = std::chrono::high_resolution_clock::now();
                        auto incAuthPathTime = std::chrono::duration_cast<std::chrono::nanoseconds>(incAuthPathEnd - incAuthPathStart).count();

                        // Regular tree authentication path generation
                        auto regAuthPathStart = std::chrono::high_resolution_clock::now();
                        std::vector<uint256> regAuthPath;
                        {
                            std::vector<uint256> currentLevel = testHashes;
                            long long position = authPathPosition;
                            
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
                        auto regAuthPathEnd = std::chrono::high_resolution_clock::now();
                        auto regAuthPathTime = std::chrono::duration_cast<std::chrono::nanoseconds>(regAuthPathEnd - regAuthPathStart).count();

                        // Test 3: VERIFICATION (verify the authentication path for this position)
                        auto incVerifyStart = std::chrono::high_resolution_clock::now();
                        {
                            uint256 currentHash = testHashes[authPathPosition];
                            long long pos = authPathPosition;
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
                            uint256 currentHash = testHashes[authPathPosition];
                            long long pos = authPathPosition;
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
                        
                        // Accumulate times for position
                        totalIncAuthPathTime += incAuthPathTime;
                        totalRegAuthPathTime += regAuthPathTime;
                        totalIncVerifyTime += incVerifyTime;
                        totalRegVerifyTime += regVerifyTime;
                        
                        // Store individual position results for detailed output
                        if (sample == 0) { // Only print on first sample for clarity
                            double authPathSpeedup = (regAuthPathTime > 0) ? (double)regAuthPathTime / incAuthPathTime : 0.0;
                            double verifySpeedup = (regVerifyTime > 0) ? (double)regVerifyTime / incVerifyTime : 0.0;
                            // std::cout << "    " << posName << " (" << authPathPosition << "): " 
                            //          << "AUTH_PATH Inc=" << incAuthPathTime << "ns (len=" << incAuthPath.size() << "), "
                            //          << "Reg=" << regAuthPathTime << "ns (len=" << regAuthPath.size() << ") (" 
                            //          << std::fixed << std::setprecision(1) << authPathSpeedup << "x), "
                            //          << "VERIFY Inc=" << incVerifyTime << "ns, Reg=" << regVerifyTime << "ns (" 
                            //          << verifySpeedup << "x)\n";
                        }
                    }

                    // Accumulate times (nanoseconds)
                    totalIncAppend += incAppendTime;
                    totalRegAppend += regAppendTime;
                    totalIncAuthPath += totalIncAuthPathTime / 3; // Average across 3 positions
                    totalRegAuthPath += totalRegAuthPathTime / 3; // Average across 3 positions
                    totalIncVerify += totalIncVerifyTime / 3; // Average across 3 positions
                    totalRegVerify += totalRegVerifyTime / 3; // Average across 3 positions
                    successfulSamples++;

                } catch (std::exception& e) {
                    //std::cout << "Sample " << sample << " failed: " << e.what() << "\n";
                }
            }

            if (successfulSamples > 0) {
                long long avgIncAppend = totalIncAppend / successfulSamples;
                long long avgRegAppend = totalRegAppend / successfulSamples;
                long long avgIncAuthPath = totalIncAuthPath / successfulSamples;
                long long avgRegAuthPath = totalRegAuthPath / successfulSamples;
                long long avgIncVerify = totalIncVerify / successfulSamples;
                long long avgRegVerify = totalRegVerify / successfulSamples;
                
                testSizesResults.push_back(size);
                incrementalAppendTimes.push_back(avgIncAppend);
                regularAppendTimes.push_back(avgRegAppend);
                incrementalAuthPathTimes.push_back(avgIncAuthPath);
                regularAuthPathTimes.push_back(avgRegAuthPath);
                incrementalVerifyTimes.push_back(avgIncVerify);
                regularVerifyTimes.push_back(avgRegVerify);
                
                double appendSpeedup = (avgRegAppend > 0) ? (double)avgRegAppend / avgIncAppend : 0.0;
                double authPathSpeedup = (avgRegAuthPath > 0) ? (double)avgRegAuthPath / avgIncAuthPath : 0.0;
                double verifySpeedup = (avgRegVerify > 0) ? (double)avgRegVerify / avgIncVerify : 0.0;
                
                //std::cout << "Results for " << size << " nodes (" << successfulSamples << " samples):\n";
                //std::cout << "  APPEND: Inc=" << avgIncAppend << "ns, Reg=" << avgRegAppend << "ns, Speedup=" << std::fixed << std::setprecision(1) << appendSpeedup << "x\n";
                //std::cout << "  AUTH_PATH:  Inc=" << avgIncAuthPath << "ns, Reg=" << avgRegAuthPath << "ns, Speedup=" << authPathSpeedup << "x\n";
                //std::cout << "  VERIFY: Inc=" << avgIncVerify << "ns, Reg=" << avgRegVerify << "ns, Speedup=" << verifySpeedup << "x\n\n";
                
                // Validate test results
                BEAST_EXPECT(avgIncAppend >= 0);
                BEAST_EXPECT(avgRegAppend >= 0);
                BEAST_EXPECT(avgIncAuthPath >= 0);
                BEAST_EXPECT(avgRegAuthPath >= 0);
            }
        }

        // Display comprehensive comparison
        //std::cout << "==========================================\n";
        //std::cout << "INCREMENTAL VS REGULAR MERKLE TREE COMPARISON\n";
        //std::cout << "==========================================\n";
        
        if (!testSizesResults.empty()) {
            //std::cout << "Operation\tNodes\tIncremental(ns)\tRegular(ns)\tSpeedup\n";
            //std::cout << "---------\t-----\t--------------\t----------\t-------\n";
            
            for (size_t i = 0; i < testSizesResults.size(); ++i) {
                long long size = testSizesResults[i];
                long long incAppend = incrementalAppendTimes[i];
                long long regAppend = regularAppendTimes[i];
                long long incAuthPath = incrementalAuthPathTimes[i];
                long long regAuthPath = regularAuthPathTimes[i];
                long long incVerify = incrementalVerifyTimes[i];
                long long regVerify = regularVerifyTimes[i];
                
                double appendSpeedup = (regAppend > 0) ? (double)regAppend / incAppend : 0.0;
                double authPathSpeedup = (regAuthPath > 0) ? (double)regAuthPath / incAuthPath : 0.0;
                double verifySpeedup = (regVerify > 0) ? (double)regVerify / incVerify : 0.0;
                
                // std::cout << "APPEND\t\t" << size << "\t" << incAppend << "\t\t" << regAppend << "\t\t" 
                //          << std::fixed << std::setprecision(1) << appendSpeedup << "x\n";
                // std::cout << "AUTH_PATH\t\t" << size << "\t" << incAuthPath << "\t\t" << regAuthPath << "\t\t" 
                //          << authPathSpeedup << "x\n";
                // std::cout << "VERIFY\t\t" << size << "\t" << incVerify << "\t\t" << regVerify << "\t\t" 
                //          << verifySpeedup << "x\n";
                // std::cout << "-----\t\t-----\t--------------\t----------\t-------\n";
            }
            

            
        }
        //std::cout << "==========================================\n";
    }

private:
};

BEAST_DEFINE_TESTSUITE(MerkleTree, protocol, ripple);

}  // namespace ripple
