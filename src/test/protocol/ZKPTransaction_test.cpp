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
#include <limits>

#include <libxrpl/zkp/Note.h>          
#include <libxrpl/zkp/ZKProver.h>
#include <libxrpl/zkp/IncrementalMerkleTree.h>

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
        testSecp256k1Transaction();          // standalone secp256k1 perf (already self-contained)
        testEd25519Transaction();            // standalone ed25519 perf (already self-contained)
        testZKTransactionPerformance();      // standalone zk deposit perf
        testSecp256k1PlusZKPerformance();    // combined secp256k1 + zk deposit perf
        testEd25519PlusZKPerformance();      // combined ed25519 + zk deposit perf
        // testComprehensivePerformanceComparison();
    }

    void
    testSecp256k1Transaction()
    {
        testcase("Secp256k1 Full Transaction Process (Performance)");

        const int iterations = 1000;  // tune as needed
        long long totalKeygen = 0, totalSign = 0, totalVerify = 0;
        long long minKeygen = std::numeric_limits<long long>::max();
        long long minSign = std::numeric_limits<long long>::max();
        long long minVerify = std::numeric_limits<long long>::max();
        long long maxKeygen = 0, maxSign = 0, maxVerify = 0;

        // Warm-up to avoid first-iteration skew
        for (int w = 0; w < 5; ++w) {
            auto kp = randomKeyPair(KeyType::secp256k1);
            std::string msg = "warmup secp256k1";
            auto digest = sha512Half(Slice{msg.data(), msg.size()});
            auto sig = signDigest(kp.first, kp.second, digest);
            (void)verifyDigest(kp.first, digest, sig);
        }

        for (int i = 0; i < iterations; ++i)
        {
            // Key generation
            auto startK = std::chrono::high_resolution_clock::now();
            auto keyPair = randomKeyPair(KeyType::secp256k1);
            auto endK = std::chrono::high_resolution_clock::now();
            auto dk = (long long)std::chrono::duration_cast<std::chrono::microseconds>(endK - startK).count();
            totalKeygen += dk; minKeygen = std::min(minKeygen, dk); maxKeygen = std::max(maxKeygen, dk);

            auto const& pk = keyPair.first;
            auto const& sk = keyPair.second;

            BEAST_EXPECT(pk.size() != 0);
            BEAST_EXPECT(sk.size() != 0);

            // Sign
            std::string message = "This is a test transaction for secp256k1.";
            uint256 digest = sha512Half(Slice{message.data(), message.size()});

            auto startS = std::chrono::high_resolution_clock::now();
            auto sig = signDigest(pk, sk, digest);
            auto endS = std::chrono::high_resolution_clock::now();
            auto ds = (long long)std::chrono::duration_cast<std::chrono::microseconds>(endS - startS).count();
            totalSign += ds; minSign = std::min(minSign, ds); maxSign = std::max(maxSign, ds);

            BEAST_EXPECT(sig.size() != 0);

            // Verify
            auto startV = std::chrono::high_resolution_clock::now();
            bool isValid = verifyDigest(pk, digest, sig);
            auto endV = std::chrono::high_resolution_clock::now();
            auto dv = (long long)std::chrono::duration_cast<std::chrono::microseconds>(endV - startV).count();
            totalVerify += dv; minVerify = std::min(minVerify, dv); maxVerify = std::max(maxVerify, dv);

            BEAST_EXPECT(isValid);
        }

        // Averages and TPS
        long long avgK = totalKeygen / iterations;
        long long avgS = totalSign / iterations;
        long long avgV = totalVerify / iterations;
        long long avgTotal = avgK + avgS + avgV;

        std::cout << "\n=== Secp256k1 Performance (standalone) ===\n";
        std::cout << "Iterations: " << iterations << "\n";
        std::cout << "KeyGen: avg=" << avgK << " us, min=" << minKeygen << " us, max=" << maxKeygen << " us\n";
        std::cout << "Sign:   avg=" << avgS << " us, min=" << minSign   << " us, max=" << maxSign   << " us\n";
        std::cout << "Verify: avg=" << avgV << " us, min=" << minVerify << " us, max=" << maxVerify << " us\n";
        std::cout << "Total/txn: " << avgTotal << " us\n";
        std::cout << "Throughput: " << (avgTotal > 0 ? (1000000.0 / avgTotal) : 0.0) << " tx/s\n";
    }

    void
    testEd25519Transaction(){
  
        testcase("Ed25519 Full Transaction Process (Performance)");

        const int iterations = 1000;  // tune as needed
        long long totalKeygen = 0, totalSign = 0, totalVerify = 0;
        long long minKeygen = std::numeric_limits<long long>::max();
        long long minSign = std::numeric_limits<long long>::max();
        long long minVerify = std::numeric_limits<long long>::max();
        long long maxKeygen = 0, maxSign = 0, maxVerify = 0;

        // Warm-up
        for (int w = 0; w < 5; ++w) {
            auto kp = randomKeyPair(KeyType::ed25519);
            std::string msg = "warmup ed25519";
            auto sig = sign(kp.first, kp.second, Slice{msg.data(), msg.size()});
            (void)verify(kp.first, Slice{msg.data(), msg.size()}, sig);
        }

        for (int i = 0; i < iterations; ++i)
        {
            // Key generation
            auto startK = std::chrono::high_resolution_clock::now();
            auto keyPair = randomKeyPair(KeyType::ed25519);
            auto endK = std::chrono::high_resolution_clock::now();
            auto dk = (long long)std::chrono::duration_cast<std::chrono::microseconds>(endK - startK).count();
            totalKeygen += dk; minKeygen = std::min(minKeygen, dk); maxKeygen = std::max(maxKeygen, dk);

            auto const& pk = keyPair.first;
            auto const& sk = keyPair.second;

            BEAST_EXPECT(pk.size() != 0);
            BEAST_EXPECT(sk.size() != 0);

            // Sign (Ed25519 signs the message directly, not a digest)
            std::string message = "This is a test transaction for ed25519.";

            auto startS = std::chrono::high_resolution_clock::now();
            auto sig = sign(pk, sk, Slice{message.data(), message.size()});
            auto endS = std::chrono::high_resolution_clock::now();
            auto ds = (long long)std::chrono::duration_cast<std::chrono::microseconds>(endS - startS).count();
            totalSign += ds; minSign = std::min(minSign, ds); maxSign = std::max(maxSign, ds);

            BEAST_EXPECT(sig.size() != 0);

            // Verify
            auto startV = std::chrono::high_resolution_clock::now();
            bool isValid = verify(pk, Slice{message.data(), message.size()}, sig);
            auto endV = std::chrono::high_resolution_clock::now();
            auto dv = (long long)std::chrono::duration_cast<std::chrono::microseconds>(endV - startV).count();
            totalVerify += dv; minVerify = std::min(minVerify, dv); maxVerify = std::max(maxVerify, dv);

            BEAST_EXPECT(isValid);
        }

        // Averages and TPS
        long long avgK = totalKeygen / iterations;
        long long avgS = totalSign / iterations;
        long long avgV = totalVerify / iterations;
        long long avgTotal = avgK + avgS + avgV;

        std::cout << "\n=== Ed25519 Performance (standalone) ===\n";
        std::cout << "Iterations: " << iterations << "\n";
        std::cout << "KeyGen: avg=" << avgK << " us, min=" << minKeygen << " us, max=" << maxKeygen << " us\n";
        std::cout << "Sign:   avg=" << avgS << " us, min=" << minSign   << " us, max=" << maxSign   << " us\n";
        std::cout << "Verify: avg=" << avgV << " us, min=" << minVerify << " us, max=" << maxVerify << " us\n";
        std::cout << "Total/txn: " << avgTotal << " us\n";
        std::cout << "Throughput: " << (avgTotal > 0 ? (1000000.0 / avgTotal) : 0.0) << " tx/s\n";
    }


    void
    testZKTransactionPerformance()
    {
        testcase("ZK Deposit Proof (Standalone) Performance");

        const int iterations = 20; // tune as needed
        long long total = 0;
        long long minT = std::numeric_limits<long long>::max();
        long long maxT = 0;

        // Initialize ZKP system once
        bool zkp_initialized = false;
        try {
            ripple::zkp::ZkProver::initialize();
            zkp_initialized = ripple::zkp::ZkProver::generateKeys(false);
            std::cout << "ZKP system initialized successfully\n";
        } catch (std::exception& e) {
            std::cout << "ZKP initialization failed: " << e.what() << "\n";
            BEAST_EXPECT(false);
            return;
        }

        // Warm-up
        if (zkp_initialized) {
            auto note = ripple::zkp::ZkProver::createRandomNote(1234567);
            auto proof = ripple::zkp::ZkProver::createDepositProof(note);
            (void)ripple::zkp::ZkProver::verifyDepositProof(proof);
        }

        for (int i = 0; i < iterations; ++i)
        {
            if (!zkp_initialized) break;

            auto start = std::chrono::high_resolution_clock::now();
            try {
                ripple::zkp::Note depositNote = ripple::zkp::ZkProver::createRandomNote(1000000 + i * 100000);
                auto depositProof = ripple::zkp::ZkProver::createDepositProof(depositNote);
                BEAST_EXPECT(!depositProof.empty());

                bool depositValid = ripple::zkp::ZkProver::verifyDepositProof(depositProof);
                BEAST_EXPECT(depositValid);
            } catch (std::exception& e) {
                std::cout << "ZK deposit test failed for " << i << ": " << e.what() << std::endl;
                BEAST_EXPECT(false);
            }
            auto end = std::chrono::high_resolution_clock::now();

            auto dt = (long long)std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
            total += dt;
            minT = std::min(minT, dt);
            maxT = std::max(maxT, dt);
        }

        long long avg = (iterations > 0) ? (total / iterations) : 0;

        std::cout << "\n=== ZK Deposit Performance (standalone) ===\n";
        std::cout << "Iterations: " << iterations << "\n";
        std::cout << "Full deposit (prove+verify): avg=" << avg << " us, min=" << minT << " us, max=" << maxT << " us\n";
        std::cout << "Throughput: " << (avg > 0 ? (1000000.0 / avg) : 0.0) << " tx/s\n";
    }

    void
    testSecp256k1PlusZKPerformance()
    {
        testcase("Combined: Secp256k1 Signature + ZK Deposit (Performance)");

        const int iterations = 100; // tune as needed
        long long total = 0;
        long long minT = std::numeric_limits<long long>::max();
        long long maxT = 0;

        // Initialize ZKP system once
        bool zkp_initialized = false;
        try {
            ripple::zkp::ZkProver::initialize();
            zkp_initialized = ripple::zkp::ZkProver::generateKeys(false);
        } catch (std::exception& e) {
            std::cout << "ZKP init failed: " << e.what() << "\n";
            BEAST_EXPECT(false);
            return;
        }

        // Warm-up
        {
            auto kp = randomKeyPair(KeyType::secp256k1);
            std::string msg = "warmup secp+zk";
            auto digest = sha512Half(Slice{msg.data(), msg.size()});
            auto sig = signDigest(kp.first, kp.second, digest);
            (void)verifyDigest(kp.first, digest, sig);

            auto note = ripple::zkp::ZkProver::createRandomNote(424242);
            auto proof = ripple::zkp::ZkProver::createDepositProof(note);
            (void)ripple::zkp::ZkProver::verifyDepositProof(proof);
        }

        for (int i = 0; i < iterations; ++i)
        {
            auto start = std::chrono::high_resolution_clock::now();

            // 1) Secp256k1 sign + verify
            auto keyPair = randomKeyPair(KeyType::secp256k1);
            auto const& pk = keyPair.first;
            auto const& sk = keyPair.second;

            std::string message = "Combined secp256k1 + ZK transaction";
            uint256 digest = sha512Half(Slice{message.data(), message.size()});
            auto sig = signDigest(pk, sk, digest);
            bool sigValid = verifyDigest(pk, digest, sig);
            BEAST_EXPECT(sigValid);

            // 2) ZK deposit prove + verify
            ripple::zkp::Note depositNote = ripple::zkp::ZkProver::createRandomNote(2000000 + i);
            auto depositProof = ripple::zkp::ZkProver::createDepositProof(depositNote);
            bool depositValid = ripple::zkp::ZkProver::verifyDepositProof(depositProof);
            BEAST_EXPECT(depositValid);

            auto end = std::chrono::high_resolution_clock::now();

            auto dt = (long long)std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
            total += dt;
            minT = std::min(minT, dt);
            maxT = std::max(maxT, dt);
        }

        long long avg = (iterations > 0) ? (total / iterations) : 0;

        std::cout << "\n=== Combined Secp256k1 + ZK Deposit Performance ===\n";
        std::cout << "Iterations: " << iterations << "\n";
        std::cout << "End-to-end: avg=" << avg << " us, min=" << minT << " us, max=" << maxT << " us\n";
        std::cout << "Throughput: " << (avg > 0 ? (1000000.0 / avg) : 0.0) << " tx/s\n";
    }

    void
    testEd25519PlusZKPerformance()
    {
        testcase("Combined: Ed25519 Signature + ZK Deposit (Performance)");

        const int iterations = 100; // tune as needed
        long long total = 0;
        long long minT = std::numeric_limits<long long>::max();
        long long maxT = 0;

        // Initialize ZKP system once
        bool zkp_initialized = false;
        try {
            ripple::zkp::ZkProver::initialize();
            zkp_initialized = ripple::zkp::ZkProver::generateKeys(false);
        } catch (std::exception& e) {
            std::cout << "ZKP init failed: " << e.what() << "\n";
            BEAST_EXPECT(false);
            return;
        }

        // Warm-up
        {
            auto kp = randomKeyPair(KeyType::ed25519);
            std::string msg = "warmup ed+zk";
            auto sig = sign(kp.first, kp.second, Slice{msg.data(), msg.size()});
            (void)verify(kp.first, Slice{msg.data(), msg.size()}, sig);

            auto note = ripple::zkp::ZkProver::createRandomNote(737373);
            auto proof = ripple::zkp::ZkProver::createDepositProof(note);
            (void)ripple::zkp::ZkProver::verifyDepositProof(proof);
        }

        for (int i = 0; i < iterations; ++i)
        {
            auto start = std::chrono::high_resolution_clock::now();

            // 1) Ed25519 sign + verify
            auto keyPair = randomKeyPair(KeyType::ed25519);
            auto const& pk = keyPair.first;
            auto const& sk = keyPair.second;

            std::string message = "Combined ed25519 + ZK transaction";
            auto sig = sign(pk, sk, Slice{message.data(), message.size()});
            bool sigValid = verify(pk, Slice{message.data(), message.size()}, sig);
            BEAST_EXPECT(sigValid);

            // 2) ZK deposit prove + verify
            ripple::zkp::Note depositNote = ripple::zkp::ZkProver::createRandomNote(3000000 + i);
            auto depositProof = ripple::zkp::ZkProver::createDepositProof(depositNote);
            bool depositValid = ripple::zkp::ZkProver::verifyDepositProof(depositProof);
            BEAST_EXPECT(depositValid);

            auto end = std::chrono::high_resolution_clock::now();

            auto dt = (long long)std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
            total += dt;
            minT = std::min(minT, dt);
            maxT = std::max(maxT, dt);
        }

        long long avg = (iterations > 0) ? (total / iterations) : 0;

        std::cout << "\n=== Combined Ed25519 + ZK Deposit Performance ===\n";
        std::cout << "Iterations: " << iterations << "\n";
        std::cout << "End-to-end: avg=" << avg << " us, min=" << minT << " us, max=" << maxT << " us\n";
        std::cout << "Throughput: " << (avg > 0 ? (1000000.0 / avg) : 0.0) << " tx/s\n";
    }

    void
    testComprehensivePerformanceComparison()
    {
        testcase("Comprehensive Performance Comparison: Secp256k1 vs Ed25519 vs ZKP");

        const int iterations = 1000; // More iterations for statistical significance
        
        // Performance metrics storage
        long long totalSecp256k1KeygenTime = 0;
        long long totalSecp256k1SignTime = 0;
        long long totalSecp256k1VerifyTime = 0;
        
        long long totalEd25519KeygenTime = 0;
        long long totalEd25519SignTime = 0;
        long long totalEd25519VerifyTime = 0;
        
        long long totalZKDepositTime = 0;

        // Initialize ZKP system once
        bool zkp_initialized = false;
        try {
            ripple::zkp::ZkProver::initialize();
            zkp_initialized = ripple::zkp::ZkProver::generateKeys(false);
            std::cout << "ZKP system initialized successfully for comparison testing\n";
        } catch (std::exception& e) {
            std::cout << "ZKP initialization failed: " << e.what() << "\n";
        }

        std::cout << "Starting comprehensive performance comparison with " << iterations << " iterations...\n";

        for (int i = 0; i < iterations; ++i)
        {
            // ===========================================
            // SECP256K1 PERFORMANCE
            // ===========================================
            {
                // Key Generation
                auto startKeygen = std::chrono::high_resolution_clock::now();
                auto keyPair = randomKeyPair(KeyType::secp256k1);
                auto endKeygen = std::chrono::high_resolution_clock::now();
                auto keygenDuration = static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(endKeygen - startKeygen).count());
                totalSecp256k1KeygenTime += keygenDuration;

                auto const& sk = keyPair.second;
                auto const& pk = keyPair.first;

                // Signing
                std::string message = "Performance test message for secp256k1";
                uint256 digest = sha512Half(Slice{message.data(), message.size()});
                
                auto startSign = std::chrono::high_resolution_clock::now();
                auto sig = signDigest(pk, sk, digest);
                auto endSign = std::chrono::high_resolution_clock::now();
                auto signDuration = static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(endSign - startSign).count());
                totalSecp256k1SignTime += signDuration;

                // Verification
                auto startVerify = std::chrono::high_resolution_clock::now();
                bool isValid = verifyDigest(pk, digest, sig);
                auto endVerify = std::chrono::high_resolution_clock::now();
                auto verifyDuration = static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(endVerify - startVerify).count());
                totalSecp256k1VerifyTime += verifyDuration;

                BEAST_EXPECT(isValid);
            }

            // ===========================================
            // ED25519 PERFORMANCE
            // ===========================================
            {
                // Key Generation
                auto startKeygen = std::chrono::high_resolution_clock::now();
                auto keyPair = randomKeyPair(KeyType::ed25519);
                auto endKeygen = std::chrono::high_resolution_clock::now();
                auto keygenDuration = static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(endKeygen - startKeygen).count());
                totalEd25519KeygenTime += keygenDuration;

                auto const& sk = keyPair.second;
                auto const& pk = keyPair.first;

                // Signing
                std::string message = "Performance test message for ed25519";
                
                auto startSign = std::chrono::high_resolution_clock::now();
                auto sig = sign(pk, sk, Slice{message.data(), message.size()});
                auto endSign = std::chrono::high_resolution_clock::now();
                auto signDuration = static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(endSign - startSign).count());
                totalEd25519SignTime += signDuration;

                // Verification
                auto startVerify = std::chrono::high_resolution_clock::now();
                bool isValid = verify(pk, Slice{message.data(), message.size()}, sig);
                auto endVerify = std::chrono::high_resolution_clock::now();
                auto verifyDuration = static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(endVerify - startVerify).count());
                totalEd25519VerifyTime += verifyDuration;

                BEAST_EXPECT(isValid);
            }

            // ===========================================
            // ZK DEPOSIT PERFORMANCE (Every 100 iterations to manage time)
            // ===========================================
            if (zkp_initialized && (i % 100 == 0)) {
                try {
                    auto startZKDeposit = std::chrono::high_resolution_clock::now();

                    // Create note
                    ripple::zkp::Note depositNote = ripple::zkp::ZkProver::createRandomNote(1000000 + i);
                    
                    // Generate deposit proof
                    auto depositProof = ripple::zkp::ZkProver::createDepositProof(depositNote);
                    
                    // Verify deposit proof
                    bool depositValid = ripple::zkp::ZkProver::verifyDepositProof(depositProof);

                    auto endZKDeposit = std::chrono::high_resolution_clock::now();
                    auto zkDepositDuration = static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(endZKDeposit - startZKDeposit).count());
                    totalZKDepositTime += zkDepositDuration;

                    BEAST_EXPECT(depositValid);
                } catch (std::exception& e) {
                    std::cout << "ZK test failed for iteration " << i << ": " << e.what() << std::endl;
                }
            }

            // Progress indicator
            if ((i + 1) % 100 == 0) {
                std::cout << "Completed " << (i + 1) << "/" << iterations << " iterations\n";
            }
        }

        // Calculate averages
        long long avgSecp256k1Keygen = totalSecp256k1KeygenTime / iterations;
        long long avgSecp256k1Sign = totalSecp256k1SignTime / iterations;
        long long avgSecp256k1Verify = totalSecp256k1VerifyTime / iterations;
        
        long long avgEd25519Keygen = totalEd25519KeygenTime / iterations;
        long long avgEd25519Sign = totalEd25519SignTime / iterations;
        long long avgEd25519Verify = totalEd25519VerifyTime / iterations;
        
        int zkIterations = iterations / 100;
        long long avgZKDeposit = zkp_initialized && zkIterations > 0 ? totalZKDepositTime / zkIterations : 0;

        // Display comprehensive results
        std::cout << "\n==========================================\n";
        std::cout << "COMPREHENSIVE PERFORMANCE COMPARISON\n";
        std::cout << "==========================================\n";
        std::cout << "Total Iterations: " << iterations << "\n\n";

        std::cout << "SECP256K1 PERFORMANCE:\n";
        std::cout << "  Key Generation: " << avgSecp256k1Keygen << " μs average\n";
        std::cout << "  Signing: " << avgSecp256k1Sign << " μs average\n";
        std::cout << "  Verification: " << avgSecp256k1Verify << " μs average\n";
        std::cout << "  Total Transaction: " << (avgSecp256k1Keygen + avgSecp256k1Sign + avgSecp256k1Verify) << " μs average\n";
        std::cout << "  Throughput: " << (1000000.0 / (avgSecp256k1Keygen + avgSecp256k1Sign + avgSecp256k1Verify)) << " transactions/second\n\n";

        std::cout << "ED25519 PERFORMANCE:\n";
        std::cout << "  Key Generation: " << avgEd25519Keygen << " μs average\n";
        std::cout << "  Signing: " << avgEd25519Sign << " μs average\n";
        std::cout << "  Verification: " << avgEd25519Verify << " μs average\n";
        std::cout << "  Total Transaction: " << (avgEd25519Keygen + avgEd25519Sign + avgEd25519Verify) << " μs average\n";
        std::cout << "  Throughput: " << (1000000.0 / (avgEd25519Keygen + avgEd25519Sign + avgEd25519Verify)) << " transactions/second\n\n";

        if (zkp_initialized && avgZKDeposit > 0) {
            std::cout << "ZK DEPOSIT PERFORMANCE:\n";
            std::cout << "  Full Deposit Process: " << avgZKDeposit << " μs average (" << zkIterations << " samples)\n";
            std::cout << "  Throughput: " << (1000000.0 / avgZKDeposit) << " transactions/second\n\n";
        }

        std::cout << "PERFORMANCE RATIOS (vs Secp256k1):\n";
        long long secp256k1Total = avgSecp256k1Keygen + avgSecp256k1Sign + avgSecp256k1Verify;
        long long ed25519Total = avgEd25519Keygen + avgEd25519Sign + avgEd25519Verify;
        
        std::cout << "  Ed25519 vs Secp256k1: " << (double)ed25519Total / secp256k1Total << "x\n";
        if (zkp_initialized && avgZKDeposit > 0) {
            std::cout << "  ZK vs Secp256k1: " << (double)avgZKDeposit / secp256k1Total << "x\n";
            std::cout << "  ZK vs Ed25519: " << (double)avgZKDeposit / ed25519Total << "x\n";
        }

        std::cout << "==========================================\n";
    }

    void testMetrics()
    {
        testcase("Performance Comparison: Secp256k1 vs ZKP");

        const int NUM_ITERATIONS = 2;  // Very small for compilation testing
        
        // Initialize ZKP system once
        bool zkp_initialized = false;
        try {
            ripple::zkp::ZkProver::initialize();
            zkp_initialized = ripple::zkp::ZkProver::generateKeys(false);
        } catch (std::exception& e) {
            std::cout << "ZKP initialization failed: " << e.what() << std::endl;
        }
        
        // Secp256k1 Key Generation Timing
        auto secp256k1_keygen_start = std::chrono::high_resolution_clock::now();
        std::vector<std::pair<PublicKey, SecretKey>> secp256k1_keys;
        
        for (int i = 0; i < NUM_ITERATIONS; ++i) {
            auto keyPair = randomKeyPair(KeyType::secp256k1);
            secp256k1_keys.push_back(keyPair);
        }
        
        auto secp256k1_keygen_end = std::chrono::high_resolution_clock::now();
        auto secp256k1_keygen_duration = std::chrono::duration_cast<std::chrono::microseconds>(secp256k1_keygen_end - secp256k1_keygen_start);
        
        // ZKP Note Generation Timing
        auto zkp_keygen_start = std::chrono::high_resolution_clock::now();
        std::vector<ripple::zkp::Note> zkp_notes;
        
        for (int i = 0; i < std::min(NUM_ITERATIONS, 1); ++i) {
            if (zkp_initialized) {
                try {
                    ripple::zkp::Note note = ripple::zkp::ZkProver::createRandomNote(1000000);
                    zkp_notes.push_back(note);
                    
                    std::cout << "\n=== ZKP NOTE DEBUG " << i << " ===" << std::endl;
                    std::cout << "  Value: " << note.value << std::endl;
                    std::cout << "  Commitment: " << note.commitment() << std::endl;
                    
                } catch (std::exception& e) {
                    std::cout << "ZKP note generation failed for " << i << ": " << e.what() << std::endl;
                }
            }
        }
        
        auto zkp_keygen_end = std::chrono::high_resolution_clock::now();
        auto zkp_keygen_duration = std::chrono::duration_cast<std::chrono::microseconds>(zkp_keygen_end - zkp_keygen_start);
        
        // Results
        std::cout << "\n=== KEY GENERATION PERFORMANCE ===" << std::endl;
        std::cout << "Secp256k1 (avg per key): " << secp256k1_keygen_duration.count() / NUM_ITERATIONS << " μs" << std::endl;
        if (!zkp_notes.empty()) {
            std::cout << "ZKP Note (avg per note): " << zkp_keygen_duration.count() / zkp_notes.size() << " μs" << std::endl;
        }
        
        BEAST_EXPECT(secp256k1_keys.size() == NUM_ITERATIONS);
        
        std::cout << "\n=== TEST COMPLETED ===" << std::endl;
    }
};

BEAST_DEFINE_TESTSUITE(ZKPTransaction, ripple_app, ripple);

}  // namespace ripple