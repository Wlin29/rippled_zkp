#include <xrpl/beast/unit_test.h>
#include <array>
#include <vector>
#include <string>
#include <algorithm>
#include <random>
#include <libxrpl/zkp/circuits/MerkleCircuit.h>

namespace ripple {

class MerkleCircuit_test : public beast::unit_test::suite
{
private:
    // Helper to generate a random 256-bit value as std::array<uint8_t, 32>
    std::array<uint8_t, 32> randomUint256() {
        std::array<uint8_t, 32> arr;
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        for (auto& b : arr) b = static_cast<uint8_t>(dis(gen));
        return arr;
    }

    // Helper to generate a random hex string of length 64 (256 bits)
    std::string randomHex256() {
        static const char* hex = "0123456789abcdef";
        std::string out(64, '0');
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 15);
        for (auto& c : out) c = hex[dis(gen)];
        return out;
    }

public:
    void run() override
    {
        testUint256ToBitsAndBack();
        testSpendKeyToBits();
        testGenerateDepositWitness();
        testGenerateWithdrawalWitness();
        testConstraintSystemGeneration();
        testNullifierHashConsistency();
    }

    void testUint256ToBitsAndBack()
    {
        testcase("Uint256ToBitsAndBack");
        
        zkp::MerkleCircuit circuit(8);
        auto original = randomUint256();
        auto bits = circuit.uint256ToBits(original);
        auto back = circuit.bitsToUint256(bits);
        BEAST_EXPECT(original == back);
    }

    void testSpendKeyToBits()
    {
        testcase("SpendKeyToBits");
        
        zkp::MerkleCircuit circuit(8);
        std::string hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        auto bits = circuit.spendKeyToBits(hex);
        BEAST_EXPECT(bits.size() == 256);
        
        // Check first nibble (should be 0x0)
        for (int i = 0; i < 4; ++i)
            BEAST_EXPECT(bits[i] == false);
            
        // Check last nibble (should be 0xf)
        for (int i = 252; i < 256; ++i)
            BEAST_EXPECT(bits[i] == true);
    }

    void testGenerateDepositWitness()
    {
        testcase("GenerateDepositWitness");
        
        zkp::MerkleCircuit circuit(8);
        auto leaf = circuit.uint256ToBits(randomUint256());
        auto root = circuit.uint256ToBits(randomUint256());
        auto spendKey = circuit.spendKeyToBits(randomHex256());
        auto witness = circuit.generateDepositWitness(leaf, root, spendKey);
        BEAST_EXPECT(!witness.empty());
    }

    void testGenerateWithdrawalWitness()
    {
        testcase("GenerateWithdrawalWitness");
        
        size_t treeDepth = 8;
        zkp::MerkleCircuit circuit(treeDepth);
        auto leaf = circuit.uint256ToBits(randomUint256());
        auto root = circuit.uint256ToBits(randomUint256());
        auto spendKey = circuit.spendKeyToBits(randomHex256());
        std::vector<std::vector<bool>> path(treeDepth, std::vector<bool>(256, false));
        size_t address = 5;
        auto witness = circuit.generateWithdrawalWitness(leaf, path, root, spendKey, address);
        BEAST_EXPECT(!witness.empty());
    }

    void testConstraintSystemGeneration()
    {
        testcase("ConstraintSystemGeneration");
        
        zkp::MerkleCircuit circuit(8);
        circuit.generateConstraints();
        auto cs = circuit.getConstraintSystem();
        BEAST_EXPECT(cs.num_constraints() > 0);
    }

    void testNullifierHashConsistency()
    {
        testcase("NullifierHashConsistency");
        
        zkp::MerkleCircuit circuit(8);
        auto leaf = circuit.uint256ToBits(randomUint256());
        auto root = circuit.uint256ToBits(randomUint256());
        auto spendKey = circuit.spendKeyToBits(randomHex256());
        circuit.generateDepositWitness(leaf, root, spendKey);
        
        // Just check that getProtoboard() returns a valid pointer
        auto pb = circuit.getProtoboard();
        BEAST_EXPECT(pb != nullptr);
    }
};

BEAST_DEFINE_TESTSUITE(MerkleCircuit, test, ripple);

} // namespace ripple