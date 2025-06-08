#include "ZKProver.h"
#include "circuits/MerkleCircuit.h"
#include <fstream>
#include <iostream>
#include <functional>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <sstream>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

namespace ripple {
namespace zkp {

// Static members
bool ZkProver::isInitialized = false;
std::shared_ptr<libsnark::r1cs_gg_ppzksnark_proving_key<DefaultCurve>> ZkProver::depositProvingKey;
std::shared_ptr<libsnark::r1cs_gg_ppzksnark_verification_key<DefaultCurve>> ZkProver::depositVerificationKey;
std::shared_ptr<libsnark::r1cs_gg_ppzksnark_proving_key<DefaultCurve>> ZkProver::withdrawalProvingKey;
std::shared_ptr<libsnark::r1cs_gg_ppzksnark_verification_key<DefaultCurve>> ZkProver::withdrawalVerificationKey;

void ZkProver::initialize() {
    if (!isInitialized) {
        initCurveParameters();
        isInitialized = true;
        std::cout << "Initializing ZkProver..." << std::endl;
        if (!loadKeys("/tmp/rippled_zkp_keys")) {
            generateKeys(true);
            saveKeys("/tmp/rippled_zkp_keys");
        }
    }
}

bool ZkProver::generateDepositKeys(bool forceRegeneration) {
    if (depositProvingKey && depositVerificationKey && !forceRegeneration) {
        std::cout << "Deposit keys already generated." << std::endl;
        return true;
    }
    
    try {
        std::cout << "Generating deposit keys..." << std::endl;
        auto merkleCircuit = std::make_shared<MerkleCircuit>(2); // Depth 2 for testing
        std::cout << "Generating constraints..." << std::endl;
        merkleCircuit->generateConstraints();
        std::cout << "Getting constraint system..." << std::endl;
        auto cs = merkleCircuit->getConstraintSystem();
        std::cout << "Generating keypair..." << std::endl;
        auto keypair = libsnark::r1cs_gg_ppzksnark_generator<DefaultCurve>(cs);
        depositProvingKey = std::make_shared<libsnark::r1cs_gg_ppzksnark_proving_key<DefaultCurve>>(keypair.pk);
        depositVerificationKey = std::make_shared<libsnark::r1cs_gg_ppzksnark_verification_key<DefaultCurve>>(keypair.vk);
        return true;
    } catch (std::exception& e) {
        std::cerr << "Error generating deposit keys: " << e.what() << std::endl;
        return false;
    }
}

bool ZkProver::generateWithdrawalKeys(bool forceRegeneration) {
    if (withdrawalProvingKey && withdrawalVerificationKey && !forceRegeneration)
        return true;
    try {
        auto merkleCircuit = std::make_shared<MerkleCircuit>(2);
        merkleCircuit->generateConstraints();
        auto cs = merkleCircuit->getConstraintSystem();
        auto keypair = libsnark::r1cs_gg_ppzksnark_generator<DefaultCurve>(cs);
        withdrawalProvingKey = std::make_shared<libsnark::r1cs_gg_ppzksnark_proving_key<DefaultCurve>>(keypair.pk);
        withdrawalVerificationKey = std::make_shared<libsnark::r1cs_gg_ppzksnark_verification_key<DefaultCurve>>(keypair.vk);
        return true;
    } catch (std::exception& e) {
        std::cerr << "Error generating withdrawal keys: " << e.what() << std::endl;
        return false;
    }
}

bool ZkProver::generateKeys(bool forceRegeneration) {
    return generateDepositKeys(forceRegeneration) && generateWithdrawalKeys(forceRegeneration);
}

bool ZkProver::saveKeys(const std::string& basePath) {
    try {
        // Save deposit keys
        if (depositProvingKey) {
            std::ofstream deposit_pk_file(basePath + "_deposit_pk", std::ios::binary);
            deposit_pk_file << *depositProvingKey;
        }
        
        if (depositVerificationKey) {
            std::ofstream deposit_vk_file(basePath + "_deposit_vk", std::ios::binary);
            deposit_vk_file << *depositVerificationKey;
        }
        
        // Save withdrawal keys
        if (withdrawalProvingKey) {
            std::ofstream withdrawal_pk_file(basePath + "_withdrawal_pk", std::ios::binary);
            withdrawal_pk_file << *withdrawalProvingKey;
        }
        
        if (withdrawalVerificationKey) {
            std::ofstream withdrawal_vk_file(basePath + "_withdrawal_vk", std::ios::binary);
            withdrawal_vk_file << *withdrawalVerificationKey;
        }
        
        return true;
    } catch (std::exception& e) {
        std::cerr << "Error saving keys: " << e.what() << std::endl;
        return false;
    }
}

bool ZkProver::loadKeys(const std::string& basePath) {
    try {
        // Try to load deposit keys
        std::ifstream deposit_pk_file(basePath + "_deposit_pk", std::ios::binary);
        std::ifstream deposit_vk_file(basePath + "_deposit_vk", std::ios::binary);
        
        if (deposit_pk_file.good() && deposit_vk_file.good()) {
            depositProvingKey = std::make_shared<libsnark::r1cs_gg_ppzksnark_proving_key<DefaultCurve>>();
            depositVerificationKey = std::make_shared<libsnark::r1cs_gg_ppzksnark_verification_key<DefaultCurve>>();
            
            deposit_pk_file >> *depositProvingKey;
            deposit_vk_file >> *depositVerificationKey;
        } else {
            return false;
        }
        
        // Try to load withdrawal keys
        std::ifstream withdrawal_pk_file(basePath + "_withdrawal_pk", std::ios::binary);
        std::ifstream withdrawal_vk_file(basePath + "_withdrawal_vk", std::ios::binary);
        
        if (withdrawal_pk_file.good() && withdrawal_vk_file.good()) {
            withdrawalProvingKey = std::make_shared<libsnark::r1cs_gg_ppzksnark_proving_key<DefaultCurve>>();
            withdrawalVerificationKey = std::make_shared<libsnark::r1cs_gg_ppzksnark_verification_key<DefaultCurve>>();
            
            withdrawal_pk_file >> *withdrawalProvingKey;
            withdrawal_vk_file >> *withdrawalVerificationKey;
        } else {
            return false;
        }
        
        return true;
    } catch (std::exception& e) {
        std::cerr << "Error loading keys: " << e.what() << std::endl;
        return false;
    }
}

std::vector<unsigned char> ZkProver::createDepositProof(
    uint64_t publicAmount,
    const uint256& commitment,
    const std::string& spendKey)
{
    if (!isInitialized || !depositProvingKey) initialize();
    try {
        auto merkleCircuit = std::make_shared<MerkleCircuit>(2);
        merkleCircuit->generateConstraints();
        std::vector<bool> commitmentBits = uint256ToBits(commitment);
        std::vector<bool> rootBits(256, false);
        std::vector<bool> spendKeyBits = MerkleCircuit::spendKeyToBits(spendKey);
        auto witness = merkleCircuit->generateDepositWitness(commitmentBits, rootBits, spendKeyBits);
        auto proof = libsnark::r1cs_gg_ppzksnark_prover<DefaultCurve>(
            *depositProvingKey,
            merkleCircuit->getPrimaryInput(),
            merkleCircuit->getAuxiliaryInput());
        return serializeProof(proof);
    } catch (std::exception& e) {
        std::cerr << "Error creating deposit proof: " << e.what() << std::endl;
        return {};
    }
}

std::vector<unsigned char> ZkProver::createWithdrawalProof(
    uint64_t publicAmount,
    const uint256& nullifier,
    const uint256& merkleRoot,
    const std::vector<uint256>& merklePath,
    size_t pathIndex,
    const std::string& spendKey)
{
    if (!isInitialized || !withdrawalProvingKey) {
        initialize();
    }
    
    try {
        // Create a circuit for the withdrawal
        auto merkleCircuit = std::make_shared<MerkleCircuit>(2);
        merkleCircuit->generateConstraints();
        
        // Convert inputs to bits
        std::vector<bool> nullifierBits = uint256ToBits(nullifier);
        std::vector<bool> rootBits = uint256ToBits(merkleRoot);
        std::vector<bool> spendKeyBits = MerkleCircuit::spendKeyToBits(spendKey);
        
        // Convert merkle path to bits
        std::vector<std::vector<bool>> pathBits;
        for (const auto& node : merklePath) {
            pathBits.push_back(uint256ToBits(node));
        }
        
        // Generate the witness (ADD SPEND KEY)
        auto witness = merkleCircuit->generateWithdrawalWitness(
            nullifierBits, pathBits, rootBits, spendKeyBits, pathIndex);
        
        // Generate the proof
        auto proof = libsnark::r1cs_gg_ppzksnark_prover<DefaultCurve>(
            *withdrawalProvingKey, 
            merkleCircuit->getPrimaryInput(), 
            merkleCircuit->getAuxiliaryInput());
        
        return serializeProof(proof);
    } catch (std::exception& e) {
        std::cerr << "Error creating withdrawal proof: " << e.what() << std::endl;
        return {};
    }
}

bool ZkProver::verifyDepositProof(
    const std::vector<unsigned char>& proofData,
    uint64_t publicAmount,
    const uint256& commitment)
{
    if (!isInitialized || !depositVerificationKey) initialize();
    try {
        auto proof = deserializeProof(proofData);
        libsnark::r1cs_gg_ppzksnark_primary_input<DefaultCurve> primary_input;
        primary_input.push_back(FieldT(publicAmount));
        std::vector<bool> commitmentBits = uint256ToBits(commitment);
        for (bool bit : commitmentBits)
            primary_input.push_back(bit ? FieldT::one() : FieldT::zero());
        return libsnark::r1cs_gg_ppzksnark_verifier_strong_IC<DefaultCurve>(
            *depositVerificationKey, primary_input, proof);
    } catch (std::exception& e) {
        std::cerr << "Error verifying deposit proof: " << e.what() << std::endl;
        return false;
    }
}

bool ZkProver::verifyWithdrawalProof(
    const std::vector<unsigned char>& proofData,
    uint64_t publicAmount,
    const uint256& merkleRoot,
    const uint256& nullifier)
{
    if (!isInitialized || !withdrawalVerificationKey) {
        initialize();
    }
    
    try {
        // Deserialize the proof
        auto proof = deserializeProof(proofData);
        
        // Create a primary input vector with publicAmount, merkleRoot, and nullifier
        libsnark::r1cs_primary_input<FieldT> primary_input;
        
        // Add amount
        primary_input.push_back(FieldT(publicAmount));
        
        // Add merkle root bits
        std::vector<bool> rootBits = uint256ToBits(merkleRoot);
        for (bool bit : rootBits) {
            primary_input.push_back(bit ? FieldT::one() : FieldT::zero());
        }
        
        // Add nullifier bits (now included in the primary input)
        std::vector<bool> nullifierBits = uint256ToBits(nullifier);
        for (bool bit : nullifierBits) {
            primary_input.push_back(bit ? FieldT::one() : FieldT::zero());
        }
        
        // Verify the proof
        return libsnark::r1cs_gg_ppzksnark_verifier_strong_IC<DefaultCurve>(
            *withdrawalVerificationKey, primary_input, proof);
    } catch (std::exception& e) {
        std::cerr << "Error verifying withdrawal proof: " << e.what() << std::endl;
        return false;
    }
}

std::vector<bool> ZkProver::uint256ToBits(const uint256& input) {
    std::vector<bool> bits(256);
    
    for (size_t i = 0; i < 256; i++) {
        // Get the byte index (0 to 31)
        size_t byteIndex = i / 8;
        // Get the bit index within the byte (0 to 7)
        size_t bitIndex = i % 8;
        // Extract the bit
        bits[i] = ((input.begin()[byteIndex] >> bitIndex) & 1) != 0;
    }
    
    return bits;
}

uint256 ZkProver::bitsToUint256(const std::vector<bool>& bits) {
    uint256 result;
    
    for (size_t i = 0; i < std::min(bits.size(), (size_t)256); i++) {
        // Get the byte index (0 to 31)
        size_t byteIndex = i / 8;
        // Get the bit index within the byte (0 to 7)
        size_t bitIndex = i % 8;
        // Set the bit
        if (bits[i]) {
            result.begin()[byteIndex] |= (1 << bitIndex);
        }
    }
    
    return result;
}

std::vector<unsigned char> ZkProver::serializeProof(
    const libsnark::r1cs_gg_ppzksnark_proof<DefaultCurve>& proof)
{
    std::ostringstream oss(std::ios::binary);
    oss << proof.g_A << proof.g_B << proof.g_C;
    std::string str = oss.str();
    return std::vector<unsigned char>(str.begin(), str.end());
}

libsnark::r1cs_gg_ppzksnark_proof<DefaultCurve> ZkProver::deserializeProof(
    const std::vector<unsigned char>& proofData)
{
    if (proofData.empty()) throw std::invalid_argument("Empty proof data");
    std::string str(proofData.begin(), proofData.end());
    std::istringstream iss(str, std::ios::binary);
    libff::G1<DefaultCurve> g_A, g_C;
    libff::G2<DefaultCurve> g_B;
    iss >> g_A >> g_B >> g_C;
    return libsnark::r1cs_gg_ppzksnark_proof<DefaultCurve>(
        std::move(g_A), std::move(g_B), std::move(g_C));
}

} // namespace zkp
} // namespace ripple