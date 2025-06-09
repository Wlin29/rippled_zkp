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
        libff::alt_bn128_pp::init_public_params();
        isInitialized = true;
        std::cout << "Initializing ZkProver..." << std::endl;
        if (!loadKeys("/tmp/rippled_zkp_keys")) {
            generateKeys(true);
            saveKeys("/tmp/rippled_zkp_keys");
        }
    }
}

bool ZkProver::generateDepositKeys(bool force) {
    std::cout << "Starting deposit key generation..." << std::endl;
    
    if (!force && depositProvingKey && depositVerificationKey) {
        std::cout << "Deposit keys already exist, skipping generation." << std::endl;
        return true;
    }
    
    try {
        std::cout << "Initializing curve parameters..." << std::endl;
        libff::alt_bn128_pp::init_public_params();
        
        std::cout << "Creating MerkleCircuit..." << std::endl;
        auto circuit = std::make_shared<MerkleCircuit>(2);
        
        std::cout << "Generating constraints..." << std::endl;
        circuit->generateConstraints();
        
        std::cout << "Getting constraint system..." << std::endl;
        auto cs = circuit->getConstraintSystem();
        
        std::cout << "Constraint system size: " << cs.num_constraints() << " constraints, " 
                  << cs.num_variables() << " variables" << std::endl;
        
        std::cout << "Running key generator..." << std::endl;
        auto keypair = libsnark::r1cs_gg_ppzksnark_generator<DefaultCurve>(cs);
        
        std::cout << "Storing keys..." << std::endl;
        depositProvingKey = std::make_shared<libsnark::r1cs_gg_ppzksnark_proving_key<DefaultCurve>>(keypair.pk);
        depositVerificationKey = std::make_shared<libsnark::r1cs_gg_ppzksnark_verification_key<DefaultCurve>>(keypair.vk);
        
        std::cout << "Deposit keys generated successfully!" << std::endl;
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Error generating deposit keys: " << e.what() << std::endl;
        return false;
    } catch (...) {
        std::cerr << "Unknown error generating deposit keys" << std::endl;
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

// UPDATED: Return ProofData instead of std::vector<unsigned char>
ProofData ZkProver::createDepositProof(
    uint64_t amount, 
    const uint256& commitment, 
    const std::string& spendKey) 
{
    try {
        if (!depositProvingKey) {
            std::cerr << "Deposit proving key not available" << std::endl;
            return {};  // Return empty ProofData
        }
        
        auto merkleCircuit = std::make_shared<MerkleCircuit>(2);
        merkleCircuit->generateConstraints();
        
        // Convert inputs to bits
        std::vector<bool> commitmentBits = uint256ToBits(commitment);
        std::vector<bool> spendKeyBits = MerkleCircuit::spendKeyToBits(spendKey);  // SECRET
        
        // For deposits, root = commitment
        std::vector<bool> rootBits = commitmentBits;
        
        auto witness = merkleCircuit->generateDepositWitness(
            amount,                           // uint64_t value
            FieldT::random_element(),         // FieldT value_randomness
            commitmentBits,                   // leaf
            rootBits,                         // root
            spendKeyBits                      // spend_key
        );
        
        // Extract PUBLIC values computed by the circuit
        FieldT public_anchor = merkleCircuit->getAnchor();
        FieldT public_nullifier = merkleCircuit->getNullifier();      // Derived from secret, but now public
        FieldT public_value_commitment = merkleCircuit->getValueCommitment();
        
        // Create primary input from PUBLIC values
        std::vector<FieldT> primary_input;
        primary_input.push_back(public_anchor);
        primary_input.push_back(public_nullifier);
        primary_input.push_back(public_value_commitment);
        
        // Generate proof
        auto proof = libsnark::r1cs_gg_ppzksnark_prover<DefaultCurve>(
            *depositProvingKey, primary_input, witness);
        
        // Serialize proof
        std::stringstream ss;
        ss << proof;
        std::string proof_str = ss.str();
        
        // Return proof + public inputs (NO SECRETS!)
        return ProofData{
            std::vector<unsigned char>(proof_str.begin(), proof_str.end()),
            public_anchor,
            public_nullifier,
            public_value_commitment
        };
        
    } catch (std::exception& e) {
        std::cerr << "Error creating deposit proof: " << e.what() << std::endl;
        return {};  // Return empty ProofData
    }
}

// UPDATED: Return ProofData instead of std::vector<unsigned char>
ProofData ZkProver::createWithdrawalProof(
    uint64_t amount,
    const uint256& merkleRoot,
    const uint256& nullifier,
    const std::vector<uint256>& merklePath,
    size_t pathIndex,
    const std::string& spendKey)
{
    try {
        if (!withdrawalProvingKey) {
            std::cerr << "Withdrawal proving key not available" << std::endl;
            return {};  // Return empty ProofData
        }
        
        auto merkleCircuit = std::make_shared<MerkleCircuit>(2);
        merkleCircuit->generateConstraints();
        
        // Convert inputs to bits
        std::vector<bool> nullifierBits = uint256ToBits(nullifier);
        std::vector<bool> rootBits = uint256ToBits(merkleRoot);
        std::vector<bool> spendKeyBits = MerkleCircuit::spendKeyToBits(spendKey);  // SECRET
        
        // Convert merkle path to bits
        std::vector<std::vector<bool>> pathBits;
        for (const auto& pathNode : merklePath) {
            pathBits.push_back(uint256ToBits(pathNode));
        }
        
        auto witness = merkleCircuit->generateWithdrawalWitness(
            amount,                           // uint64_t value
            FieldT::random_element(),         // FieldT value_randomness
            nullifierBits,                    // leaf
            pathBits,                         // path
            rootBits,                         // root
            spendKeyBits,                     // spend_key
            pathIndex                         // address
        );
        
        // Extract PUBLIC values computed by the circuit
        FieldT public_anchor = merkleCircuit->getAnchor();
        FieldT public_nullifier = merkleCircuit->getNullifier();      // Derived from secret, but now public
        FieldT public_value_commitment = merkleCircuit->getValueCommitment();
        
        // Create primary input from PUBLIC values
        std::vector<FieldT> primary_input;
        primary_input.push_back(public_anchor);
        primary_input.push_back(public_nullifier);
        primary_input.push_back(public_value_commitment);
        
        // Generate proof
        auto proof = libsnark::r1cs_gg_ppzksnark_prover<DefaultCurve>(
            *withdrawalProvingKey, primary_input, witness);
        
        // Serialize proof
        std::stringstream ss;
        ss << proof;
        std::string proof_str = ss.str();
        
        // Return proof + public inputs (NO SECRETS!)
        return ProofData{
            std::vector<unsigned char>(proof_str.begin(), proof_str.end()),
            public_anchor,
            public_nullifier,
            public_value_commitment
        };
        
    } catch (std::exception& e) {
        std::cerr << "Error creating withdrawal proof: " << e.what() << std::endl;
        return {};  // Return empty ProofData
    }
}

// UPDATED: Verification uses ONLY public data (no spendKey!)
bool ZkProver::verifyDepositProof(
    const std::vector<unsigned char>& proofData,
    const FieldT& anchor,
    const FieldT& nullifier,
    const FieldT& value_commitment)  // NO spendKey parameter!
{
    if (!isInitialized || !depositVerificationKey) {
        initialize();
    }
    
    try {
        if (proofData.empty()) {
            std::cerr << "Error verifying deposit proof: Empty proof data" << std::endl;
            return false;
        }
        
        auto proof = deserializeProof(proofData);
        
        // Create primary input from PROVIDED public values (no secret computation!)
        libsnark::r1cs_primary_input<libff::Fr<DefaultCurve>> primary_input;
        primary_input.push_back(anchor);
        primary_input.push_back(nullifier);
        primary_input.push_back(value_commitment);
        
        // Verify using only public data
        return libsnark::r1cs_gg_ppzksnark_verifier_strong_IC<DefaultCurve>(
            *depositVerificationKey, primary_input, proof);
            
    } catch (std::exception& e) {
        std::cerr << "Error verifying deposit proof: " << e.what() << std::endl;
        return false;
    }
}

// UPDATED: Verification uses ONLY public data (no spendKey!)
bool ZkProver::verifyWithdrawalProof(
    const std::vector<unsigned char>& proofData,
    const FieldT& anchor,
    const FieldT& nullifier,
    const FieldT& value_commitment)  // NO spendKey parameter!
{
    if (!isInitialized || !withdrawalVerificationKey) {
        initialize();
    }
    
    try {
        if (proofData.empty()) {
            std::cerr << "Error verifying withdrawal proof: Empty proof data" << std::endl;
            return false;
        }
        
        auto proof = deserializeProof(proofData);
        
        // Create primary input from PROVIDED public values (no secret computation!)
        libsnark::r1cs_primary_input<libff::Fr<DefaultCurve>> primary_input;
        primary_input.push_back(anchor);
        primary_input.push_back(nullifier);
        primary_input.push_back(value_commitment);
        
        // Verify using only public data
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