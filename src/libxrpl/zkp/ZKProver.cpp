#include "ZKProver.h"
#include "circuits/MerkleCircuit.h"
#include "IncrementalMerkleTree.h"
#include "Note.h"
#include <fstream>
#include <iostream>
#include <functional>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <sstream>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>

namespace ripple {
namespace zkp {

class TreeManager {
private:
    static std::unique_ptr<IncrementalMerkleTree> commitment_tree_;
    static std::string tree_path_;
    
public:
    static void initialize(const std::string& dataPath = "/tmp/rippled_commitment_tree") {
        tree_path_ = dataPath;
        
        // Try to load existing tree
        std::ifstream file(tree_path_, std::ios::binary);
        if (file.good()) {
            std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                    std::istreambuf_iterator<char>());
            commitment_tree_ = std::make_unique<IncrementalMerkleTree>(
                IncrementalMerkleTree::deserialize(data));
            
            std::cout << "Loaded commitment tree with " << commitment_tree_->size() 
                      << " leaves" << std::endl;
        } else {
            commitment_tree_ = std::make_unique<IncrementalMerkleTree>(32);
            std::cout << "Created new commitment tree" << std::endl;
        }
    }
    
    static size_t addCommitment(const uint256& commitment) {
        if (!commitment_tree_) {
            initialize();
        }
        
        size_t position = commitment_tree_->append(commitment);
        
        // Periodically save tree state
        if (position % 100 == 0) {
            saveTree();
        }
        
        return position;
    }
    
    static uint256 getRoot() {
        if (!commitment_tree_) {
            initialize();
        }
        return commitment_tree_->root();
    }
    
    static std::vector<uint256> getAuthPath(size_t position) {
        if (!commitment_tree_) {
            initialize();
        }
        return commitment_tree_->authPath(position);
    }
    
    static void saveTree() {
        if (!commitment_tree_) return;
        
        auto data = commitment_tree_->serialize();
        std::ofstream file(tree_path_, std::ios::binary);
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        
        std::cout << "Saved commitment tree state" << std::endl;
    }
    
    static void optimizeTree() {
        if (!commitment_tree_) return;
        
        commitment_tree_->precomputeNodes(commitment_tree_->size());
        std::cout << "Optimized commitment tree" << std::endl;
    }
};

// Static member definitions
std::unique_ptr<IncrementalMerkleTree> TreeManager::commitment_tree_;
std::string TreeManager::tree_path_;

// Static members for ZkProver
bool ZkProver::isInitialized = false;
std::shared_ptr<libsnark::r1cs_gg_ppzksnark_proving_key<DefaultCurve>> ZkProver::provingKey;
std::shared_ptr<libsnark::r1cs_gg_ppzksnark_verification_key<DefaultCurve>> ZkProver::verificationKey;
std::shared_ptr<MerkleCircuit> ZkProver::unifiedCircuit;

void ZkProver::initialize() {
    if (!isInitialized) {
        libff::alt_bn128_pp::init_public_params();
        TreeManager::initialize();
        isInitialized = true;
        std::cout << "Initializing ZkProver with the circuit..." << std::endl;
        
        if (!loadKeys("/tmp/rippled_zkp_keys")) {
            generateKeys(true);
            saveKeys("/tmp/rippled_zkp_keys");
        }
    }
}

bool ZkProver::generateKeys(bool forceRegeneration) {
    std::cout << "Starting key generation..." << std::endl;
    
    if (!forceRegeneration && provingKey && verificationKey && unifiedCircuit) {
        std::cout << "keys already exist, skipping generation." << std::endl;
        return true;
    }
    
    try {
        std::cout << "Initializing curve parameters..." << std::endl;
        libff::alt_bn128_pp::init_public_params();
        
        std::cout << "Creating MerkleCircuit..." << std::endl;
        unifiedCircuit = std::make_shared<MerkleCircuit>(32);  // Standard depth
        
        std::cout << "Generating constraints..." << std::endl;
        unifiedCircuit->generateConstraints();
        
        std::cout << "Getting constraint system..." << std::endl;
        auto cs = unifiedCircuit->getConstraintSystem();
        std::cout << "Circuit has " << cs.num_constraints() << " constraints" << std::endl;
        
        std::cout << "Running key generator..." << std::endl;
        auto keypair = libsnark::r1cs_gg_ppzksnark_generator<DefaultCurve>(cs);
        
        provingKey = std::make_shared<libsnark::r1cs_gg_ppzksnark_proving_key<DefaultCurve>>(std::move(keypair.pk));
        verificationKey = std::make_shared<libsnark::r1cs_gg_ppzksnark_verification_key<DefaultCurve>>(std::move(keypair.vk));
        
        std::cout << "Keys generated successfully!" << std::endl;
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Error generating keys: " << e.what() << std::endl;
        return false;
    } catch (...) {
        std::cerr << "Unknown error generating keys" << std::endl;
        return false;
    }
}

bool ZkProver::saveKeys(const std::string& basePath) {
    try {
        // Save keys
        if (provingKey) {
            std::ofstream pk_file(basePath + "_pk", std::ios::binary);
            pk_file << *provingKey;
            std::cout << "Saved proving key" << std::endl;
        }
        
        if (verificationKey) {
            std::ofstream vk_file(basePath + "_vk", std::ios::binary);
            vk_file << *verificationKey;
            std::cout << "Saved verification key" << std::endl;
        }
        
        return true;
    } catch (std::exception& e) {
        std::cerr << "Error saving keys: " << e.what() << std::endl;
        return false;
    }
}

bool ZkProver::loadKeys(const std::string& basePath) {
    try {
        // Load keys
        std::ifstream pk_file(basePath + "_pk", std::ios::binary);
        std::ifstream vk_file(basePath + "_vk", std::ios::binary);
        
        if (pk_file.good() && vk_file.good()) {
            provingKey = std::make_shared<libsnark::r1cs_gg_ppzksnark_proving_key<DefaultCurve>>();
            verificationKey = std::make_shared<libsnark::r1cs_gg_ppzksnark_verification_key<DefaultCurve>>();
            
            pk_file >> *provingKey;
            vk_file >> *verificationKey;
            
            std::cout << "Loaded keys with " << provingKey->constraint_system.num_constraints() << " constraints" << std::endl;
            
            // Create circuit that matches the loaded keys
            std::cout << "Creating circuit to match loaded keys..." << std::endl;
            unifiedCircuit = std::make_shared<MerkleCircuit>(32);
            unifiedCircuit->generateConstraints();
            
            // Verify circuit matches the keys
            auto circuit_cs = unifiedCircuit->getConstraintSystem();
            auto key_cs = provingKey->constraint_system;
            
            if (circuit_cs.num_constraints() != key_cs.num_constraints()) {
                std::cerr << "ERROR: circuit constraint count (" << circuit_cs.num_constraints() 
                          << ") doesn't match key constraint count (" << key_cs.num_constraints() << ")" << std::endl;
                
                // Force key regeneration
                std::cout << "Regenerating keys due to mismatch..." << std::endl;
                return generateKeys(true);
            }
            
            return true;
        } else {
            std::cout << "No existing keys found" << std::endl;
            return false;
        }
        
    } catch (std::exception& e) {
        std::cerr << "Error loading keys: " << e.what() << std::endl;
        return false;
    }
}

ProofData ZkProver::createDepositProof(
    uint64_t amount, 
    const uint256& commitment, 
    const std::string& spendKey,
    const FieldT& value_randomness) 
{
    try {
        if (!provingKey || !unifiedCircuit) {
            std::cerr << "Proving key or circuit not available" << std::endl;
            return {};
        }
        
        // Add commitment to incremental tree
        size_t position = TreeManager::addCommitment(commitment);
        uint256 currentRoot = TreeManager::getRoot();
        
        std::cout << "=== DEPOSIT PROOF ===" << std::endl;
        std::cout << "Added commitment at position " << position 
                  << " with root " << currentRoot << std::endl;
        
        // Create Note structure
        Note note;
        note.value = amount;
        
        uint256 a_sk = {};
        auto spendKeyBits = MerkleCircuit::spendKeyToBits(spendKey);
        for (size_t i = 0; i < std::min(spendKeyBits.size(), size_t(256)); ++i) {
            if (spendKeyBits[i]) {
                size_t byteIndex = i / 8;
                size_t bitIndex = i % 8;
                if (byteIndex < 32) {
                    a_sk.begin()[byteIndex] |= (1 << bitIndex);
                }
            }
        }
        
        note.rho = a_sk;
        note.r = generateRandomUint256();
        note.a_pk = generateRandomUint256();
        
        uint256 actual_commitment = note.commitment();
        
        std::cout << "Note value: " << note.value << std::endl;
        std::cout << "Computed commitment: " << actual_commitment << std::endl;
        std::cout << "Expected commitment: " << commitment << std::endl;
        
        // Convert to bits for circuit
        std::vector<bool> commitmentBits = uint256ToBits(actual_commitment);
        std::vector<bool> rootBits = uint256ToBits(currentRoot);
        
        // Use value_randomness as vcm_r
        uint256 vcm_r = fieldElementToUint256(value_randomness);
        
        // Use circuit for deposit witness
        auto witness = unifiedCircuit->generateDepositWitness(
            note, a_sk, vcm_r, commitmentBits, rootBits);
        
        // Extract computed values from circuit
        FieldT public_anchor = unifiedCircuit->getAnchor();
        FieldT public_nullifier = unifiedCircuit->getNullifier();
        FieldT public_value_commitment = unifiedCircuit->getValueCommitment();
        
        // std::vector<FieldT> primary_input;
        // primary_input.push_back(public_anchor);
        // primary_input.push_back(public_nullifier);
        // primary_input.push_back(public_value_commitment);
        
        // Build constraint system and primary input
        libsnark::r1cs_constraint_system<FieldT> cs = unifiedCircuit->getConstraintSystem();
        libsnark::r1cs_primary_input<FieldT> primary_input = {public_anchor, public_nullifier, public_value_commitment};

        std::cout << "Generated anchor: " << public_anchor << std::endl;
        std::cout << "Generated nullifier: " << public_nullifier << std::endl;
        std::cout << "Generated value_commitment: " << public_value_commitment << std::endl;
        
        // Constraint Satisfaction Check 
        if (!cs.is_satisfied(primary_input, witness)) {
            std::cerr << "ERROR: Witness does not satisfy circuit constraints!" << std::endl;
            return {}; // Abort proof generation
        }

        // Generate proof using proving key
        auto proof = libsnark::r1cs_gg_ppzksnark_prover<DefaultCurve>(
            *provingKey, primary_input, witness);

        // Serialize proof
        std::stringstream ss;
        ss << proof;
        std::string proof_str = ss.str();
        
        return ProofData{
            std::vector<unsigned char>(proof_str.begin(), proof_str.end()),
            public_anchor,
            public_nullifier,
            public_value_commitment
        };
        
    } catch (std::exception& e) {
        std::cerr << "Error creating deposit proof: " << e.what() << std::endl;
        return {};
    }
}

ProofData ZkProver::createWithdrawalProof(
    uint64_t amount,
    const uint256& merkleRoot,
    const uint256& nullifier,
    const std::vector<uint256>& merklePath,
    size_t pathIndex,
    const std::string& spendKey,
    const FieldT& value_randomness
)
{
    try {
        if (!provingKey || !unifiedCircuit) {
            std::cerr << "Proving key or circuit not available" << std::endl;
            return {};
        }
        
        std::cout << "=== WITHDRAWAL PROOF ===" << std::endl;
        
        Note note;
        note.value = amount;
        
        // Convert spendKey to uint256
        uint256 a_sk = {};
        auto spendKeyBits = MerkleCircuit::spendKeyToBits(spendKey);
        for (size_t i = 0; i < std::min(spendKeyBits.size(), size_t(256)); ++i) {
            if (spendKeyBits[i]) {
                size_t byteIndex = i / 8;
                size_t bitIndex = i % 8;
                if (byteIndex < 32) {
                    a_sk.begin()[byteIndex] |= (1 << bitIndex);
                }
            }
        }
        
        // Generate deterministic note components
        note.rho = a_sk; // Use spend key as rho base
        note.r = generateRandomUint256();
        note.a_pk = generateRandomUint256();
        
        std::vector<bool> rootBits = uint256ToBits(merkleRoot);
        std::vector<bool> leafBits = uint256ToBits(note.commitment());
        
        // Convert Merkle path to bit vectors
        std::vector<std::vector<bool>> pathBits;
        for (const auto& pathNode : merklePath) {
            pathBits.push_back(uint256ToBits(pathNode));
        }
        
        // Ensure path has correct depth
        size_t treeDepth = unifiedCircuit->getTreeDepth();
        while (pathBits.size() < treeDepth) {
            pathBits.push_back(std::vector<bool>(256, false)); // Add dummy path elements
        }
        
        std::cout << "Tree depth: " << treeDepth << std::endl;
        std::cout << "Path index: " << pathIndex << std::endl;
        std::cout << "Path length: " << pathBits.size() << std::endl;
        std::cout << "Expected root: " << merkleRoot << std::endl;
        
        // Use value_randomness as vcm_r
        uint256 vcm_r = fieldElementToUint256(value_randomness);
        
        // Use circuit for withdrawal witness
        auto witness = unifiedCircuit->generateWithdrawalWitness(
            note,       // The complete note structure
            a_sk,       // Spend key as uint256
            vcm_r,      // Value commitment randomness
            leafBits,   // Note commitment as leaf
            pathBits,   // Authentication path
            rootBits,   // Expected root
            pathIndex   // Leaf position
        );
        
        FieldT public_anchor = unifiedCircuit->getAnchor();
        FieldT public_nullifier = unifiedCircuit->getNullifier();
        FieldT public_value_commitment = unifiedCircuit->getValueCommitment();
        
        std::cout << "Computed anchor: " << public_anchor << std::endl;
        std::cout << "Computed nullifier: " << public_nullifier << std::endl;
        std::cout << "Computed value_commitment: " << public_value_commitment << std::endl;

         // Build constraint system and primary input
        libsnark::r1cs_constraint_system<FieldT> cs = unifiedCircuit->getConstraintSystem();
        libsnark::r1cs_primary_input<FieldT> primary_input = {public_anchor, public_nullifier, public_value_commitment};
        
        // Constraint Satisfaction Check 
        if (!cs.is_satisfied(primary_input, witness)) {
            std::cerr << "ERROR: Witness does not satisfy circuit constraints!" << std::endl;
            return {}; // Abort proof generation
        }
        
        // std::vector<FieldT> primary_input;
        // primary_input.push_back(public_anchor);
        // primary_input.push_back(public_nullifier);
        // primary_input.push_back(public_value_commitment);
        
        // Generate proof using proving key
        auto proof = libsnark::r1cs_gg_ppzksnark_prover<DefaultCurve>(
            *provingKey, primary_input, witness);
        
        std::stringstream ss;
        ss << proof;
        std::string proof_str = ss.str();
        
        return ProofData{
            std::vector<unsigned char>(proof_str.begin(), proof_str.end()),
            public_anchor,
            public_nullifier,
            public_value_commitment
        };
        
    } catch (std::exception& e) {
        std::cerr << "Error creating withdrawal proof: " << e.what() << std::endl;
        return {};
    }
}

bool ZkProver::verifyDepositProof(
    const std::vector<unsigned char>& proofData,
    const FieldT& anchor,
    const FieldT& nullifier,
    const FieldT& value_commitment)
{
    if (!isInitialized || !verificationKey) {
        initialize();
    }
    
    try {
        if (proofData.empty()) {
            std::cerr << "Error verifying deposit proof: Empty proof data" << std::endl;
            return false;
        }        
        
        // Deserialize proof
        auto proof = deserializeProof(proofData);
        
        // Create primary input from provided public values
        libsnark::r1cs_primary_input<libff::Fr<DefaultCurve>> primary_input;
        primary_input.push_back(anchor);
        primary_input.push_back(nullifier);
        primary_input.push_back(value_commitment);

        std::cout << "=== DEPOSIT PROOF VERIFICATION ===" << std::endl;
        std::cout << "Anchor: " << anchor << std::endl;
        std::cout << "Nullifier: " << nullifier << std::endl;
        std::cout << "Value commitment: " << value_commitment << std::endl;
        std::cout << "Using verification key" << std::endl;
        
        // Verify using verification key
        bool verification_result = libsnark::r1cs_gg_ppzksnark_verifier_strong_IC<DefaultCurve>(
            *verificationKey, primary_input, proof);
        
        std::cout << "Verification result: " << (verification_result ? "PASS" : "FAIL") << std::endl;
        
        return verification_result;
            
    } catch (std::exception& e) {
        std::cerr << "Error verifying deposit proof: " << e.what() << std::endl;
        return false;
    }
}

bool ZkProver::verifyWithdrawalProof(
    const std::vector<unsigned char>& proofData,
    const FieldT& anchor,
    const FieldT& nullifier,
    const FieldT& value_commitment) 
{
    if (!isInitialized || !verificationKey) {
        initialize();
    }
    
    try {
        if (proofData.empty()) {
            std::cerr << "Error verifying withdrawal proof: Empty proof data" << std::endl;
            return false;
        }
        
        auto proof = deserializeProof(proofData);
        
        // Create primary input from provided public values
        libsnark::r1cs_primary_input<libff::Fr<DefaultCurve>> primary_input;
        primary_input.push_back(anchor);
        primary_input.push_back(nullifier);
        primary_input.push_back(value_commitment);
        
        std::cout << "=== WITHDRAWAL PROOF VERIFICATION ===" << std::endl;
        std::cout << "Using unified verification key" << std::endl;
        
        // Verify using verification key (same as deposits)
        bool verification_result = libsnark::r1cs_gg_ppzksnark_verifier_strong_IC<DefaultCurve>(
            *verificationKey, primary_input, proof);
            
        std::cout << "Verification result: " << (verification_result ? "PASS" : "FAIL") << std::endl;
        
        return verification_result;
            
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

// Helper function to convert FieldT to uint256
uint256 ZkProver::fieldElementToUint256(const FieldT& element) {
    auto bits = MerkleCircuit::fieldElementToBits(element);
    uint256 result;
    for (size_t i = 0; i < std::min(bits.size(), size_t(256)); ++i) {
        if (bits[i]) {
            size_t byteIndex = i / 8;
            size_t bitIndex = i % 8;
            if (byteIndex < 32) {
                result.begin()[byteIndex] |= (1 << bitIndex);
            }
        }
    }
    return result;
}

// Helper function to generate random uint256
uint256 ZkProver::generateRandomUint256() {
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

std::vector<unsigned char> ZkProver::serializeProof(
    const libsnark::r1cs_gg_ppzksnark_proof<DefaultCurve>& proof)
{
    std::ostringstream oss;
    oss << proof;  
    
    std::string str = oss.str();
    return std::vector<unsigned char>(str.begin(), str.end());
}

libsnark::r1cs_gg_ppzksnark_proof<DefaultCurve> ZkProver::deserializeProof(
    const std::vector<unsigned char>& proofData)
{
    std::string str(proofData.begin(), proofData.end());
    std::istringstream iss(str);
    
    libsnark::r1cs_gg_ppzksnark_proof<DefaultCurve> proof;
    iss >> proof;  
    
    return proof;
}

} // namespace zkp
} // namespace ripple