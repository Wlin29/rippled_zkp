#include "ZKProver.h"
#include "circuits/MerkleCircuit.h"
#include <fstream>
#include <iostream>

namespace ripple {
namespace zkp {

// Initialize static members
bool ZkProver::isInitialized = false;
std::shared_ptr<libsnark::r1cs_ppzksnark_proving_key<DefaultCurve>> ZkProver::depositProvingKey;
std::shared_ptr<libsnark::r1cs_ppzksnark_verification_key<DefaultCurve>> ZkProver::depositVerificationKey;
std::shared_ptr<libsnark::r1cs_ppzksnark_proving_key<DefaultCurve>> ZkProver::withdrawalProvingKey;
std::shared_ptr<libsnark::r1cs_ppzksnark_verification_key<DefaultCurve>> ZkProver::withdrawalVerificationKey;

// Legacy variables
std::shared_ptr<libsnark::r1cs_ppzksnark_proving_key<DefaultCurve>> ZkProver::provingKey;
std::shared_ptr<libsnark::r1cs_ppzksnark_verification_key<DefaultCurve>> ZkProver::verificationKey;

void ZkProver::initialize() {
    if (!isInitialized) {
        // Initialize the curve parameters
        initCurveParameters();
        isInitialized = true;
        
        // Try to load keys or generate them if they don't exist
        if (!loadKeys("/tmp/rippled_zkp_keys")) {
            generateKeys(true);
            saveKeys("/tmp/rippled_zkp_keys");
        }
    }
}

bool ZkProver::generateDepositKeys(bool forceRegeneration) {
    if (depositProvingKey && depositVerificationKey && !forceRegeneration) {
        return true; // Keys already generated
    }
    
    try {
        // Setup the deposit circuit
        auto merkleCircuit = std::make_shared<MerkleCircuit>(20); // Use a tree depth of 20 for deposits
        merkleCircuit->generateConstraints();
        
        auto cs = merkleCircuit->getConstraintSystem();
        
        // Generate the proving and verification keys
        auto keypair = libsnark::r1cs_ppzksnark_generator<DefaultCurve>(cs);
        depositProvingKey = std::make_shared<libsnark::r1cs_ppzksnark_proving_key<DefaultCurve>>(keypair.pk);
        depositVerificationKey = std::make_shared<libsnark::r1cs_ppzksnark_verification_key<DefaultCurve>>(keypair.vk);
        
        // For legacy support
        provingKey = depositProvingKey;
        verificationKey = depositVerificationKey;
        
        return true;
    } catch (std::exception& e) {
        std::cerr << "Error generating deposit keys: " << e.what() << std::endl;
        return false;
    }
}

bool ZkProver::generateWithdrawalKeys(bool forceRegeneration) {
    if (withdrawalProvingKey && withdrawalVerificationKey && !forceRegeneration) {
        return true; // Keys already generated
    }
    
    try {
        // Setup the withdrawal circuit with a larger tree depth
        auto merkleCircuit = std::make_shared<MerkleCircuit>(20); // Use a tree depth of 20 for withdrawals
        merkleCircuit->generateConstraints();
        
        auto cs = merkleCircuit->getConstraintSystem();
        
        // Generate the proving and verification keys
        auto keypair = libsnark::r1cs_ppzksnark_generator<DefaultCurve>(cs);
        withdrawalProvingKey = std::make_shared<libsnark::r1cs_ppzksnark_proving_key<DefaultCurve>>(keypair.pk);
        withdrawalVerificationKey = std::make_shared<libsnark::r1cs_ppzksnark_verification_key<DefaultCurve>>(keypair.vk);
        
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
            depositProvingKey = std::make_shared<libsnark::r1cs_ppzksnark_proving_key<DefaultCurve>>();
            depositVerificationKey = std::make_shared<libsnark::r1cs_ppzksnark_verification_key<DefaultCurve>>();
            
            deposit_pk_file >> *depositProvingKey;
            deposit_vk_file >> *depositVerificationKey;
            
            // For legacy support
            provingKey = depositProvingKey;
            verificationKey = depositVerificationKey;
        } else {
            return false;
        }
        
        // Try to load withdrawal keys
        std::ifstream withdrawal_pk_file(basePath + "_withdrawal_pk", std::ios::binary);
        std::ifstream withdrawal_vk_file(basePath + "_withdrawal_vk", std::ios::binary);
        
        if (withdrawal_pk_file.good() && withdrawal_vk_file.good()) {
            withdrawalProvingKey = std::make_shared<libsnark::r1cs_ppzksnark_proving_key<DefaultCurve>>();
            withdrawalVerificationKey = std::make_shared<libsnark::r1cs_ppzksnark_verification_key<DefaultCurve>>();
            
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
    if (!isInitialized || !depositProvingKey) {
        initialize();
    }
    
    try {
        // Create a circuit for the deposit
        auto merkleCircuit = std::make_shared<MerkleCircuit>(20);
        merkleCircuit->generateConstraints();
        
        // Convert inputs to bits
        std::vector<bool> commitmentBits = uint256ToBits(commitment);
        std::vector<bool> rootBits(256, false); // dummy root for deposit
        std::vector<bool> spendKeyBits = MerkleCircuit::spendKeyToBits(spendKey); // Add this
        
        // Generate the witness (ADD SPEND KEY)
        auto witness = merkleCircuit->generateDepositWitness(
            commitmentBits, rootBits, spendKeyBits); // Now 3 arguments
        
        // Generate the proof
        auto proof = libsnark::r1cs_ppzksnark_prover<DefaultCurve>(
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
        auto merkleCircuit = std::make_shared<MerkleCircuit>(20);
        merkleCircuit->generateConstraints();
        
        // Convert inputs to bits
        std::vector<bool> nullifierBits = uint256ToBits(nullifier);
        std::vector<bool> rootBits = uint256ToBits(merkleRoot);
        std::vector<bool> spendKeyBits = MerkleCircuit::spendKeyToBits(spendKey); // Add this
        
        // Convert merkle path to bits
        std::vector<std::vector<bool>> pathBits;
        for (const auto& node : merklePath) {
            pathBits.push_back(uint256ToBits(node));
        }
        
        // Generate the witness (ADD SPEND KEY)
        auto witness = merkleCircuit->generateWithdrawalWitness(
            nullifierBits, pathBits, rootBits, spendKeyBits, pathIndex); // Now 5 arguments
        
        // Generate the proof
        auto proof = libsnark::r1cs_ppzksnark_prover<DefaultCurve>(
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
    if (!isInitialized || !depositVerificationKey) {
        initialize();
    }
    
    try {
        // Deserialize the proof
        auto proof = deserializeProof(proofData);
        
        // Create a primary input vector with publicAmount and commitment
        libsnark::r1cs_primary_input<FieldT> primary_input;
        
        // Add amount
        primary_input.push_back(FieldT(publicAmount));
        
        // Add commitment bits
        std::vector<bool> commitmentBits = uint256ToBits(commitment);
        for (bool bit : commitmentBits) {
            primary_input.push_back(bit ? FieldT::one() : FieldT::zero());
        }
        
        // Verify the proof
        return libsnark::r1cs_ppzksnark_verifier_strong_IC<DefaultCurve>(
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
        
        // Add nullifier bits (not part of primary input in this example)
        // In a real implementation, the nullifier verification would be part of the circuit
        
        // Verify the proof
        return libsnark::r1cs_ppzksnark_verifier_strong_IC<DefaultCurve>(
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
    const libsnark::r1cs_ppzksnark_proof<DefaultCurve>& proof)
{
    // This is a simplified serialization that doesn't handle all edge cases
    // A real implementation would need more robust serialization
    std::stringstream ss;
    ss << proof;
    
    std::string str = ss.str();
    return std::vector<unsigned char>(str.begin(), str.end());
}

libsnark::r1cs_ppzksnark_proof<DefaultCurve> ZkProver::deserializeProof(
    const std::vector<unsigned char>& proofData)
{
    // This is a simplified deserialization that doesn't handle all edge cases
    // A real implementation would need more robust deserialization
    std::string str(proofData.begin(), proofData.end());
    std::stringstream ss(str);
    
    libsnark::r1cs_ppzksnark_proof<DefaultCurve> proof;
    ss >> proof;
    
    return proof;
}

} // namespace zkp
} // namespace ripple