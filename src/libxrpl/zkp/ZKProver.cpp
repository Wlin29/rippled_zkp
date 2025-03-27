#include "ZKProver.h"
#include <fstream>
#include <stdexcept>
#include <sstream>

#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>
// #include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
// #include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
// #include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>

using namespace libsnark;

namespace ripple {
namespace zkp {

using FieldT = typename DefaultCurve::Fp_type;

// Static member initialization
std::shared_ptr<r1cs_ppzksnark_proving_key<DefaultCurve>> ZkProver::provingKey = nullptr;
std::shared_ptr<r1cs_ppzksnark_verification_key<DefaultCurve>> ZkProver::verificationKey = nullptr;
bool ZkProver::isInitialized = false;

void ZkProver::initialize() {
    if (!isInitialized) {
        // Initialize the curve parameters
        DefaultCurve::init_public_params();
        isInitialized = true;
    }
}

bool ZkProver::generateKeys(bool forceRegeneration) {
    if (!isInitialized) {
        initialize();
    }
    
    if (provingKey && verificationKey && !forceRegeneration) {
        // Keys already generated
        return true;
    }
    
    try {
        // Create constraint system for deposit circuit
        protoboard<FieldT> pb;
        
        // Define variables for the deposit circuit
        pb_variable<FieldT> public_amount;
        pb_variable<FieldT> value;
        pb_variable_array<FieldT> commitment_bits;
        
        // Allocate variables
        public_amount.allocate(pb, "public_amount");
        value.allocate(pb, "value");
        commitment_bits.allocate(pb, 256, "commitment_bits");
        
        // Make public_amount and commitment public inputs
        pb.set_input_sizes(1 + 256); // 1 for amount + 256 bits for commitment
        
        // Set up constraints for the deposit circuit
        
        /*
            1. Constraint: commitment = Hash(value || spend_key || recipient)
        */
        // Libsnark seems to have been currupted or mismatched, digest_variable should take a string as 
        // the third argument, but it takes a pb_variable array.
        
        // digest_variable<FieldT> commitment(pb, 256, commitment_bits);
        //         size_t n1 = spend_key_bits.size();
        //         size_t n2 = recipient_bits.size();
        //         pb_variable_array<FieldT> preimage;
        //         preimage.allocate(pb, n1 + n2, "preimage");

        //         // Copy spend_key_bits into the first half of preimage
        //         for (size_t i = 0; i < n1; i++) {
        //             preimage[i] = spend_key_bits[i];
        //         }

        //         // Copy recipient_bits into the second half of preimage
        //         for (size_t j = 0; j < n2; j++) {
        //             preimage[n1 + j] = recipient_bits[j];
        // }
                
        //         // Use SHA256 for the commitment
        //         pb_linear_combination_array<FieldT> value_bits;
        //         value_bits.push_back(pb_linear_combination<FieldT>(value));
                
        //         sha256_compression_function_gadget<FieldT> commitment_hasher(
        //             pb, value_bits, preimage, commitment, "commitment_hasher");
        
        /* 
            2. Constraint: public_amount == value 
        */
        pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                public_amount,
                linear_combination<FieldT>(FieldT(1)),
                pb_linear_combination<FieldT>(value)
            ),
            "public_amount_equals_value"
        );
        
        // Generate the keys
        r1cs_ppzksnark_keypair<DefaultCurve> keypair =
            r1cs_ppzksnark_generator<DefaultCurve>(pb.get_constraint_system());
        
        provingKey = std::make_shared<r1cs_ppzksnark_proving_key<DefaultCurve>>(keypair.pk);
        verificationKey = std::make_shared<r1cs_ppzksnark_verification_key<DefaultCurve>>(keypair.vk);
        
        return true;
    }
    catch (std::exception& e) {
        return false;
    }
}

bool ZkProver::saveKeys(const std::string& provingKeyPath, const std::string& verificationKeyPath) {
    if (!provingKey || !verificationKey) {
        return false;
    }
    
    try {
        std::ofstream provingOut(provingKeyPath, std::ios::binary);
        std::ofstream verificationOut(verificationKeyPath, std::ios::binary);
        
        // Use the ofstream objects directly.
        provingOut << *provingKey;
        verificationOut << *verificationKey;
        
        return true;
    }
    catch (std::exception& e) {
        return false;
    }
}

bool ZkProver::loadKeys(const std::string& provingKeyPath, const std::string& verificationKeyPath) {
    if (!isInitialized) {
        initialize();
    }
    
    try {
        std::ifstream provingIn(provingKeyPath, std::ios::binary);
        std::ifstream verificationIn(verificationKeyPath, std::ios::binary);
        
        if (!provingIn || !verificationIn) {
            return false;
        }
        
        // Deserialize the keys (simplified; proper handling of curve elements is recommended)
        provingKey = std::make_shared<r1cs_ppzksnark_proving_key<DefaultCurve>>();
        verificationKey = std::make_shared<r1cs_ppzksnark_verification_key<DefaultCurve>>();
        
        provingIn >> *provingKey;
        verificationIn >> *verificationKey;
        
        return true;
    }
    catch (std::exception& e) {
        return false;
    }
}

std::vector<unsigned char> ZkProver::createDepositProof(
    uint64_t publicAmount,
    const uint256& commitment,
    const std::string& spendKey) {
    
    if (!provingKey) {
        if (!generateKeys()) {
            return {}; // Failure: return empty vector
        }
    }
    
    try {
        // Create a new protoboard for deposit proof construction
        protoboard<FieldT> pb;
        
        // Setup variables similar to generateKeys()
        pb_variable<FieldT> public_amount;
        pb_variable<FieldT> value;
        pb_variable_array<FieldT> commitment_bits;
        
        public_amount.allocate(pb, "public_amount");
        value.allocate(pb, "value");
        commitment_bits.allocate(pb, 256, "commitment_bits");
        
        pb.set_input_sizes(1 + 256); // 1 for amount + 256 bits for commitment
        
        // Set values of the variables
        pb.val(public_amount) = FieldT(publicAmount);
        pb.val(value) = FieldT(publicAmount); // deposit: value equals public amount
        
        // Convert commitment to bit vector for ZKP verification
        std::vector<bool> commitment_bits_vector = uint256ToBits(commitment);
        for (size_t i = 0; i < 256; i++) {
            pb.val(commitment_bits[i]) = commitment_bits_vector[i] ? FieldT::one() : FieldT::zero();
        }
        
        // The actual commitment constraint should be enforced via a SHA256 gadget (not fully shown)        // Generate the proof
        const r1cs_ppzksnark_proof<DefaultCurve> proof =
            r1cs_ppzksnark_prover<DefaultCurve>(*provingKey, pb.primary_input(), pb.auxiliary_input());
        
        return serializeProof(proof);
    }
    catch (std::exception& e) {
        return {}; // On error, return empty vector
    }
}

std::vector<unsigned char> ZkProver::createWithdrawalProof(
    uint64_t publicAmount,
    const uint256& nullifier,
    const uint256& merkleRoot,
    const std::vector<uint256>& merklePath,
    size_t pathIndex,
    const std::string& spendKey) {
    
    if (!provingKey) {
        if (!generateKeys()) {
            return {};
        }
    }
    
    try {
        // Create a new protoboard for withdrawal proof construction
        protoboard<FieldT> pb;
        
        pb_variable<FieldT> public_amount;
        pb_variable_array<FieldT> root_bits;
        pb_variable_array<FieldT> nullifier_bits;
        
        public_amount.allocate(pb, "public_amount");
        root_bits.allocate(pb, 256, "root_bits");
        nullifier_bits.allocate(pb, 256, "nullifier_bits");
        
        pb.set_input_sizes(1 + 256 + 256); // amount + root + nullifier
        
        // Set values
        pb.val(public_amount) = FieldT(publicAmount);
        
        std::vector<bool> root_bits_vector = uint256ToBits(merkleRoot);
        for (size_t i = 0; i < 256; i++) {
            pb.val(root_bits[i]) = root_bits_vector[i] ? FieldT::one() : FieldT::zero();
        }
        
        std::vector<bool> nullifier_bits_vector = uint256ToBits(nullifier);
        for (size_t i = 0; i < 256; i++) {
            pb.val(nullifier_bits[i]) = nullifier_bits_vector[i] ? FieldT::one() : FieldT::zero();
        }
        
        // Generate the proof
        const r1cs_ppzksnark_proof<DefaultCurve> proof =
            r1cs_ppzksnark_prover<DefaultCurve>(*provingKey, pb.primary_input(), pb.auxiliary_input());
        
        return serializeProof(proof);
    }
    catch (std::exception& e) {
        return {};
    }
}

bool ZkProver::verifyDepositProof(
    const std::vector<unsigned char>& proofData,
    uint64_t publicAmount,
    const uint256& commitment) {
    
    if (!verificationKey) {
        if (!generateKeys()) {
            return false;
        }
    }
    
    try {
        r1cs_ppzksnark_proof<DefaultCurve> proof = deserializeProof(proofData);
        
        std::vector<FieldT> public_input;
        public_input.push_back(FieldT(publicAmount));
        
        std::vector<bool> commitment_bits = uint256ToBits(commitment);
        for (bool bit : commitment_bits) {
            public_input.push_back(bit ? FieldT::one() : FieldT::zero());
        }
        
        bool verified = r1cs_ppzksnark_verifier_strong_IC<DefaultCurve>(*verificationKey, public_input, proof);
        return verified;
    }
    catch (std::exception& e) {
        return false;
    }
}

bool ZkProver::verifyWithdrawalProof(
    const std::vector<unsigned char>& proofData,
    uint64_t publicAmount,
    const uint256& merkleRoot,
    const uint256& nullifier) {
    
    if (!verificationKey) {
        if (!generateKeys()) {
            return false;
        }
    }
    
    try {
        r1cs_ppzksnark_proof<DefaultCurve> proof = deserializeProof(proofData);
        
        std::vector<FieldT> public_input;
        public_input.push_back(FieldT(publicAmount));
        
        std::vector<bool> root_bits = uint256ToBits(merkleRoot);
        for (bool bit : root_bits) {
            public_input.push_back(bit ? FieldT::one() : FieldT::zero());
        }
        
        std::vector<bool> nullifier_bits = uint256ToBits(nullifier);
        for (bool bit : nullifier_bits) {
            public_input.push_back(bit ? FieldT::one() : FieldT::zero());
        }
        
        bool verified = r1cs_ppzksnark_verifier_strong_IC<DefaultCurve>(*verificationKey, public_input, proof);
        return verified;
    }
    catch (std::exception& e) {
        return false;
    }
}

std::vector<bool> ZkProver::uint256ToBits(const uint256& input) {
    std::vector<bool> result(256);
    for (size_t i = 0; i < 256; i++) {
        size_t byte_idx = i / 8;
        size_t bit_idx = i % 8;
        result[i] = (input.data()[byte_idx] >> bit_idx) & 1;
    }
    return result;
}

uint256 ZkProver::bitsToUint256(const std::vector<bool>& bits) {
    uint256 result;
    for (size_t i = 0; i < std::min(bits.size(), size_t(256)); i++) {
        if (bits[i]) {
            size_t byte_idx = i / 8;
            size_t bit_idx = i % 8;
            result.data()[byte_idx] |= (1 << bit_idx);
        }
    }
    return result;
}

std::vector<unsigned char> ZkProver::serializeProof(
    const r1cs_ppzksnark_proof<DefaultCurve>& proof) {
    std::stringstream ss;
    ss << proof;
    std::string str = ss.str();
    return std::vector<unsigned char>(str.begin(), str.end());
}

r1cs_ppzksnark_proof<DefaultCurve> ZkProver::deserializeProof(
    const std::vector<unsigned char>& proofData) {
    std::string str(proofData.begin(), proofData.end());
    std::stringstream ss(str);
    r1cs_ppzksnark_proof<DefaultCurve> proof;
    ss >> proof;
    return proof;
}

} // namespace zkp
} // namespace ripple