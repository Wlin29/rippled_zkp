#include "MerkleCircuit.h"
#include <iostream>
#include <libsnark/gadgetlib1/pb_variable.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <algorithm>
#include <cassert>

namespace ripple {
namespace zkp {

using libsnark::pb_variable;
using libsnark::pb_variable_array;
using libsnark::pb_linear_combination;
using libsnark::packing_gadget;
using libsnark::multipacking_gadget;
using libsnark::sha256_two_to_one_hash_gadget;
using libsnark::merkle_authentication_path_variable;
using libsnark::merkle_tree_check_read_gadget;

void initCurveParameters() {
    static bool initialized = false;
    if (!initialized) {
        DefaultCurve::init_public_params();
        initialized = true;
    }
}

class MerkleCircuit::Impl {
private:
    size_t tree_depth_;
    std::shared_ptr<libsnark::protoboard<FieldT>> pb_;
    
    // PRIMARY INPUTS (public)
    pb_variable<FieldT> anchor_;                    
    pb_variable<FieldT> nullifier_;                 
    pb_variable<FieldT> value_commitment_;          

    // AUXILIARY INPUTS (private)
    pb_variable<FieldT> value_;                     
    pb_variable<FieldT> value_randomness_;          
    pb_variable<FieldT> spend_key_;                 
    pb_variable<FieldT> rho_;                       
    
    // MERKLE TREE VARIABLES
    pb_variable_array<FieldT> address_bits_;        // Position in tree
    pb_variable<FieldT> read_successful_;           // Always 1 for successful reads
    
    // BIT REPRESENTATIONS
    pb_variable_array<FieldT> value_bits_;          // 64 bits
    pb_variable_array<FieldT> value_randomness_bits_; // 256 bits
    pb_variable_array<FieldT> spend_key_bits_;      // 256 bits
    pb_variable_array<FieldT> rho_bits_;            // 256 bits
    
    // SHA256 TWO-TO-ONE HASH GADGETS
    std::unique_ptr<sha256_two_to_one_hash_gadget<FieldT>> value_commit_hasher_;
    std::unique_ptr<sha256_two_to_one_hash_gadget<FieldT>> nullifier_hasher_;
    std::unique_ptr<sha256_two_to_one_hash_gadget<FieldT>> note_commit_hasher_;
    
    // MERKLE TREE GADGETS
    std::unique_ptr<merkle_authentication_path_variable<FieldT, sha256_two_to_one_hash_gadget<FieldT>>> auth_path_;
    std::unique_ptr<merkle_tree_check_read_gadget<FieldT, sha256_two_to_one_hash_gadget<FieldT>>> merkle_verifier_;
    
    // DIGEST VARIABLES (SHA256 inputs and outputs)
    std::unique_ptr<digest_variable<FieldT>> value_digest_;
    std::unique_ptr<digest_variable<FieldT>> value_randomness_digest_;
    std::unique_ptr<digest_variable<FieldT>> spend_key_digest_;
    std::unique_ptr<digest_variable<FieldT>> rho_digest_;
    
    std::unique_ptr<digest_variable<FieldT>> value_commit_digest_;
    std::unique_ptr<digest_variable<FieldT>> nullifier_digest_;
    std::unique_ptr<digest_variable<FieldT>> note_commit_digest_;
    std::unique_ptr<digest_variable<FieldT>> computed_root_digest_;
    
    // PACKING GADGETS (convert bits to field elements)
    std::unique_ptr<packing_gadget<FieldT>> value_packer_;
    std::unique_ptr<packing_gadget<FieldT>> spend_key_packer_;
    std::unique_ptr<packing_gadget<FieldT>> value_randomness_packer_;
    std::unique_ptr<packing_gadget<FieldT>> rho_packer_;
    std::unique_ptr<packing_gadget<FieldT>> value_commit_packer_;
    std::unique_ptr<packing_gadget<FieldT>> nullifier_packer_;
    std::unique_ptr<packing_gadget<FieldT>> anchor_packer_;
    
public:
    Impl(size_t tree_depth) : tree_depth_(tree_depth) {
        std::cout << "Creating working MerkleCircuit with depth " << tree_depth << std::endl;
        
        pb_ = std::make_shared<libsnark::protoboard<FieldT>>();
        
        // Allocate public inputs first
        anchor_.allocate(*pb_, "anchor");
        nullifier_.allocate(*pb_, "nullifier");
        value_commitment_.allocate(*pb_, "value_commitment");
        
        // Set the number of primary inputs
        pb_->set_input_sizes(3);
        
        // Allocate private field elements
        value_.allocate(*pb_, "value");
        value_randomness_.allocate(*pb_, "value_randomness");
        spend_key_.allocate(*pb_, "spend_key");
        rho_.allocate(*pb_, "rho");
        
        // Allocate Merkle tree variables
        address_bits_.allocate(*pb_, tree_depth_, "address_bits");
        read_successful_.allocate(*pb_, "read_successful");
        
        std::cout << "MerkleCircuit initialized successfully" << std::endl;
    }
    
    void generateConstraints() {
        std::cout << "Generating working constraints..." << std::endl;
        
        // 1. ALLOCATE BIT VARIABLES
        value_bits_.allocate(*pb_, 64, "value_bits");
        value_randomness_bits_.allocate(*pb_, 256, "value_randomness_bits");
        spend_key_bits_.allocate(*pb_, 256, "spend_key_bits");
        rho_bits_.allocate(*pb_, 256, "rho_bits");
        
        // 2. SETUP PACKING GADGETS
        value_packer_ = std::make_unique<packing_gadget<FieldT>>(
            *pb_, value_bits_, value_, "value_packer");
        
        spend_key_packer_ = std::make_unique<packing_gadget<FieldT>>(
            *pb_, spend_key_bits_, spend_key_, "spend_key_packer");
        
        value_randomness_packer_ = std::make_unique<packing_gadget<FieldT>>(
            *pb_, value_randomness_bits_, value_randomness_, "value_randomness_packer");
        
        rho_packer_ = std::make_unique<packing_gadget<FieldT>>(
            *pb_, rho_bits_, rho_, "rho_packer");
        
        // 3. SETUP DIGEST VARIABLES (256-bit chunks for two-to-one hashing)
        value_digest_ = std::make_unique<digest_variable<FieldT>>(
            *pb_, 256, "value_digest");
        
        value_randomness_digest_ = std::make_unique<digest_variable<FieldT>>(
            *pb_, 256, "value_randomness_digest");
        
        spend_key_digest_ = std::make_unique<digest_variable<FieldT>>(
            *pb_, 256, "spend_key_digest");
        
        rho_digest_ = std::make_unique<digest_variable<FieldT>>(
            *pb_, 256, "rho_digest");
        
        // Output digests
        value_commit_digest_ = std::make_unique<digest_variable<FieldT>>(
            *pb_, 256, "value_commit_digest");
        
        nullifier_digest_ = std::make_unique<digest_variable<FieldT>>(
            *pb_, 256, "nullifier_digest");
        
        note_commit_digest_ = std::make_unique<digest_variable<FieldT>>(
            *pb_, 256, "note_commit_digest");
        
        computed_root_digest_ = std::make_unique<digest_variable<FieldT>>(
            *pb_, 256, "computed_root_digest");
        
        // 4. SETUP SHA256 TWO-TO-ONE HASH GADGETS
        
        // Value commitment: SHA256(value || value_randomness)
        value_commit_hasher_ = std::make_unique<sha256_two_to_one_hash_gadget<FieldT>>(
            *pb_,
            *value_digest_,           // left input (padded value)
            *value_randomness_digest_, // right input (value_randomness)
            *value_commit_digest_,     // output
            "value_commit_hasher");
        
        // Nullifier: SHA256(spend_key || rho)
        nullifier_hasher_ = std::make_unique<sha256_two_to_one_hash_gadget<FieldT>>(
            *pb_,
            *spend_key_digest_,       // left input
            *rho_digest_,             // right input
            *nullifier_digest_,       // output
            "nullifier_hasher");
        
        // Note commitment: SHA256(value_commit_digest || nullifier_digest)
        note_commit_hasher_ = std::make_unique<sha256_two_to_one_hash_gadget<FieldT>>(
            *pb_,
            *value_commit_digest_,    // left input (value commitment)
            *nullifier_digest_,       // right input (nullifier)
            *note_commit_digest_,     // output (leaf in Merkle tree)
            "note_commit_hasher");
        
        // 5. SETUP MERKLE TREE VERIFICATION
        
        // Authentication path for Merkle tree
        auth_path_ = std::make_unique<merkle_authentication_path_variable<FieldT, sha256_two_to_one_hash_gadget<FieldT>>>(
            *pb_, tree_depth_, "auth_path");
        
        // Merkle tree verification gadget
        merkle_verifier_ = std::make_unique<merkle_tree_check_read_gadget<FieldT, sha256_two_to_one_hash_gadget<FieldT>>>(
            *pb_,
            tree_depth_,
            address_bits_,           // position in tree
            *note_commit_digest_,    // leaf (note commitment)
            *computed_root_digest_,  // computed root
            *auth_path_,            // authentication path
            read_successful_,        // read successful flag
            "merkle_verifier");
        
        // 6. SETUP PACKING GADGETS (SHA256 OUTPUTS → FIELD ELEMENTS)
        value_commit_packer_ = std::make_unique<packing_gadget<FieldT>>(
            *pb_, value_commit_digest_->bits, value_commitment_, "value_commit_packer");
        
        nullifier_packer_ = std::make_unique<packing_gadget<FieldT>>(
            *pb_, nullifier_digest_->bits, nullifier_, "nullifier_packer");
        
        anchor_packer_ = std::make_unique<packing_gadget<FieldT>>(
            *pb_, computed_root_digest_->bits, anchor_, "anchor_packer");
        
        // 7. GENERATE ALL CONSTRAINTS
        
        // Packing constraints (field elements ↔ bits)
        value_packer_->generate_r1cs_constraints(true);
        spend_key_packer_->generate_r1cs_constraints(true);
        value_randomness_packer_->generate_r1cs_constraints(true);
        rho_packer_->generate_r1cs_constraints(true);
        
        // SHA256 two-to-one hash constraints
        value_commit_hasher_->generate_r1cs_constraints();
        nullifier_hasher_->generate_r1cs_constraints();
        note_commit_hasher_->generate_r1cs_constraints();
        
        // CRITICAL: Merkle tree verification constraints
        merkle_verifier_->generate_r1cs_constraints();
        
        // Constrain read_successful to 1 (successful read)
        pb_->add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(
            read_successful_, 1, FieldT::one()), "read_successful_constraint");
        
        // Packing constraints (SHA256 outputs → field elements)
        value_commit_packer_->generate_r1cs_constraints(true);
        nullifier_packer_->generate_r1cs_constraints(true);
        anchor_packer_->generate_r1cs_constraints(true);
        
        // 8. BOOLEAN CONSTRAINTS (ensure all bits are 0 or 1)
        for (size_t i = 0; i < value_bits_.size(); ++i) {
            libsnark::generate_boolean_r1cs_constraint<FieldT>(*pb_, value_bits_[i], "value_bit_" + std::to_string(i));
        }
        
        for (size_t i = 0; i < spend_key_bits_.size(); ++i) {
            libsnark::generate_boolean_r1cs_constraint<FieldT>(*pb_, spend_key_bits_[i], "spend_key_bit_" + std::to_string(i));
        }
        
        for (size_t i = 0; i < value_randomness_bits_.size(); ++i) {
            libsnark::generate_boolean_r1cs_constraint<FieldT>(*pb_, value_randomness_bits_[i], "value_randomness_bit_" + std::to_string(i));
        }
        
        for (size_t i = 0; i < rho_bits_.size(); ++i) {
            libsnark::generate_boolean_r1cs_constraint<FieldT>(*pb_, rho_bits_[i], "rho_bit_" + std::to_string(i));
        }
        
        // Address bit constraints
        for (size_t i = 0; i < address_bits_.size(); ++i) {
            libsnark::generate_boolean_r1cs_constraint<FieldT>(*pb_, address_bits_[i], "address_bit_" + std::to_string(i));
        }
        
        std::cout << "constraints with Merkle verification generated. Total: " << pb_->num_constraints() << std::endl;
    }
    
    void generateWitness(
        uint64_t value,
        const FieldT& value_randomness,
        const std::vector<bool>& leaf,
        const std::vector<std::vector<bool>>& path,
        const std::vector<bool>& root,
        const std::vector<bool>& spend_key,
        size_t address)
    {
        std::cout << "Generating witness..." << std::endl;
        
        try {
            // 1. SET FIELD ELEMENT VALUES
            pb_->val(value_) = FieldT(value);
            pb_->val(value_randomness_) = value_randomness;
            pb_->val(spend_key_) = bitsToFieldElement(spend_key);
            
            // Generate deterministic rho from spend_key and value
            FieldT spend_key_field = bitsToFieldElement(spend_key);
            pb_->val(rho_) = spend_key_field + FieldT(value) + FieldT(12345);
            pb_->val(read_successful_) = FieldT::one();
            
            // 2. SET ADDRESS BITS FOR MERKLE PATH
            for (size_t i = 0; i < tree_depth_; ++i) {
                pb_->val(address_bits_[i]) = FieldT((address >> i) & 1);
            }
            
            // 3. CONVERT FIELD ELEMENTS TO BIT ARRAYS
            
            // Convert value to 64 bits, pad to 256
            uint64_t value_u64 = value;
            for (size_t i = 0; i < 64; ++i) {
                pb_->val(value_bits_[i]) = FieldT((value_u64 >> i) & 1);
            }
            
            // Convert spend_key to bits
            for (size_t i = 0; i < std::min(spend_key.size(), size_t(256)); ++i) {
                pb_->val(spend_key_bits_[i]) = spend_key[i] ? FieldT::one() : FieldT::zero();
            }
            
            // Convert value_randomness to bits
            std::vector<bool> value_randomness_bits = fieldElementToBits(value_randomness);
            for (size_t i = 0; i < std::min(value_randomness_bits.size(), size_t(256)); ++i) {
                pb_->val(value_randomness_bits_[i]) = value_randomness_bits[i] ? FieldT::one() : FieldT::zero();
            }
            
            // Convert rho to bits
            std::vector<bool> rho_bits = fieldElementToBits(pb_->val(rho_));
            for (size_t i = 0; i < std::min(rho_bits.size(), size_t(256)); ++i) {
                pb_->val(rho_bits_[i]) = rho_bits[i] ? FieldT::one() : FieldT::zero();
            }
            
            // 4. SET DIGEST BITS
            
            // Set value digest bits (pad value to 256 bits)
            for (size_t i = 0; i < 64; ++i) {
                pb_->val(value_digest_->bits[i]) = pb_->val(value_bits_[i]);
            }
            for (size_t i = 64; i < 256; ++i) {
                pb_->val(value_digest_->bits[i]) = FieldT::zero();
            }
            
            // Set other digest bits
            for (size_t i = 0; i < 256; ++i) {
                pb_->val(value_randomness_digest_->bits[i]) = pb_->val(value_randomness_bits_[i]);
                pb_->val(spend_key_digest_->bits[i]) = pb_->val(spend_key_bits_[i]);
                pb_->val(rho_digest_->bits[i]) = pb_->val(rho_bits_[i]);
            }
            
            // 5. SET MERKLE AUTHENTICATION PATH
            for (size_t i = 0; i < tree_depth_; ++i) {
                if (i < path.size()) {
                    for (size_t j = 0; j < 256; ++j) {
                        if (j < path[i].size()) {
                            pb_->val(auth_path_->left_digests[i].bits[j]) = path[i][j] ? FieldT::one() : FieldT::zero();
                            pb_->val(auth_path_->right_digests[i].bits[j]) = path[i][j] ? FieldT::one() : FieldT::zero();
                        } else {
                            pb_->val(auth_path_->left_digests[i].bits[j]) = FieldT::zero();
                            pb_->val(auth_path_->right_digests[i].bits[j]) = FieldT::zero();
                        }
                    }
                } else {
                    // Fill remaining path levels with zeros
                    for (size_t j = 0; j < 256; ++j) {
                        pb_->val(auth_path_->left_digests[i].bits[j]) = FieldT::zero();
                        pb_->val(auth_path_->right_digests[i].bits[j]) = FieldT::zero();
                    }
                }
            }
            
            // 6. GENERATE PACKING WITNESSES
            value_packer_->generate_r1cs_witness_from_packed();
            spend_key_packer_->generate_r1cs_witness_from_packed();
            value_randomness_packer_->generate_r1cs_witness_from_packed();
            rho_packer_->generate_r1cs_witness_from_packed();
            
            // 7. GENERATE SHA256 WITNESSES
            value_commit_hasher_->generate_r1cs_witness();
            nullifier_hasher_->generate_r1cs_witness();
            note_commit_hasher_->generate_r1cs_witness();
            
            // 8. GENERATE MERKLE TREE WITNESS
            merkle_verifier_->generate_r1cs_witness();
            
            // 9. GENERATE FINAL PACKING WITNESSES (SHA256 outputs → field elements)
            value_commit_packer_->generate_r1cs_witness_from_bits();
            nullifier_packer_->generate_r1cs_witness_from_bits();
            anchor_packer_->generate_r1cs_witness_from_bits();
            
            std::cout << "Working witness generation completed successfully" << std::endl;
            
        } catch (const std::exception& e) {
            std::cerr << "Error in working witness generation: " << e.what() << std::endl;
            throw;
        }
    }
    
private:
    FieldT bitsToFieldElement(const std::vector<bool>& bits) {
        FieldT result = FieldT::zero();
        FieldT power = FieldT::one();
        
        for (size_t i = 0; i < std::min(bits.size(), size_t(253)); ++i) {
            if (bits[i]) {
                result += power;
            }
            power += power; // power *= 2
        }
        return result;
    }
    
    std::vector<bool> fieldElementToBits(const FieldT& element) {
        std::vector<bool> bits(253);
        FieldT temp = element;
        FieldT two = FieldT(2);
        
        for (size_t i = 0; i < 253; ++i) {
            FieldT remainder = temp - ((temp * two.inverse()) + (temp * two.inverse())); // temp % 2
            bits[i] = (remainder == FieldT::one());
            temp = temp * two.inverse(); // temp /= 2
        }
        return bits;
    }
    
public:
    // Getters
    FieldT getNullifier() const { return pb_->val(nullifier_); }
    FieldT getValueCommitment() const { return pb_->val(value_commitment_); }
    FieldT getAnchor() const { return pb_->val(anchor_); }
    
    libsnark::r1cs_constraint_system<FieldT> getConstraintSystem() const {
        return pb_->get_constraint_system();
    }
    
    libsnark::r1cs_primary_input<FieldT> getPrimaryInput() const {
        return pb_->primary_input();
    }
    
    libsnark::r1cs_auxiliary_input<FieldT> getAuxiliaryInput() const {
        return pb_->auxiliary_input();
    }
    
    std::shared_ptr<libsnark::protoboard<FieldT>> getProtoboard() const {
        return pb_;
    }
    
    size_t getTreeDepth() const { return tree_depth_; }
    
    // Witness generation wrappers
    std::vector<FieldT> generateDepositWitness(
        uint64_t value,
        const FieldT& value_randomness,
        const std::vector<bool>& leaf,
        const std::vector<bool>& root,
        const std::vector<bool>& spend_key)
    {
        // For deposits, use dummy path (note not yet in tree)
        std::vector<std::vector<bool>> dummyPath(tree_depth_, std::vector<bool>(256, false));
        generateWitness(value, value_randomness, leaf, dummyPath, root, spend_key, 0);
        return pb_->auxiliary_input();
    }
    
    std::vector<FieldT> generateWithdrawalWitness(
        uint64_t value,
        const FieldT& value_randomness,
        const std::vector<bool>& leaf,
        const std::vector<std::vector<bool>>& path,
        const std::vector<bool>& root,
        const std::vector<bool>& spend_key,
        size_t address)
    {
        // For withdrawals, use real authentication path
        generateWitness(value, value_randomness, leaf, path, root, spend_key, address);
        return pb_->auxiliary_input();
    }
};

// Implementation of public interface
MerkleCircuit::MerkleCircuit(size_t treeDepth) 
    : pImpl_(std::make_unique<Impl>(treeDepth)) {
}

MerkleCircuit::~MerkleCircuit() = default;

void MerkleCircuit::generateConstraints() {
    pImpl_->generateConstraints();
}

std::vector<FieldT> MerkleCircuit::generateDepositWitness(
    uint64_t value,
    const FieldT& value_randomness,
    const std::vector<bool>& leaf,
    const std::vector<bool>& root,
    const std::vector<bool>& spend_key) {
    return pImpl_->generateDepositWitness(value, value_randomness, leaf, root, spend_key);
}

std::vector<FieldT> MerkleCircuit::generateWithdrawalWitness(
    uint64_t value,
    const FieldT& value_randomness,
    const std::vector<bool>& leaf,
    const std::vector<std::vector<bool>>& path,
    const std::vector<bool>& root,
    const std::vector<bool>& spend_key,
    size_t address) {
    return pImpl_->generateWithdrawalWitness(value, value_randomness, leaf, path, root, spend_key, address);
}

FieldT MerkleCircuit::getNullifier() const { return pImpl_->getNullifier(); }
FieldT MerkleCircuit::getValueCommitment() const { return pImpl_->getValueCommitment(); }
FieldT MerkleCircuit::getAnchor() const { return pImpl_->getAnchor(); }

libsnark::r1cs_constraint_system<FieldT> MerkleCircuit::getConstraintSystem() const {
    return pImpl_->getConstraintSystem();
}

libsnark::r1cs_primary_input<FieldT> MerkleCircuit::getPrimaryInput() const {
    return pImpl_->getPrimaryInput();
}

libsnark::r1cs_auxiliary_input<FieldT> MerkleCircuit::getAuxiliaryInput() const {
    return pImpl_->getAuxiliaryInput();
}

std::shared_ptr<libsnark::protoboard<FieldT>> MerkleCircuit::getProtoboard() const {
    return pImpl_->getProtoboard();
}

size_t MerkleCircuit::getTreeDepth() const {
    return pImpl_->getTreeDepth();
}

// Utility functions implementation
std::vector<bool> MerkleCircuit::uint256ToBits(const std::array<uint8_t, 32>& input) {
    std::vector<bool> bits(256);
    for (size_t i = 0; i < 256; i++) {
        size_t byteIndex = i / 8;
        size_t bitIndex = i % 8;
        bits[i] = ((input[byteIndex] >> bitIndex) & 1) != 0;
    }
    return bits;
}

std::array<uint8_t, 32> MerkleCircuit::bitsToUint256(const std::vector<bool>& bits) {
    std::array<uint8_t, 32> result = {};
    for (size_t i = 0; i < std::min(bits.size(), size_t(256)); i++) {
        size_t byteIndex = i / 8;
        size_t bitIndex = i % 8;
        if (bits[i]) {
            result[byteIndex] |= (1 << bitIndex);
        }
    }
    return result;
}

std::vector<bool> MerkleCircuit::spendKeyToBits(const std::string& spendKey) {
    std::vector<bool> bits(256, false);
    for (size_t i = 0; i < std::min(spendKey.length(), size_t(32)); ++i) {
        uint8_t byte = static_cast<uint8_t>(spendKey[i]);
        for (size_t j = 0; j < 8; ++j) {
            bits[i * 8 + j] = (byte >> j) & 1;
        }
    }
    return bits;
}

FieldT MerkleCircuit::bitsToFieldElement(const std::vector<bool>& bits) {
    FieldT result = FieldT::zero();
    FieldT power = FieldT::one();
    
    for (size_t i = 0; i < std::min(bits.size(), size_t(253)); ++i) {
        if (bits[i]) {
            result += power;
        }
        power += power; // power *= 2 using addition
    }
    return result;
}

std::vector<bool> MerkleCircuit::fieldElementToBits(const FieldT& element) {
    std::vector<bool> bits(253);
    FieldT temp = element;
    FieldT two = FieldT(2);
    
    for (size_t i = 0; i < 253; ++i) {
        FieldT quotient = temp * two.inverse();
        FieldT remainder = temp - (quotient + quotient);
        
        bits[i] = (remainder == FieldT::one());
        temp = quotient;
    }
    return bits;
}

} // namespace zkp
} // namespace ripple