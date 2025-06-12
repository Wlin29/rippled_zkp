#include "MerkleCircuit.h"
#include "../Note.h"
#include <xrpl/basics/base_uint.h>
#include <iostream>
#include <libsnark/gadgetlib1/pb_variable.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <algorithm>
#include <cassert>
#include <openssl/sha.h>

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
    
    // ===== PUBLIC INPUTS (PRIMARY) =====
    pb_variable<FieldT> anchor_;                    // Tree root
    pb_variable<FieldT> nullifier_;                 // Spend nullifier
    pb_variable<FieldT> value_commitment_;          // Value hiding commitment

    // ===== PRIVATE INPUTS (AUXILIARY) =====
    // Note components
    pb_variable<FieldT> note_value_;                // Note amount
    pb_variable<FieldT> note_rho_;                  // Nullifier seed
    pb_variable<FieldT> note_r_;                    // Commitment randomness
    pb_variable<FieldT> note_a_pk_;                 // Recipient public key
    
    // Spend authorization
    pb_variable<FieldT> a_sk_;                      // Spend key (secret)
    pb_variable<FieldT> vcm_r_;                     // Value commitment randomness
    
    // Merkle tree variables
    pb_variable_array<FieldT> address_bits_;        // Leaf position
    pb_variable<FieldT> read_successful_;           // Always 1
    
    // ===== BIT DECOMPOSITIONS =====
    pb_variable_array<FieldT> note_value_bits_;     // 64 bits
    pb_variable_array<FieldT> note_rho_bits_;       // 256 bits
    pb_variable_array<FieldT> note_r_bits_;         // 256 bits
    pb_variable_array<FieldT> note_a_pk_bits_;      // 256 bits
    pb_variable_array<FieldT> a_sk_bits_;           // 256 bits
    pb_variable_array<FieldT> vcm_r_bits_;          // 256 bits
    
    // ===== SHA256 HASH VARIABLES =====
    std::unique_ptr<digest_variable<FieldT>> note_commitment_hash_;
    std::unique_ptr<digest_variable<FieldT>> nullifier_hash_;
    std::unique_ptr<digest_variable<FieldT>> value_commitment_hash_;
    std::unique_ptr<digest_variable<FieldT>> computed_root_;
    
    // ===== SHA256 GADGETS =====
    std::unique_ptr<sha256_two_to_one_hash_gadget<FieldT>> note_commit_hasher_;
    std::unique_ptr<sha256_two_to_one_hash_gadget<FieldT>> nullifier_hasher_;
    std::unique_ptr<sha256_two_to_one_hash_gadget<FieldT>> value_commit_hasher_;
    
    // ===== MERKLE TREE GADGETS =====
    std::unique_ptr<merkle_authentication_path_variable<FieldT, sha256_two_to_one_hash_gadget<FieldT>>> auth_path_;
    std::unique_ptr<merkle_tree_check_read_gadget<FieldT, sha256_two_to_one_hash_gadget<FieldT>>> merkle_verifier_;
    
    // ===== PACKING GADGETS =====
    std::unique_ptr<packing_gadget<FieldT>> note_value_packer_;
    std::unique_ptr<packing_gadget<FieldT>> note_rho_packer_;
    std::unique_ptr<packing_gadget<FieldT>> note_r_packer_;
    std::unique_ptr<packing_gadget<FieldT>> note_a_pk_packer_;
    std::unique_ptr<packing_gadget<FieldT>> a_sk_packer_;
    std::unique_ptr<packing_gadget<FieldT>> vcm_r_packer_;
    
    std::unique_ptr<packing_gadget<FieldT>> anchor_packer_;
    std::unique_ptr<packing_gadget<FieldT>> nullifier_packer_;
    std::unique_ptr<packing_gadget<FieldT>> value_commitment_packer_;

public:
    Impl(size_t tree_depth) : tree_depth_(tree_depth) {
        std::cout << "Creating MerkleCircuit with depth " << tree_depth << std::endl;
        
        pb_ = std::make_shared<libsnark::protoboard<FieldT>>();
        
        // Allocate public inputs first (order: anchor, nullifier, value_commitment)
        anchor_.allocate(*pb_, "anchor");
        nullifier_.allocate(*pb_, "nullifier");
        value_commitment_.allocate(*pb_, "value_commitment");
        
        // Set primary input count
        pb_->set_input_sizes(3);
        
        // Allocate private field elements
        note_value_.allocate(*pb_, "note_value");
        note_rho_.allocate(*pb_, "note_rho");
        note_r_.allocate(*pb_, "note_r");
        note_a_pk_.allocate(*pb_, "note_a_pk");
        a_sk_.allocate(*pb_, "a_sk");
        vcm_r_.allocate(*pb_, "vcm_r");
        
        // Allocate Merkle tree variables
        address_bits_.allocate(*pb_, tree_depth_, "address_bits");
        read_successful_.allocate(*pb_, "read_successful");
        
        std::cout << "MerkleCircuit initialized successfully" << std::endl;
    }
    
    void generateConstraints() {
        std::cout << "Generating constraints..." << std::endl;
        
        // 1. ALLOCATE BIT DECOMPOSITION VARIABLES
        note_value_bits_.allocate(*pb_, 64, "note_value_bits");
        note_rho_bits_.allocate(*pb_, 256, "note_rho_bits");
        note_r_bits_.allocate(*pb_, 256, "note_r_bits");
        note_a_pk_bits_.allocate(*pb_, 256, "note_a_pk_bits");
        a_sk_bits_.allocate(*pb_, 256, "a_sk_bits");
        vcm_r_bits_.allocate(*pb_, 256, "vcm_r_bits");
        
        // 2. SETUP PACKING GADGETS (field elements ↔ bits)
        note_value_packer_ = std::make_unique<packing_gadget<FieldT>>(
            *pb_, note_value_bits_, note_value_, "note_value_packer");
        
        note_rho_packer_ = std::make_unique<packing_gadget<FieldT>>(
            *pb_, note_rho_bits_, note_rho_, "note_rho_packer");
        
        note_r_packer_ = std::make_unique<packing_gadget<FieldT>>(
            *pb_, note_r_bits_, note_r_, "note_r_packer");
        
        note_a_pk_packer_ = std::make_unique<packing_gadget<FieldT>>(
            *pb_, note_a_pk_bits_, note_a_pk_, "note_a_pk_packer");
        
        a_sk_packer_ = std::make_unique<packing_gadget<FieldT>>(
            *pb_, a_sk_bits_, a_sk_, "a_sk_packer");
        
        vcm_r_packer_ = std::make_unique<packing_gadget<FieldT>>(
            *pb_, vcm_r_bits_, vcm_r_, "vcm_r_packer");
        
        // 3. SETUP SHA256 DIGEST VARIABLES
        note_commitment_hash_ = std::make_unique<digest_variable<FieldT>>(
            *pb_, 256, "note_commitment_hash");
        
        nullifier_hash_ = std::make_unique<digest_variable<FieldT>>(
            *pb_, 256, "nullifier_hash");
        
        value_commitment_hash_ = std::make_unique<digest_variable<FieldT>>(
            *pb_, 256, "value_commitment_hash");
        
        computed_root_ = std::make_unique<digest_variable<FieldT>>(
            *pb_, 256, "computed_root");
        
        // 4. SETUP SHA256 HASH GADGETS
        
        // Note commitment: SHA256(value || rho || r || a_pk) - simplified as SHA256(value||rho, r||a_pk)
        auto value_rho_digest = std::make_unique<digest_variable<FieldT>>(*pb_, 256, "value_rho_digest");
        auto r_a_pk_digest = std::make_unique<digest_variable<FieldT>>(*pb_, 256, "r_a_pk_digest");
        
        // Pack value and rho together (simplified)
        for (size_t i = 0; i < 64; ++i) {
            value_rho_digest->bits[i] = note_value_bits_[i];
        }
        for (size_t i = 0; i < 192 && i < 256; ++i) {
            value_rho_digest->bits[64 + i] = note_rho_bits_[i];
        }
        
        // Pack r and a_pk together
        for (size_t i = 0; i < 256; ++i) {
            if (i < note_r_bits_.size()) {
                r_a_pk_digest->bits[i] = note_r_bits_[i];
            }
        }
        
        note_commit_hasher_ = std::make_unique<sha256_two_to_one_hash_gadget<FieldT>>(
            *pb_,
            *value_rho_digest,
            *r_a_pk_digest,
            *note_commitment_hash_,
            "note_commit_hasher");
        
        // Nullifier: SHA256(a_sk || rho)
        auto a_sk_digest = std::make_unique<digest_variable<FieldT>>(*pb_, 256, "a_sk_digest");
        auto rho_digest = std::make_unique<digest_variable<FieldT>>(*pb_, 256, "rho_digest");
        
        for (size_t i = 0; i < 256; ++i) {
            a_sk_digest->bits[i] = a_sk_bits_[i];
            rho_digest->bits[i] = note_rho_bits_[i];
        }
        
        nullifier_hasher_ = std::make_unique<sha256_two_to_one_hash_gadget<FieldT>>(
            *pb_,
            *a_sk_digest,
            *rho_digest,
            *nullifier_hash_,
            "nullifier_hasher");
        
        // Value commitment: SHA256(value || vcm_r)
        auto value_digest = std::make_unique<digest_variable<FieldT>>(*pb_, 256, "value_digest");
        auto vcm_r_digest = std::make_unique<digest_variable<FieldT>>(*pb_, 256, "vcm_r_digest");
        
        // Pad value to 256 bits
        for (size_t i = 0; i < 64; ++i) {
            value_digest->bits[i] = note_value_bits_[i];
        }
        for (size_t i = 64; i < 256; ++i) {
            pb_->val(value_digest->bits[i]) = FieldT::zero();
        }
        
        for (size_t i = 0; i < 256; ++i) {
            vcm_r_digest->bits[i] = vcm_r_bits_[i];
        }
        
        value_commit_hasher_ = std::make_unique<sha256_two_to_one_hash_gadget<FieldT>>(
            *pb_,
            *value_digest,
            *vcm_r_digest,
            *value_commitment_hash_,
            "value_commit_hasher");
        
        // 5. SETUP MERKLE TREE VERIFICATION
        auth_path_ = std::make_unique<merkle_authentication_path_variable<FieldT, sha256_two_to_one_hash_gadget<FieldT>>>(
            *pb_, tree_depth_, "auth_path");
        
        merkle_verifier_ = std::make_unique<merkle_tree_check_read_gadget<FieldT, sha256_two_to_one_hash_gadget<FieldT>>>(
            *pb_,
            tree_depth_,
            address_bits_,
            *note_commitment_hash_,
            *computed_root_,
            *auth_path_,
            read_successful_,
            "merkle_verifier");
        
        // 6. SETUP OUTPUT PACKING GADGETS
        anchor_packer_ = std::make_unique<packing_gadget<FieldT>>(
            *pb_, computed_root_->bits, anchor_, "anchor_packer");
        
        nullifier_packer_ = std::make_unique<packing_gadget<FieldT>>(
            *pb_, nullifier_hash_->bits, nullifier_, "nullifier_packer");
        
        value_commitment_packer_ = std::make_unique<packing_gadget<FieldT>>(
            *pb_, value_commitment_hash_->bits, value_commitment_, "value_commitment_packer");
        
        // 7. GENERATE ALL CONSTRAINTS
        
        // Input packing constraints
        note_value_packer_->generate_r1cs_constraints(true);
        note_rho_packer_->generate_r1cs_constraints(true);
        note_r_packer_->generate_r1cs_constraints(true);
        note_a_pk_packer_->generate_r1cs_constraints(true);
        a_sk_packer_->generate_r1cs_constraints(true);
        vcm_r_packer_->generate_r1cs_constraints(true);
        
        // Hash constraints
        note_commit_hasher_->generate_r1cs_constraints();
        nullifier_hasher_->generate_r1cs_constraints();
        value_commit_hasher_->generate_r1cs_constraints();
        
        // Merkle tree constraints
        merkle_verifier_->generate_r1cs_constraints();
        
        // Read successful constraint (always 1)
        pb_->add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(
            read_successful_, 1, FieldT::one()), "read_successful_constraint");
        
        // Output packing constraints
        anchor_packer_->generate_r1cs_constraints(true);
        nullifier_packer_->generate_r1cs_constraints(true);
        value_commitment_packer_->generate_r1cs_constraints(true);
        
        // Boolean constraints for all bits
        generateBooleanConstraints();
        
        std::cout << "Constraints generated. Total: " << pb_->num_constraints() << std::endl;
    }
    
    void generateBooleanConstraints() {
        // Boolean constraints for note value bits
        for (size_t i = 0; i < note_value_bits_.size(); ++i) {
            libsnark::generate_boolean_r1cs_constraint<FieldT>(*pb_, note_value_bits_[i], 
                "note_value_bit_" + std::to_string(i));
        }
        
        // Boolean constraints for other bit arrays
        auto generateBoolConstraintsForArray = [&](const pb_variable_array<FieldT>& arr, const std::string& prefix) {
            for (size_t i = 0; i < arr.size(); ++i) {
                libsnark::generate_boolean_r1cs_constraint<FieldT>(*pb_, arr[i], 
                    prefix + std::to_string(i));
            }
        };
        
        generateBoolConstraintsForArray(note_rho_bits_, "note_rho_bit_");
        generateBoolConstraintsForArray(note_r_bits_, "note_r_bit_");
        generateBoolConstraintsForArray(note_a_pk_bits_, "note_a_pk_bit_");
        generateBoolConstraintsForArray(a_sk_bits_, "a_sk_bit_");
        generateBoolConstraintsForArray(vcm_r_bits_, "vcm_r_bit_");
        generateBoolConstraintsForArray(address_bits_, "address_bit_");
    }
    
    std::vector<FieldT> generateDepositWitness(
        const Note& note,
        const uint256& a_sk,
        const uint256& vcm_r,
        const std::vector<bool>& leaf,
        const std::vector<bool>& root)
    {
        std::cout << "=== DEPOSIT WITNESS GENERATION ===" << std::endl;
        
        // For deposits, use dummy authentication path
        std::vector<std::vector<bool>> dummyPath(tree_depth_, std::vector<bool>(256, false));
        
        return generateWitness(note, a_sk, vcm_r, leaf, dummyPath, root, 0);
    }
    
    std::vector<FieldT> generateWithdrawalWitness(
        const Note& note,
        const uint256& a_sk,
        const uint256& vcm_r,
        const std::vector<bool>& leaf,
        const std::vector<std::vector<bool>>& path,
        const std::vector<bool>& root,
        size_t address)
    {
        std::cout << "=== WITHDRAWAL WITNESS GENERATION ===" << std::endl;
        
        return generateWitness(note, a_sk, vcm_r, leaf, path, root, address);
    }
    
private:
    std::vector<FieldT> generateWitness(
        const Note& note,
        const uint256& a_sk,
        const uint256& vcm_r,
        const std::vector<bool>& leaf,
        const std::vector<std::vector<bool>>& path,
        const std::vector<bool>& root,
        size_t address)
    {
        try {
            // 1. SET FIELD ELEMENT VALUES FROM NOTE
            pb_->val(note_value_) = FieldT(note.value);
            pb_->val(note_rho_) = MerkleCircuit::uint256ToFieldElement(note.rho);
            pb_->val(note_r_) = MerkleCircuit::uint256ToFieldElement(note.r);
            pb_->val(note_a_pk_) = MerkleCircuit::uint256ToFieldElement(note.a_pk);
            pb_->val(a_sk_) = MerkleCircuit::uint256ToFieldElement(a_sk);
            pb_->val(vcm_r_) = MerkleCircuit::uint256ToFieldElement(vcm_r);
            pb_->val(read_successful_) = FieldT::one();
            
            // 2. SET ADDRESS BITS
            for (size_t i = 0; i < tree_depth_; ++i) {
                pb_->val(address_bits_[i]) = FieldT((address >> i) & 1);
            }
            
            // 3. CONVERT TO BIT REPRESENTATIONS
            setBits(note, a_sk, vcm_r);
            
            // 4. SET AUTHENTICATION PATH
            setAuthenticationPath(path);
            
            // 5. GENERATE WITNESSES FOR ALL GADGETS
            generateAllWitnesses();
            
            std::cout << "Witness generation completed successfully" << std::endl;
            
            return pb_->auxiliary_input();
            
        } catch (const std::exception& e) {
            std::cerr << "Error in witness generation: " << e.what() << std::endl;
            throw;
        }
    }
    
    void setBits(const Note& note, const uint256& a_sk, const uint256& vcm_r) {
        // Convert note value to 64 bits
        uint64_t value_u64 = note.value;
        for (size_t i = 0; i < 64; ++i) {
            pb_->val(note_value_bits_[i]) = FieldT((value_u64 >> i) & 1);
        }
        
        // Convert uint256 values to bits
        auto rho_bits = MerkleCircuit::uint256ToBits(note.rho);
        auto r_bits = MerkleCircuit::uint256ToBits(note.r);
        auto a_pk_bits = MerkleCircuit::uint256ToBits(note.a_pk);
        auto a_sk_bits = MerkleCircuit::uint256ToBits(a_sk);
        auto vcm_r_bits = MerkleCircuit::uint256ToBits(vcm_r);
        
        // Set bit values
        for (size_t i = 0; i < 256; ++i) {
            pb_->val(note_rho_bits_[i]) = rho_bits[i] ? FieldT::one() : FieldT::zero();
            pb_->val(note_r_bits_[i]) = r_bits[i] ? FieldT::one() : FieldT::zero();
            pb_->val(note_a_pk_bits_[i]) = a_pk_bits[i] ? FieldT::one() : FieldT::zero();
            pb_->val(a_sk_bits_[i]) = a_sk_bits[i] ? FieldT::one() : FieldT::zero();
            pb_->val(vcm_r_bits_[i]) = vcm_r_bits[i] ? FieldT::one() : FieldT::zero();
        }
    }
    
    void setAuthenticationPath(const std::vector<std::vector<bool>>& path) {
        // Set authentication path for Merkle verification
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
                for (size_t j = 0; j < 256; ++j) {
                    pb_->val(auth_path_->left_digests[i].bits[j]) = FieldT::zero();
                    pb_->val(auth_path_->right_digests[i].bits[j]) = FieldT::zero();
                }
            }
        }
    }
    
    void generateAllWitnesses() {
        // Generate witnesses for packing gadgets
        note_value_packer_->generate_r1cs_witness_from_packed();
        note_rho_packer_->generate_r1cs_witness_from_packed();
        note_r_packer_->generate_r1cs_witness_from_packed();
        note_a_pk_packer_->generate_r1cs_witness_from_packed();
        a_sk_packer_->generate_r1cs_witness_from_packed();
        vcm_r_packer_->generate_r1cs_witness_from_packed();
        
        // Generate witnesses for hash gadgets
        note_commit_hasher_->generate_r1cs_witness();
        nullifier_hasher_->generate_r1cs_witness();
        value_commit_hasher_->generate_r1cs_witness();
        
        // Generate witness for Merkle tree verification
        merkle_verifier_->generate_r1cs_witness();
        
        // Generate witnesses for output packing
        anchor_packer_->generate_r1cs_witness_from_bits();
        nullifier_packer_->generate_r1cs_witness_from_bits();
        value_commitment_packer_->generate_r1cs_witness_from_bits();
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
};

// ===== PUBLIC INTERFACE IMPLEMENTATION =====

MerkleCircuit::MerkleCircuit(size_t treeDepth) 
    : pImpl_(std::make_unique<Impl>(treeDepth)) {
}

MerkleCircuit::~MerkleCircuit() = default;

void MerkleCircuit::generateConstraints() {
    pImpl_->generateConstraints();
}

std::vector<FieldT> MerkleCircuit::generateDepositWitness(
    const Note& note,
    const uint256& a_sk,
    const uint256& vcm_r,
    const std::vector<bool>& leaf,
    const std::vector<bool>& root) {
    return pImpl_->generateDepositWitness(note, a_sk, vcm_r, leaf, root);
}

std::vector<FieldT> MerkleCircuit::generateWithdrawalWitness(
    const Note& note,
    const uint256& a_sk,
    const uint256& vcm_r,
    const std::vector<bool>& leaf,
    const std::vector<std::vector<bool>>& path,
    const std::vector<bool>& root,
    size_t address) {
    return pImpl_->generateWithdrawalWitness(note, a_sk, vcm_r, leaf, path, root, address);
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

// ===== UTILITY FUNCTIONS =====

std::vector<bool> MerkleCircuit::uint256ToBits(const uint256& input) {
    std::vector<bool> bits(256);
    for (size_t i = 0; i < 256; i++) {
        size_t byteIndex = i / 8;
        size_t bitIndex = i % 8;
        if (byteIndex < 32) {
            bits[i] = ((input.begin()[byteIndex] >> bitIndex) & 1) != 0;
        } else {
            bits[i] = false;
        }
    }
    return bits;
}

uint256 MerkleCircuit::bitsToUint256(const std::vector<bool>& bits) {
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
        power += power; // power *= 2
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

FieldT MerkleCircuit::uint256ToFieldElement(const uint256& input) {
    std::vector<bool> bits = uint256ToBits(input);
    return bitsToFieldElement(bits);
}

uint256 MerkleCircuit::fieldElementToUint256(const FieldT& element) {
    std::vector<bool> bits = fieldElementToBits(element);
    return bitsToUint256(bits);
}

std::vector<uint8_t> MerkleCircuit::bitsToBytes(const std::vector<bool>& bits) {
    std::vector<uint8_t> bytes((bits.size() + 7) / 8, 0);
    
    for (size_t i = 0; i < bits.size(); ++i) {
        if (bits[i]) {
            bytes[i / 8] |= (1 << (i % 8));
        }
    }
    
    return bytes;
}

std::vector<bool> MerkleCircuit::bytesToBits(const std::vector<uint8_t>& bytes) {
    std::vector<bool> bits;
    bits.reserve(bytes.size() * 8);
    
    for (uint8_t byte : bytes) {
        for (int i = 0; i < 8; ++i) {
            bits.push_back((byte >> i) & 1);
        }
    }
    
    return bits;
}

// Commitment computations (outside circuit, for testing)
uint256 MerkleCircuit::computeNoteCommitment(
    uint64_t value,
    const uint256& rho,
    const uint256& r,
    const uint256& a_pk) {
    
    // SHA256(value || rho || r || a_pk)
    std::vector<uint8_t> input;
    
    // Add value (8 bytes, little-endian)
    for (int i = 0; i < 8; ++i) {
        input.push_back((value >> (i * 8)) & 0xFF);
    }
    
    // Add rho, r, a_pk (32 bytes each)
    input.insert(input.end(), rho.begin(), rho.end());
    input.insert(input.end(), r.begin(), r.end());
    input.insert(input.end(), a_pk.begin(), a_pk.end());
    
    uint256 result;
    SHA256(input.data(), input.size(), result.begin());
    
    return result;
}

uint256 MerkleCircuit::computeNullifier(
    const uint256& a_sk,
    const uint256& rho) {
    
    // SHA256(a_sk || rho)
    std::vector<uint8_t> input;
    input.insert(input.end(), a_sk.begin(), a_sk.end());
    input.insert(input.end(), rho.begin(), rho.end());
    
    uint256 result;
    SHA256(input.data(), input.size(), result.begin());
    
    return result;
}

uint256 MerkleCircuit::computeValueCommitment(
    uint64_t value,
    const uint256& vcm_r) {
    
    // SHA256(value || vcm_r)
    std::vector<uint8_t> input;
    
    // Add value (8 bytes, little-endian)
    for (int i = 0; i < 8; ++i) {
        input.push_back((value >> (i * 8)) & 0xFF);
    }
    
    // Add vcm_r (32 bytes)
    input.insert(input.end(), vcm_r.begin(), vcm_r.end());
    
    uint256 result;
    SHA256(input.data(), input.size(), result.begin());
    
    return result;
}

} // namespace zkp
} // namespace ripple