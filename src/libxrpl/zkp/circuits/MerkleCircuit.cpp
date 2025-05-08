#include "MerkleCircuit.h"
#include <libsnark/gadgetlib1/pb_variable.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
#include <algorithm>
#include <cassert>

namespace ripple {
namespace zkp {

using libsnark::pb_variable;
using libsnark::pb_variable_array;
using libsnark::digest_variable;
using libsnark::merkle_authentication_path_variable;
using libsnark::merkle_tree_check_read_gadget;
using libsnark::pb_linear_combination;
using libsnark::pb_linear_combination_array;

void initCurveParameters() {
    static bool initialized = false;
    if (!initialized) {
        DefaultCurve::init_public_params();
        initialized = true;
    }
}

class MerkleCircuit::Impl {
public:
    size_t tree_depth_;
    std::shared_ptr<libsnark::protoboard<FieldT>> pb_;
    std::unique_ptr<digest_variable<FieldT>> leaf_;
    std::unique_ptr<digest_variable<FieldT>> root_;
    using HashT = libsnark::sha256_two_to_one_hash_gadget<FieldT>;
    std::unique_ptr<merkle_authentication_path_variable<FieldT, HashT>> path_;
    std::unique_ptr<merkle_tree_check_read_gadget<FieldT, HashT>> check_read_gadget_;
    pb_linear_combination_array<FieldT> address_bits_;
    pb_linear_combination<FieldT> read_successful_;

    Impl(size_t tree_depth)
        : tree_depth_(tree_depth),
        pb_(std::make_shared<libsnark::protoboard<FieldT>>())
    {
        pb_->set_input_sizes(256);

        leaf_ = std::make_unique<digest_variable<FieldT>>(*pb_, 256, "leaf");
        root_ = std::make_unique<digest_variable<FieldT>>(*pb_, 256, "root");
        path_ = std::make_unique<merkle_authentication_path_variable<FieldT, HashT>>(*pb_, tree_depth_, "path");

        pb_variable_array<FieldT> address_bits_var;
        address_bits_var.allocate(*pb_, tree_depth_, "address_bits");
        address_bits_ = pb_linear_combination_array<FieldT>(address_bits_var);

        pb_variable<FieldT> read_successful_var;
        read_successful_var.allocate(*pb_, "read_successful");
        read_successful_ = read_successful_var;

        check_read_gadget_ = std::make_unique<merkle_tree_check_read_gadget<FieldT, HashT>>(
            *pb_,
            tree_depth_,
            address_bits_,
            *leaf_,
            *root_,
            *path_,
            read_successful_,
            "merkle_check"
        );
    }


    void generateConstraints() {
        check_read_gadget_->generate_r1cs_constraints();
    }

    void generateWitness(
        const std::vector<bool>& leaf,
        const std::vector<std::vector<bool>>& path,
        const std::vector<bool>& root,
        size_t address)
    {
        assert(leaf.size() == 256);
        assert(root.size() == 256);
        assert(path.size() == tree_depth_);
        for (const auto& node : path) {
            assert(node.size() == 256);
        }

        leaf_->generate_r1cs_witness(leaf);
        root_->generate_r1cs_witness(root);
        path_->generate_r1cs_witness(address, path);
        check_read_gadget_->generate_r1cs_witness();
    }

    std::vector<FieldT> generateDepositWitness(
        const std::vector<bool>& leaf,
        const std::vector<bool>& root)
    {
        std::vector<std::vector<bool>> dummyPath(tree_depth_, std::vector<bool>(256, false));
        generateWitness(leaf, dummyPath, root, 0);

        auto witness = pb_->primary_input();
        witness.insert(witness.end(), pb_->auxiliary_input().begin(), pb_->auxiliary_input().end());
        return witness;
    }

    std::vector<FieldT> generateWithdrawalWitness(
        const std::vector<bool>& leaf,
        const std::vector<std::vector<bool>>& path,
        const std::vector<bool>& root,
        size_t address)
    {
        generateWitness(leaf, path, root, address);

        auto witness = pb_->primary_input();
        witness.insert(witness.end(), pb_->auxiliary_input().begin(), pb_->auxiliary_input().end());
        return witness;
    }

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
    size_t getTreeDepth() const {
        return tree_depth_;
    }
};

MerkleCircuit::MerkleCircuit(size_t treeDepth)
    : pImpl_(std::make_unique<Impl>(treeDepth))
{
    initCurveParameters();
}

MerkleCircuit::~MerkleCircuit() = default;

void MerkleCircuit::generateConstraints() {
    pImpl_->generateConstraints();
}

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

std::vector<bool> MerkleCircuit::uint256ToBits(const std::array<uint8_t, 32>& input) {
    std::vector<bool> bits(256);
    for (size_t i = 0; i < 256; ++i) {
        size_t byteIndex = i / 8;
        size_t bitIndex = i % 8;
        bits[i] = (input[byteIndex] >> bitIndex) & 1;
    }
    return bits;
}

std::array<uint8_t, 32> MerkleCircuit::bitsToUint256(const std::vector<bool>& bits) {
    std::array<uint8_t, 32> out{};
    for (size_t i = 0; i < std::min(bits.size(), size_t(256)); ++i) {
        size_t byteIndex = i / 8;
        size_t bitIndex = i % 8;
        if (bits[i])
            out[byteIndex] |= (1 << bitIndex);
    }
    return out;
}


} // namespace zkp
} // namespace ripple
