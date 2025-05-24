#pragma once

#include <memory>
#include <vector>
#include <string>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>

namespace ripple {
namespace zkp {

using DefaultCurve = libff::alt_bn128_pp;
using FieldT = libff::Fr<DefaultCurve>;

/**
 * MerkleCircuit
 * -------------
 * A zero-knowledge circuit for proving Merkle tree membership using libsnark's built-in gadgets.
 * Supports constraint generation, witness assignment, and extraction of constraint system and inputs.
 */
class MerkleCircuit
{
public:
    /**
     * Construct a MerkleCircuit for a tree of given depth.
     * @param treeDepth The depth of the Merkle tree (number of levels).
     */
    explicit MerkleCircuit(size_t treeDepth);

    ~MerkleCircuit();

    /**
     * Generate R1CS constraints for Merkle membership proof.
     */
    void generateConstraints();

    /**
     * Assign witness values for a Merkle membership proof.
     * @param leaf         The leaf value (as a vector of bits).
     * @param root         The Merkle root (as a vector of bits).
     * @param spend_key    The spend key (as a vector of bits).
     * @return The full witness vector (primary + auxiliary input).
     */
    std::vector<FieldT> generateDepositWitness(
        const std::vector<bool>& leaf,
        const std::vector<bool>& root,
        const std::vector<bool>& spend_key);

    /**
     * Assign witness values for a Merkle membership proof.
     * @param leaf         The leaf value (as a vector of bits).
     * @param path         The authentication path (vector of sibling hashes, each as bits).
     * @param root         The Merkle root (as a vector of bits).
     * @param spend_key    The spend key (as a vector of bits).
     * @param address      The index of the leaf in the tree (as an integer).
     * @return The full witness vector (primary + auxiliary input).
     */
    std::vector<FieldT> generateWithdrawalWitness(
        const std::vector<bool>& leaf,
        const std::vector<std::vector<bool>>& path,
        const std::vector<bool>& root,
        const std::vector<bool>& spend_key,
        size_t address);

    /**
     * Get the nullifier hash (for advanced use).
     */
    std::vector<bool> getNullifierHash() const;

    /**
     * Get the underlying constraint system.
     */
    libsnark::r1cs_constraint_system<FieldT> getConstraintSystem() const;

    /**
     * Get the primary (public) input for the circuit.
     */
    libsnark::r1cs_primary_input<FieldT> getPrimaryInput() const;

    /**
     * Get the auxiliary (private/witness) input for the circuit.
     */
    libsnark::r1cs_auxiliary_input<FieldT> getAuxiliaryInput() const;

    /**
     * Access the underlying protoboard (for advanced use).
     */
    std::shared_ptr<libsnark::protoboard<FieldT>> getProtoboard() const;

    /**
     * Get the Merkle tree depth.
     */
    size_t getTreeDepth() const;

    /**
     * Utility: Convert a uint256 (32-byte array) to a vector of bits (LSB first).
     */
    static std::vector<bool> uint256ToBits(const std::array<uint8_t, 32>& input);

    /**
     * Utility: Convert a vector of bits (LSB first) to a uint256 (32-byte array).
     */
    static std::array<uint8_t, 32> bitsToUint256(const std::vector<bool>& bits);

    /**
     * Utility: Convert a hex-encoded spend key to a vector of bits.
     * @param spendKey The hex string representing the spend key.
     * @return A vector of bits representing the spend key (LSB first).
     */
    static std::vector<bool> spendKeyToBits(const std::string& spendKey);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

/// Initialize the curve parameters (must be called before using the circuit)
void initCurveParameters();

} // namespace zkp
} // namespace ripple