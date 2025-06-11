#pragma once

#include <memory>
#include <vector>
#include <string>
#include <array>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>


namespace ripple {
namespace zkp {

using DefaultCurve = libff::alt_bn128_pp;
using FieldT = libff::Fr<DefaultCurve>;

// Forward declarations for libsnark types
using libsnark::digest_variable;
using libsnark::block_variable;
using libsnark::sha256_compression_function_gadget;
using libsnark::sha256_two_to_one_hash_gadget;
using libsnark::merkle_authentication_path_variable;
using libsnark::merkle_tree_check_read_gadget;

/**
 * MerkleCircuit with Value Commitment
 * -------------------------------------------------
 * A zero-knowledge circuit for proving Merkle tree membership with value commitments.
 * Implements Zcash-style commitments using SHA256 compression functions.
 * 
 * Public inputs: [anchor, nullifier, value_commitment]
 * Private inputs: [value, value_randomness, spend_key, rho, address_bits, auth_path]
 * 
 * SHA256-based constraints:
 * - value_commitment = SHA256(value_bits || value_randomness_bits)
 * - nullifier = SHA256(spend_key_bits || rho_bits)
 * - note_commitment = SHA256(value_bits || spend_key_bits || rho_bits)
 * - Merkle path verification: note_commitment ∈ tree with root = anchor
 * - Boolean constraints: all bits ∈ {0,1}
 */
class MerkleCircuit
{
public:
    /**
     * Construct a Zcash-style MerkleCircuit for a tree of given depth.
     * @param treeDepth The depth of the Merkle tree (number of levels).
     */
    explicit MerkleCircuit(size_t treeDepth);

    ~MerkleCircuit();

    /**
     * Generate R1CS constraints for the Zcash-style circuit.
     * Creates constraints for:
     * - SHA256 value commitment
     * - SHA256 nullifier derivation  
     * - SHA256 leaf commitment
     * - Merkle tree path verification
     * - Range and boolean constraints
     */
    void generateConstraints();

    /**
     * Generate witness for deposit proof (Zcash-style).
     * @param value The note value (uint64)
     * @param value_randomness Random value for value commitment (hiding)
     * @param leaf The leaf commitment (as bits)
     * @param root The Merkle root (as bits) 
     * @param spend_key The spend key (as bits, secret)
     * @return The full witness vector (auxiliary input)
     */
    std::vector<FieldT> generateDepositWitness(
        uint64_t value,
        const FieldT& value_randomness,
        const std::vector<bool>& leaf,
        const std::vector<bool>& root,
        const std::vector<bool>& spend_key);

    /**
     * Generate witness for withdrawal proof (Zcash-style).
     * @param value The note value (uint64)
     * @param value_randomness Random value for value commitment (hiding)
     * @param leaf The leaf commitment (as bits)
     * @param path The authentication path (vector of 256-bit hashes)
     * @param root The Merkle root (as bits)
     * @param spend_key The spend key (as bits, secret)
     * @param address The leaf index in the tree
     * @return The full witness vector (auxiliary input)
     */
    std::vector<FieldT> generateWithdrawalWitness(
        uint64_t value,
        const FieldT& value_randomness,
        const std::vector<bool>& leaf,
        const std::vector<std::vector<bool>>& path,
        const std::vector<bool>& root,
        const std::vector<bool>& spend_key,
        size_t address);

    /**
     * Get the computed nullifier field element.
     * nullifier = SHA256(spend_key || rho) converted to field element
     */
    FieldT getNullifier() const;

    /**
     * Get the computed value commitment field element.
     * value_commitment = SHA256(value || value_randomness) converted to field element
     */
    FieldT getValueCommitment() const;

    /**
     * Get the anchor (root) field element.
     * anchor = Merkle root converted to field element
     */
    FieldT getAnchor() const;

    /**
     * Get the underlying R1CS constraint system.
     * Contains all the cryptographic constraints for the Zcash-style circuit.
     */
    libsnark::r1cs_constraint_system<FieldT> getConstraintSystem() const;

    /**
     * Get the primary (public) input for the circuit.
     * Format: [anchor, nullifier, value_commitment]
     */
    libsnark::r1cs_primary_input<FieldT> getPrimaryInput() const;

    /**
     * Get the auxiliary (private/witness) input for the circuit.
     * Contains all secret values and intermediate computations.
     */
    libsnark::r1cs_auxiliary_input<FieldT> getAuxiliaryInput() const;

    /**
     * Access the underlying protoboard (for advanced use).
     * Provides direct access to the constraint system builder.
     */
    std::shared_ptr<libsnark::protoboard<FieldT>> getProtoboard() const;

    /**
     * Get the Merkle tree depth.
     */
    size_t getTreeDepth() const;

    /**
     * Utility: Convert a uint256 (32-byte array) to a vector of bits (LSB first).
     * Used for converting hash values to circuit inputs.
     */
    static std::vector<bool> uint256ToBits(const std::array<uint8_t, 32>& input);

    /**
     * Utility: Convert a vector of bits (LSB first) to a uint256 (32-byte array).
     * Used for converting circuit outputs back to hash values.
     */
    static std::array<uint8_t, 32> bitsToUint256(const std::vector<bool>& bits);

    /**
     * Utility: Convert a hex-encoded spend key to a vector of bits.
     * @param spendKey The hex string representing the spend key.
     * @return A vector of bits representing the spend key (LSB first).
     */
    static std::vector<bool> spendKeyToBits(const std::string& spendKey);

    /**
     * Utility: Convert a vector of bits to a field element.
     * Uses binary representation: element = sum(bits[i] * 2^i)
     */
    static FieldT bitsToFieldElement(const std::vector<bool>& bits);
    
    /**
     * Utility: Convert a field element to a vector of bits.
     * Decomposes element into binary representation.
     */
    static std::vector<bool> fieldElementToBits(const FieldT& element);

    /**
    * Utility: Convert a vector of bits to a 32-byte array (for SHA256 input)
    */
    static std::array<uint8_t, 32> bitsToBytes(const std::vector<bool>& bits);

    /**
    * Utility: Convert a 32-byte array to a vector of bits
    */
    static std::vector<bool> bytesToBits(const std::array<uint8_t, 32>& bytes);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

/**
 * Initialize the elliptic curve parameters for alt_bn128.
 * Must be called before using any MerkleCircuit instances.
 * Thread-safe and idempotent.
 */
void initCurveParameters();

} // namespace zkp
} // namespace ripple