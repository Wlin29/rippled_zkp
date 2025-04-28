#ifndef MERKLE_CIRCUIT_H
#define MERKLE_CIRCUIT_H

#include <memory>
#include <string>
#include <vector>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>

namespace ripple {
namespace zkp {

// Use the BN-128 curve as defined in ZKProver
using DefaultCurve = libff::alt_bn128_pp;
using FieldT = libff::Fr<DefaultCurve>;

/**
 * MerkleCircuit - Creates and manages zero-knowledge proofs for Merkle tree operations
 * 
 * This circuit handles both deposit and withdrawal operations for confidential transactions,
 * providing cryptographic proof of membership in the shielded pool Merkle tree.
 */
class MerkleCircuit {
public:
    /**
     * Constructor for the Merkle circuit
     * @param treeDepth The depth of the Merkle tree being used
     */
    MerkleCircuit(size_t treeDepth);
    
    /**
     * Destructor
     */
    ~MerkleCircuit();
    
    /**
     * Generate the constraints for the circuit
     * This creates the mathematical framework for the zero-knowledge proof
     */
    void generateConstraints();
    
    /**
     * Generate a witness for standard Merkle tree membership verification
     * 
     * @param leaf The leaf commitment data as bit vector
     * @param path The authentication path as a vector of bit vectors
     * @param root The Merkle root as a bit vector
     * @param leafIndex The index of the leaf in the tree
     */
    void generateWitness(
        const std::vector<bool>& leaf,
        const std::vector<std::vector<bool>>& path,
        const std::vector<bool>& root,
        size_t leafIndex);
    
    /**
     * Generate a witness specifically for deposit operations
     * 
     * @param commitment The commitment as a bit vector
     * @param root The Merkle root as a bit vector
     * @param amount The deposit amount
     */
    void generateDepositWitness(
        const std::vector<bool>& commitment,
        const std::vector<bool>& root,
        uint64_t amount);
    
    /**
     * Get the constraint system for this circuit
     * @return The constraint system
     */
    libsnark::r1cs_constraint_system<FieldT> getConstraintSystem() const;
    
    /**
     * Get the primary input (public variables) for this circuit
     * @return The primary input
     */
    libsnark::r1cs_primary_input<FieldT> getPrimaryInput() const;
    
    /**
     * Get the auxiliary input (private witness) for this circuit
     * @return The auxiliary input
     */
    libsnark::r1cs_auxiliary_input<FieldT> getAuxiliaryInput() const;

private:
    /**
     * Helper method to set path bits based on leaf index
     * @param leafIndex The index of the leaf in the tree
     */
    void setPathBits(size_t leafIndex);
    
    // Member variables
    size_t treeDepth_;
    std::shared_ptr<libsnark::protoboard<FieldT>> pb_;
    
    // Using void pointers to hide implementation details and avoid header issues
    // These will be properly cast in the .cpp file
    void* leafHash_;
    void* rootHash_;
    void* pathVars_;
    void* merkleGadget_;
    void* amount_;
};

/**
 * Initialize cryptographic curve parameters
 */
inline void initCurveParameters() {
    static bool initialized = false;
    if (!initialized) {
        DefaultCurve::init_public_params();
        initialized = true;
    }
}

} // namespace zkp
} // namespace ripple

#endif // MERKLE_CIRCUIT_H