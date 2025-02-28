// #ifndef RIPPLE_ZKP_VALUEBALANCECIRCUIT_H_INCLUDED
// #define RIPPLE_ZKP_VALUEBALANCECIRCUIT_H_INCLUDED

// // #include <rippled/src/libxrpl/zkp/Circuit.h>
// #include <libsnark/gadgetlib1/gadget.hpp>
// #include <libsnark/gadgetlib1/protoboard.hpp>
// #include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
// #include <vector>
// #include <memory>

// namespace ripple {

// using namespace libsnark;

// /**
//  * @brief Circuit component that ensures transaction inputs equal outputs
//  * 
//  * The ValueBalanceCircuit validates that the sum of input values equals
//  * the sum of output values plus any transaction fee, without revealing
//  * any of the individual values. It uses Pedersen commitments to preserve
//  * privacy while enforcing balance.
//  */
// template<typename FieldT>
// class ValueBalanceCircuit : public gadget<FieldT> {
// private:
//     // Forward declarations of internal gadgets
//     class PedersenCommitmentGadget;
//     class RangeProofGadget;

//     // Private witnesses (known only to the prover)
//     std::vector<pb_variable<FieldT>> input_values_;
//     std::vector<pb_variable<FieldT>> input_blinding_factors_;
//     std::vector<pb_variable<FieldT>> output_values_;
//     std::vector<pb_variable<FieldT>> output_blinding_factors_;
//     pb_variable<FieldT> balancing_factor_;
    
//     // Public inputs (known to verifiers)
//     std::vector<pb_variable_array<FieldT>> input_commitments_;
//     std::vector<pb_variable_array<FieldT>> output_commitments_;
//     pb_variable<FieldT> transaction_fee_;
    
//     // Pedersen commitment verification gadgets
//     std::vector<std::shared_ptr<PedersenCommitmentGadget>> input_commitment_gadgets_;
//     std::vector<std::shared_ptr<PedersenCommitmentGadget>> output_commitment_gadgets_;
    
//     // Range proof gadgets to prevent overflow
//     std::vector<std::shared_ptr<RangeProofGadget>> input_range_proofs_;
//     std::vector<std::shared_ptr<RangeProofGadget>> output_range_proofs_;
    
//     // Internal helper methods
//     pb_linear_combination<FieldT> sum_variables(const std::vector<pb_variable<FieldT>>& vars) const;

// public:
//     /**
//      * @brief Construct a new Value Balance Circuit
//      * 
//      * @param pb The protoboard this circuit is part of
//      * @param input_values Variables representing input note values (private)
//      * @param input_blinding_factors Blinding factors for input commitments (private)
//      * @param input_commitments The Pedersen commitments for inputs (public)
//      * @param output_values Variables representing output note values (private)
//      * @param output_blinding_factors Blinding factors for output commitments (private)
//      * @param output_commitments The Pedersen commitments for outputs (public)
//      * @param transaction_fee The public transaction fee
//      * @param balancing_factor Additional blinding factor to balance the equation (private)
//      * @param annotation_prefix Prefix for debugging annotations
//      */
//     ValueBalanceCircuit(
//         protoboard<FieldT>& pb,
//         const std::vector<pb_variable<FieldT>>& input_values,
//         const std::vector<pb_variable<FieldT>>& input_blinding_factors,
//         const std::vector<pb_variable_array<FieldT>>& input_commitments,
//         const std::vector<pb_variable<FieldT>>& output_values,
//         const std::vector<pb_variable<FieldT>>& output_blinding_factors,
//         const std::vector<pb_variable_array<FieldT>>& output_commitments,
//         const pb_variable<FieldT>& transaction_fee,
//         const pb_variable<FieldT>& balancing_factor,
//         const std::string& annotation_prefix
//     );

//     /**
//      * @brief Generate constraints for the value balance circuit
//      * 
//      * Creates constraints that enforce:
//      * 1. Each input and output commitment is valid
//      * 2. All values are within a valid range (non-negative)
//      * 3. The sum of input values equals the sum of output values plus the fee
//      * 4. The blinding factors balance out
//      */
//     void generate_r1cs_constraints();

//     /**
//      * @brief Generate the values for all internal variables based on inputs
//      * 
//      * Computes values for all internal circuit variables based on the
//      * provided inputs and outputs.
//      */
//     void generate_r1cs_witness();

//     /**
//      * @brief Get the required balancing factor for a set of inputs and outputs
//      * 
//      * This is a static helper that calculates the balancing factor needed
//      * to make a transaction balance. Useful for transaction creation.
//      * 
//      * @param input_blinding_factors The input blinding factors
//      * @param output_blinding_factors The output blinding factors
//      * @return FieldT The balancing factor needed
//      */
//     static FieldT calculate_balancing_factor(
//         const std::vector<FieldT>& input_blinding_factors,
//         const std::vector<FieldT>& output_blinding_factors
//     );

//     /**
//      * @brief Verify value balance without generating a full proof
//      * 
//      * Checks that the sum of input values equals the sum of output values
//      * plus the transaction fee.
//      * 
//      * @return bool True if values balance, false otherwise
//      */
//     bool verify_balance() const;
// };

// /**
//  * @brief Helper class for Pedersen commitment verification
//  * 
//  * Internal gadget that verifies a Pedersen commitment of the form:
//  * C = value * G + blinding_factor * H
//  */
// template<typename FieldT>
// class ValueBalanceCircuit<FieldT>::PedersenCommitmentGadget : public gadget<FieldT> {
// private:
//     pb_variable<FieldT> value_;
//     pb_variable<FieldT> blinding_factor_;
//     pb_variable_array<FieldT> commitment_;
    
//     // Elliptic curve point variables and gadgets for the commitment
//     // (Implementation details depend on the specific EC operations in libsnark)

// public:
//     PedersenCommitmentGadget(
//         protoboard<FieldT>& pb,
//         const pb_variable<FieldT>& value,
//         const pb_variable<FieldT>& blinding_factor,
//         const pb_variable_array<FieldT>& commitment,
//         const std::string& annotation_prefix
//     );
    
//     void generate_r1cs_constraints();
//     void generate_r1cs_witness();
// };

// /**
//  * @brief Range proof gadget to ensure values are within bounds
//  * 
//  * Ensures that a value is non-negative and fits within a specified bit range
//  * to prevent integer overflow attacks.
//  */
// template<typename FieldT>
// class ValueBalanceCircuit<FieldT>::RangeProofGadget : public gadget<FieldT> {
// private:
//     pb_variable<FieldT> value_;
//     pb_variable_array<FieldT> value_bits_;
//     size_t bit_size_;

// public:
//     RangeProofGadget(
//         protoboard<FieldT>& pb,
//         const pb_variable<FieldT>& value,
//         size_t bit_size,
//         const std::string& annotation_prefix
//     );
    
//     void generate_r1cs_constraints();
//     void generate_r1cs_witness();
// };

// // Support for common field types
// using ValueBalanceCircuitAltBn128 = ValueBalanceCircuit<libff::alt_bn128_Fr>;

// } // namespace ripple

// #endif // RIPPLE_ZKP_VALUEBALANCECIRCUIT_H_INCLUDED