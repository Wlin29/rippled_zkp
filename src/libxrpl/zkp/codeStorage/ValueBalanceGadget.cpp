// #include "ValueBalanceGadget.h"
// #include "PedersenCommitment.h"
// #include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
// #include <libff/common/profiling.hpp>
// #include <libsnark/gadgetlib1/gadget.hpp>
// #include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
// #include <libsnark/gadgetlib1/protoboard.hpp>

// namespace ripple {

// template <typename FieldT>
// ValueBalanceCircuit<FieldT>::ValueBalanceCircuit(
//     protoboard<FieldT>& pb,
//     const std::vector<pb_variable<FieldT>>& input_values,
//     const std::vector<pb_variable<FieldT>>& input_blinding_factors,
//     const std::vector<pb_variable_array<FieldT>>& input_commitments,
//     const std::vector<pb_variable<FieldT>>& output_values,
//     const std::vector<pb_variable<FieldT>>& output_blinding_factors,
//     const std::vector<pb_variable_array<FieldT>>& output_commitments,
//     const pb_variable<FieldT>& transaction_fee,
//     const pb_variable<FieldT>& balancing_factor,
//     const std::string& annotation_prefix)
//     : gadget<FieldT>(pb, annotation_prefix)
//     , input_values_(input_values)
//     , input_blinding_factors_(input_blinding_factors)
//     , input_commitments_(input_commitments)
//     , output_values_(output_values)
//     , output_blinding_factors_(output_blinding_factors)
//     , output_commitments_(output_commitments)
//     , transaction_fee_(transaction_fee)
//     , balancing_factor_(balancing_factor)
// {
//     // Validate input parameters
//     if (input_values.size() != input_blinding_factors.size() ||
//         input_values.size() != input_commitments.size())
//     {
//         throw std::invalid_argument(
//             "Input arrays must have matching dimensions");
//     }

//     if (output_values.size() != output_blinding_factors.size() ||
//         output_values.size() != output_commitments.size())
//     {
//         throw std::invalid_argument(
//             "Output arrays must have matching dimensions");
//     }

//     // Initialize commitment verification gadgets for inputs
//     for (size_t i = 0; i < input_values.size(); i++)
//     {
//         input_commitment_gadgets_.push_back(
//             std::make_shared<PedersenCommitmentGadget>(
//                 pb,
//                 input_values[i],
//                 input_blinding_factors[i],
//                 input_commitments[i],
//                 FMT(annotation_prefix, " input_commit_%zu", i)));

//         // Create range proof for each input value (limit to 64 bits)
//         input_range_proofs_.push_back(std::make_shared<RangeProofGadget>(
//             pb,
//             input_values[i],
//             64,  // 64-bit range constraint
//             FMT(annotation_prefix, " input_range_%zu", i)));
//     }

//     // Initialize commitment verification gadgets for outputs
//     for (size_t i = 0; i < output_values.size(); i++)
//     {
//         output_commitment_gadgets_.push_back(
//             std::make_shared<PedersenCommitmentGadget>(
//                 pb,
//                 output_values[i],
//                 output_blinding_factors[i],
//                 output_commitments[i],
//                 FMT(annotation_prefix, " output_commit_%zu", i)));

//         // Create range proof for each output value (limit to 64 bits)
//         output_range_proofs_.push_back(std::make_shared<RangeProofGadget>(
//             pb,
//             output_values[i],
//             64,  // 64-bit range constraint
//             FMT(annotation_prefix, " output_range_%zu", i)));
//     }
// }

// template <typename FieldT>
// void
// ValueBalanceCircuit<FieldT>::generate_r1cs_constraints()
// {
//     libff::enter_block(
//         FMT(this->annotation_prefix, " generate_r1cs_constraints"));

//     // Generate constraints for all commitment verification gadgets
//     for (auto& gadget : input_commitment_gadgets_)
//     {
//         gadget->generate_r1cs_constraints();
//     }

//     for (auto& gadget : output_commitment_gadgets_)
//     {
//         gadget->generate_r1cs_constraints();
//     }

//     // Generate constraints for all range proofs
//     for (auto& range_proof : input_range_proofs_)
//     {
//         range_proof->generate_r1cs_constraints();
//     }

//     for (auto& range_proof : output_range_proofs_)
//     {
//         range_proof->generate_r1cs_constraints();
//     }

//     // Value balance constraint
//     // sum(input_values) = sum(output_values) + transaction_fee
//     pb_linear_combination<FieldT> sum_inputs = sum_variables(input_values_);
//     pb_linear_combination<FieldT> sum_outputs_with_fee =
//         sum_variables(output_values_);
//     sum_outputs_with_fee = sum_outputs_with_fee + transaction_fee_;

//     this->pb.add_r1cs_constraint(
//         r1cs_constraint<FieldT>(sum_inputs, 1, sum_outputs_with_fee),
//         FMT(this->annotation_prefix, " value_balance"));

//     // Blinding factor balance constraint
//     // sum(input_blinding_factors) = sum(output_blinding_factors) +
//     // balancing_factor
//     pb_linear_combination<FieldT> sum_input_blindings =
//         sum_variables(input_blinding_factors_);
//     pb_linear_combination<FieldT> sum_output_blindings =
//         sum_variables(output_blinding_factors_);
//     sum_output_blindings = sum_output_blindings + balancing_factor_;

//     this->pb.add_r1cs_constraint(
//         r1cs_constraint<FieldT>(sum_input_blindings, 1, sum_output_blindings),
//         FMT(this->annotation_prefix, " blinding_balance"));

//     libff::leave_block(
//         FMT(this->annotation_prefix, " generate_r1cs_constraints"));
// }

// template <typename FieldT>
// void
// ValueBalanceCircuit<FieldT>::generate_r1cs_witness()
// {
//     libff::enter_block(FMT(this->annotation_prefix, " generate_r1cs_witness"));

//     // Generate witness values for all commitment gadgets
//     for (auto& gadget : input_commitment_gadgets_)
//     {
//         gadget->generate_r1cs_witness();
//     }

//     for (auto& gadget : output_commitment_gadgets_)
//     {
//         gadget->generate_r1cs_witness();
//     }

//     // Generate witness values for all range proofs
//     for (auto& range_proof : input_range_proofs_)
//     {
//         range_proof->generate_r1cs_witness();
//     }

//     for (auto& range_proof : output_range_proofs_)
//     {
//         range_proof->generate_r1cs_witness();
//     }

//     // Calculate balancing factor if it's not already set
//     if (this->pb.val(balancing_factor_) == FieldT::zero())
//     {
//         // Compute sum of input blinding factors
//         FieldT sum_input_blindings = FieldT::zero();
//         for (const auto& var : input_blinding_factors_)
//         {
//             sum_input_blindings = sum_input_blindings + this->pb.val(var);
//         }

//         // Compute sum of output blinding factors
//         FieldT sum_output_blindings = FieldT::zero();
//         for (const auto& var : output_blinding_factors_)
//         {
//             sum_output_blindings = sum_output_blindings + this->pb.val(var);
//         }

//         // Set balancing factor value
//         this->pb.val(balancing_factor_) =
//             sum_input_blindings - sum_output_blindings;
//     }

//     libff::leave_block(FMT(this->annotation_prefix, " generate_r1cs_witness"));
// }

// template <typename FieldT>
// pb_linear_combination<FieldT>
// ValueBalanceCircuit<FieldT>::sum_variables(
//     const std::vector<pb_variable<FieldT>>& vars) const
// {
//     pb_linear_combination<FieldT> result;
//     for (const auto& var : vars)
//     {
//         result = result + var;
//     }
//     return result;
// }

// template <typename FieldT>
// FieldT
// ValueBalanceCircuit<FieldT>::calculate_balancing_factor(
//     const std::vector<FieldT>& input_blinding_factors,
//     const std::vector<FieldT>& output_blinding_factors)
// {
//     FieldT sum_inputs = std::accumulate(
//         input_blinding_factors.begin(),
//         input_blinding_factors.end(),
//         FieldT::zero());

//     FieldT sum_outputs = std::accumulate(
//         output_blinding_factors.begin(),
//         output_blinding_factors.end(),
//         FieldT::zero());

//     return sum_inputs - sum_outputs;
// }

// template <typename FieldT>
// bool
// ValueBalanceCircuit<FieldT>::verify_balance() const
// {
//     // Calculate sum of input values
//     FieldT sum_inputs = FieldT::zero();
//     for (const auto& var : input_values_)
//     {
//         sum_inputs = sum_inputs + this->pb.val(var);
//     }

//     // Calculate sum of output values
//     FieldT sum_outputs = FieldT::zero();
//     for (const auto& var : output_values_)
//     {
//         sum_outputs = sum_outputs + this->pb.val(var);
//     }

//     // Add transaction fee
//     sum_outputs = sum_outputs + this->pb.val(transaction_fee_);

//     // Check if values balance
//     return sum_inputs == sum_outputs;
// }

// // Implementation of PedersenCommitmentGadget

// template <typename FieldT>
// ValueBalanceCircuit<FieldT>::PedersenCommitmentGadget::PedersenCommitmentGadget(
//     protoboard<FieldT>& pb,
//     const pb_variable<FieldT>& value,
//     const pb_variable<FieldT>& blinding_factor,
//     const pb_variable_array<FieldT>& commitment,
//     const std::string& annotation_prefix)
//     : gadget<FieldT>(pb, annotation_prefix)
//     , value_(value)
//     , blinding_factor_(blinding_factor)
//     , commitment_(commitment)
// {
//     // Commitment should be 2 field elements (x and y coordinates of the EC
//     // point)
//     if (commitment.size() != 2)
//     {
//         throw std::invalid_argument(
//             "Pedersen commitment must be a point (2 field elements)");
//     }
// }

// template <typename FieldT>
// void
// ValueBalanceCircuit<
//     FieldT>::PedersenCommitmentGadget::generate_r1cs_constraints()
// {
//     libff::enter_block(
//         FMT(this->annotation_prefix, " generate_r1cs_constraints"));

//     // These constraints implement the operation:
//     // commitment = value * G + blinding_factor * H
//     // where G and H are fixed generator points

//     // The actual constraint implementation depends on the elliptic curve
//     // operations and how they're represented in the R1CS system. This is a
//     // simplified version.

//     // In practice, this would involve:
//     // 1. Scalar multiplication of value with generator G
//     // 2. Scalar multiplication of blinding_factor with generator H
//     // 3. Point addition of the two results
//     // 4. Constraint that the result equals the commitment point

//     // To demonstrate implementation pattern (actual EC math would be more
//     // complex):

//     // 1. Get the fixed generator points (these would be defined elsewhere)
//     FieldT G_x = PedersenCommitment<FieldT>::get_G_x();
//     FieldT G_y = PedersenCommitment<FieldT>::get_G_y();
//     FieldT H_x = PedersenCommitment<FieldT>::get_H_x();
//     FieldT H_y = PedersenCommitment<FieldT>::get_H_y();

//     // 2. Create variables for the intermediate points
//     pb_variable<FieldT> value_times_G_x =
//         this->pb.allocate_variable(FMT(this->annotation_prefix, " value_times_G_x"));
//     pb_variable<FieldT> value_times_G_y =
//         this->pb.allocate_variable(FMT(this->annotation_prefix, " value_times_G_y"));
//     pb_variable<FieldT> blinding_times_H_x = this->pb.allocate_variable(
//         FMT(this->annotation_prefix, " blinding_times_H_x"));
//     pb_variable<FieldT> blinding_times_H_y = this->pb.allocate_variable(
//         FMT(this->annotation_prefix, " blinding_times_H_y"));

//     // 3. Create constraints for scalar multiplication
//     // (These would actually use EC multiplication gadgets in practice)
//     this->pb.add_r1cs_constraint(
//         r1cs_constraint<FieldT>(value_, G_x, value_times_G_x),
//         FMT(this->annotation_prefix, " value_times_G_x"));
//     this->pb.add_r1cs_constraint(
//         r1cs_constraint<FieldT>(value_, G_y, value_times_G_y),
//         FMT(this->annotation_prefix, " value_times_G_y"));
//     this->pb.add_r1cs_constraint(
//         r1cs_constraint<FieldT>(blinding_factor_, H_x, blinding_times_H_x),
//         FMT(this->annotation_prefix, " blinding_times_H_x"));
//     this->pb.add_r1cs_constraint(
//         r1cs_constraint<FieldT>(blinding_factor_, H_y, blinding_times_H_y),
//         FMT(this->annotation_prefix, " blinding_times_H_y"));

//     // 4. Create constraints for point addition
//     // (This is a major simplification; actual EC addition is more complex)
//     this->pb.add_r1cs_constraint(
//         r1cs_constraint<FieldT>(
//             value_times_G_x + blinding_times_H_x, 1, commitment_[0]),
//         FMT(this->annotation_prefix, " commitment_x"));
//     this->pb.add_r1cs_constraint(
//         r1cs_constraint<FieldT>(
//             value_times_G_y + blinding_times_H_y, 1, commitment_[1]),
//         FMT(this->annotation_prefix, " commitment_y"));

//     libff::leave_block(
//         FMT(this->annotation_prefix, " generate_r1cs_constraints"));
// }

// template <typename FieldT>
// void
// ValueBalanceCircuit<FieldT>::PedersenCommitmentGadget::generate_r1cs_witness()
// {
//     libff::enter_block(FMT(this->annotation_prefix, " generate_r1cs_witness"));

//     // In a real implementation, this would use the EC operations to compute
//     // the Pedersen commitment: value * G + blinding_factor * H

//     // Get the values from the protoboard
//     FieldT value = this->pb.val(value_);
//     FieldT blinding = this->pb.val(blinding_factor_);

//     // Compute the actual commitment using the PedersenCommitment utility
//     auto commitment_point = PedersenCommitment<FieldT>::commit(value, blinding);

//     // Set the commitment values in the protoboard
//     this->pb.val(commitment_[0]) = commitment_point.first;   // x-coordinate
//     this->pb.val(commitment_[1]) = commitment_point.second;  // y-coordinate

//     // Also set intermediate values for scalar multiplications
//     FieldT G_x = PedersenCommitment<FieldT>::get_G_x();
//     FieldT G_y = PedersenCommitment<FieldT>::get_G_y();
//     FieldT H_x = PedersenCommitment<FieldT>::get_H_x();
//     FieldT H_y = PedersenCommitment<FieldT>::get_H_y();

//     // Set intermediate values (simplified for illustration)
//     this->pb.val(this->pb.get_variable_by_name(
//         FMT(this->annotation_prefix, " value_times_G_x"))) = value * G_x;
//     this->pb.val(this->pb.get_variable_by_name(
//         FMT(this->annotation_prefix, " value_times_G_y"))) = value * G_y;
//     this->pb.val(this->pb.get_variable_by_name(
//         FMT(this->annotation_prefix, " blinding_times_H_x"))) = blinding * H_x;
//     this->pb.val(this->pb.get_variable_by_name(
//         FMT(this->annotation_prefix, " blinding_times_H_y"))) = blinding * H_y;

//     libff::leave_block(FMT(this->annotation_prefix, " generate_r1cs_witness"));
// }

// // Implementation of RangeProofGadget

// template <typename FieldT>
// ValueBalanceCircuit<FieldT>::RangeProofGadget::RangeProofGadget(
//     protoboard<FieldT>& pb,
//     const pb_variable<FieldT>& value,
//     size_t bit_size,
//     const std::string& annotation_prefix)
//     : gadget<FieldT>(pb, annotation_prefix), value_(value), bit_size_(bit_size)
// {
//     // Allocate variables for the bits
//     value_bits_.allocate(pb, bit_size, FMT(annotation_prefix, " value_bits"));
// }

// template <typename FieldT>
// void
// ValueBalanceCircuit<FieldT>::RangeProofGadget::generate_r1cs_constraints()
// {
//     libff::enter_block(
//         FMT(this->annotation_prefix, " generate_r1cs_constraints"));

//     // Constrain bits to be 0 or 1
//     for (size_t i = 0; i < bit_size_; i++)
//     {
//         // Boolean constraint: bit * (1 - bit) = 0
//         this->pb.add_r1cs_constraint(
//             r1cs_constraint<FieldT>(value_bits_[i], 1 - value_bits_[i], 0),
//             FMT(this->annotation_prefix, " bit_%zu_boolean", i));
//     }

//     // Pack the bits to form the value
//     this->pb.add_r1cs_constraint(
//         r1cs_constraint<FieldT>(pb_packing_sum<FieldT>(value_bits_), 1, value_),
//         FMT(this->annotation_prefix, " bits_to_value"));

//     libff::leave_block(
//         FMT(this->annotation_prefix, " generate_r1cs_constraints"));
// }

// template <typename FieldT>
// void
// ValueBalanceCircuit<FieldT>::RangeProofGadget::generate_r1cs_witness()
// {
//     libff::enter_block(FMT(this->annotation_prefix, " generate_r1cs_witness"));

//     // Get the value
//     FieldT value = this->pb.val(value_);

//     // Convert value to bits
//     std::vector<bool> bits;

//     // Extract bits from the value
//     FieldT remainder = value;
//     for (size_t i = 0; i < bit_size_; i++)
//     {
//         FieldT bit_value = remainder % FieldT(2);
//         remainder = remainder / FieldT(2);
//         bits.push_back(bit_value == FieldT::one());
//     }

//     // Ensure all remaining bits are zero
//     if (remainder != FieldT::zero())
//     {
//         throw std::runtime_error("Value exceeds the range constraint");
//     }

//     // Assign bit values
//     this->pb.val(value_bits_) = bits;

//     libff::leave_block(FMT(this->annotation_prefix, " generate_r1cs_witness"));
// }

// // Explicit template instantiations for common field types
// template class ValueBalanceCircuit<libff::alt_bn128_Fr>;

// }  // namespace ripple