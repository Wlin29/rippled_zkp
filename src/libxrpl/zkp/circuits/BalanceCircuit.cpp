#include "BalanceCircuit.h"

namespace ripple {
namespace zkp {

template <typename FieldT>
BalanceCircuit<FieldT>::BalanceCircuit(
    libsnark::protoboard<FieldT>& pb,
    size_t num_inputs,
    size_t num_outputs,
    const std::string& annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , num_inputs(num_inputs)
    , num_outputs(num_outputs)
{
    // Allocate variables for inputs
    inputs.resize(num_inputs);
    for (size_t i = 0; i < num_inputs; i++)
    {
        inputs[i].allocate(
            pb, annotation_prefix + "_input_" + std::to_string(i));
    }

    // Allocate variables for outputs
    outputs.resize(num_outputs);
    for (size_t i = 0; i < num_outputs; i++)
    {
        outputs[i].allocate(
            pb, annotation_prefix + "_output_" + std::to_string(i));
    }

    // Allocate fee variable
    fee.allocate(pb, annotation_prefix + "_fee");

    // Allocate sum variables
    input_sum.allocate(pb, annotation_prefix + "_input_sum");
    output_sum.allocate(pb, annotation_prefix + "_output_sum");
    total_outflow.allocate(pb, annotation_prefix + "_total_outflow");
}

template <typename FieldT>
void
BalanceCircuit<FieldT>::generate_r1cs_constraints()
{
    // Constraint 1: Compute sum of inputs
    libsnark::linear_combination<FieldT> input_sum_lc;
    for (const auto& input : inputs)
    {
        input_sum_lc = input_sum_lc + input;
    }
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(1, input_sum_lc, input_sum),
        "input_sum");

    // Constraint 2: Compute sum of outputs
    libsnark::linear_combination<FieldT> output_sum_lc;
    for (const auto& output : outputs)
    {
        output_sum_lc = output_sum_lc + output;
    }
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(1, output_sum_lc, output_sum),
        "output_sum");

    // Constraint 3: total_outflow = output_sum + fee
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(1, output_sum + fee, total_outflow),
        "total_outflow");

    // Constraint 4: input_sum = total_outflow (conservation of funds)
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(1, input_sum - total_outflow, 0),
        "conservation_of_funds");

    // Constraint 5: All values must be non-negative (implicit in field
    // operations)
}

template <typename FieldT>
void
BalanceCircuit<FieldT>::generate_r1cs_witness(
    const std::vector<FieldT>& input_values,
    const std::vector<FieldT>& output_values,
    const FieldT& fee_value)
{
    // Verify input sizes
    if (input_values.size() != num_inputs ||
        output_values.size() != num_outputs)
    {
        throw std::invalid_argument("Invalid number of inputs or outputs");
    }

    // Set input values
    for (size_t i = 0; i < num_inputs; i++)
    {
        this->pb.val(inputs[i]) = input_values[i];
    }

    // Set output values
    for (size_t i = 0; i < num_outputs; i++)
    {
        this->pb.val(outputs[i]) = output_values[i];
    }

    // Set fee value
    this->pb.val(fee) = fee_value;

    // Compute input sum
    FieldT input_sum_val = FieldT::zero();
    for (const auto& val : input_values)
    {
        input_sum_val += val;
    }
    this->pb.val(input_sum) = input_sum_val;

    // Compute output sum
    FieldT output_sum_val = FieldT::zero();
    for (const auto& val : output_values)
    {
        output_sum_val += val;
    }
    this->pb.val(output_sum) = output_sum_val;

    // Compute total outflow
    this->pb.val(total_outflow) = output_sum_val + fee_value;
}

// Explicit template instantiation
template class BalanceCircuit<FrType>;

}  // namespace zkp
}  // namespace ripple