#ifndef BALANCE_CIRCUIT_H
#define BALANCE_CIRCUIT_H

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <memory>
#include <vector>

namespace ripple {
namespace zkp {

// Use alt_bn128 curve
using CurveType = libff::alt_bn128_pp;
using FrType = libff::Fr<CurveType>;

template <typename FieldT>
class BalanceCircuit : public libsnark::gadget<FieldT>
{
private:
    std::vector<libsnark::pb_variable<FieldT>> inputs;
    std::vector<libsnark::pb_variable<FieldT>> outputs;
    libsnark::pb_variable<FieldT> fee;

    // Variables for sums
    libsnark::pb_variable<FieldT> input_sum;
    libsnark::pb_variable<FieldT> output_sum;
    libsnark::pb_variable<FieldT> total_outflow;  // output_sum + fee

    size_t num_inputs;
    size_t num_outputs;

public:
    BalanceCircuit(
        libsnark::protoboard<FieldT>& pb,
        size_t num_inputs,
        size_t num_outputs,
        const std::string& annotation_prefix);

    void
    generate_r1cs_constraints();
    void
    generate_r1cs_witness(
        const std::vector<FieldT>& input_values,
        const std::vector<FieldT>& output_values,
        const FieldT& fee_value);

    // Helper functions
    bool
    is_satisfied() const
    {
        return this->pb.is_satisfied();
    }

    libsnark::r1cs_constraint_system<FieldT>
    get_constraint_system() const
    {
        return this->pb.get_constraint_system();
    }

    libsnark::r1cs_primary_input<FieldT>
    get_primary_input() const
    {
        return this->pb.primary_input();
    }

    libsnark::r1cs_auxiliary_input<FieldT>
    get_auxiliary_input() const
    {
        return this->pb.auxiliary_input();
    }
};

}  // namespace zkp
}  // namespace ripple

#endif  // BALANCE_CIRCUIT_H