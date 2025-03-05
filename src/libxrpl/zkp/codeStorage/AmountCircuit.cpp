// #include "AmountCircuit.h"
// #include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>

// template <typename FieldT>
// AmountCircuit<FieldT>::AmountCircuit(
//     libsnark::protoboard<FieldT>& pb,
//     const libsnark::pb_variable<FieldT>& x,
//     const libsnark::pb_variable<FieldT>& max_amount)
//     : libsnark::gadget<FieldT>(pb, "AmountCircuit")
//     , x(x)
//     , max_amount(max_amount)
// {
//     // Allocate the slack variable in the constructor
//     slack.allocate(pb, "slack");
// }

// template <typename FieldT>
// void
// AmountCircuit<FieldT>::generate_r1cs_constraints()
// {
//     // x + slack = max_amount
//     this->pb.add_r1cs_constraint(
//         libsnark::r1cs_constraint<FieldT>(1, x + slack, max_amount));

//     // Ensure slack ≥ 0
//     this->pb.add_r1cs_constraint(
//         libsnark::r1cs_constraint<FieldT>(slack, 1, slack * 1));
// }

// template <typename FieldT>
// void
// AmountCircuit<FieldT>::generate_r1cs_witness(
//     const FieldT& x_val,
//     const FieldT& max)
// {
//     this->pb.val(x) = x_val;
//     this->pb.val(max_amount) = max;

//     this->pb.val(slack) = max - x_val;
// }

// #include <libff/algebra/curves/bn128/bn128_pp.hpp>
// template class AmountCircuit<libff::Fp_model<4l, libff::bn128_modulus_r>>;