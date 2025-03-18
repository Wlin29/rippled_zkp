#include "SufficientFundsCircuit.h"

namespace libsnark {

template <typename FieldT>
SufficientFundsCircuit<FieldT>::SufficientFundsCircuit(
    protoboard<FieldT>& pb,
    size_t num_bits)
    : gadget<FieldT>(pb, "SufficientFundsCircuit"), num_bits(num_bits)
{
    // Allocate variables
    balance.allocate(pb, "balance");
    amount.allocate(pb, "amount");
    balance_bits.allocate(pb, num_bits, "balance_bits");
    amount_bits.allocate(pb, num_bits, "amount_bits");
    less.allocate(pb, "less");
    less_or_eq.allocate(pb, "less_or_eq");

    // Create unpacking gadgets
    unpack_balance.reset(new packing_gadget<FieldT>(
        pb, balance_bits, balance, "unpack_balance"));
    unpack_amount.reset(
        new packing_gadget<FieldT>(pb, amount_bits, amount, "unpack_amount"));

    // Create comparison gadget
    // Note: comparison_gadget expects pb_linear_combination, not
    // pb_variable_array
    pb_linear_combination<FieldT> balance_lc;
    pb_linear_combination<FieldT> amount_lc;

    // Convert variables to linear combinations
    balance_lc.assign(pb, balance);
    amount_lc.assign(pb, amount);

    cmp.reset(new comparison_gadget<FieldT>(
        pb, num_bits, amount_lc, balance_lc, less, less_or_eq, "cmp"));
}

template <typename FieldT>
void
SufficientFundsCircuit<FieldT>::generate_r1cs_constraints()
{
    // Generate constraints for unpacking gadgets
    unpack_balance->generate_r1cs_constraints(false);
    unpack_amount->generate_r1cs_constraints(false);

    // Generate constraints for comparison gadget
    cmp->generate_r1cs_constraints();

    // Add constraint: amount <= balance (less_or_eq must be 1)
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(1, less_or_eq, FieldT::one()),
        "less_or_eq == 1");
}

template <typename FieldT>
void
SufficientFundsCircuit<FieldT>::generate_r1cs_witness(
    const FieldT& balance_val,
    const FieldT& amount_val)
{
    // Set the values
    this->pb.val(balance) = balance_val;
    this->pb.val(amount) = amount_val;

    // Generate witness for unpacking
    unpack_balance->generate_r1cs_witness_from_packed();
    unpack_amount->generate_r1cs_witness_from_packed();

    // Generate witness for comparison
    cmp->generate_r1cs_witness();
}

// Explicitly instantiate the template for alt_bn128 field
template class SufficientFundsCircuit<FrType>;

}  // namespace libsnark