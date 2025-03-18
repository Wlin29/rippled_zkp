#ifndef SUFFICIENT_FUNDS_CIRCUIT_H
#define SUFFICIENT_FUNDS_CIRCUIT_H

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <memory>

namespace libsnark {

// Use alt_bn128 curve explicitly instead of default_r1cs_ppzksnark_pp
using CurveType = libff::alt_bn128_pp;
using FrType = libff::Fr<CurveType>;

template <typename FieldT>
class SufficientFundsCircuit : public gadget<FieldT>
{
private:
    pb_variable<FieldT> balance;
    pb_variable<FieldT> amount;
    pb_variable_array<FieldT> balance_bits;
    pb_variable_array<FieldT> amount_bits;
    std::shared_ptr<packing_gadget<FieldT>> unpack_balance;
    std::shared_ptr<packing_gadget<FieldT>> unpack_amount;
    pb_variable<FieldT> less;
    pb_variable<FieldT> less_or_eq;
    std::shared_ptr<comparison_gadget<FieldT>> cmp;
    size_t num_bits;

public:
    SufficientFundsCircuit(protoboard<FieldT>& pb, size_t num_bits);

    void
    generate_r1cs_constraints();
    void
    generate_r1cs_witness(const FieldT& balance_val, const FieldT& amount_val);

    // Utility methods
    bool
    is_satisfied() const
    {
        return this->pb.is_satisfied();
    }

    r1cs_constraint_system<FieldT>
    get_constraint_system() const
    {
        return this->pb.get_constraint_system();
    }

    r1cs_primary_input<FieldT>
    get_primary_input() const
    {
        return this->pb.primary_input();
    }

    r1cs_auxiliary_input<FieldT>
    get_auxiliary_input() const
    {
        return this->pb.auxiliary_input();
    }
};

}  // namespace libsnark

#endif  // SUFFICIENT_FUNDS_CIRCUIT_H