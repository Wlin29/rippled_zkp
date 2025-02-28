#ifndef AMOUNT_CIRCUIT_H
#define AMOUNT_CIRCUIT_H
#pragma once

#include <libsnark/gadgetlib1/gadget.hpp>

template <typename FieldT>
class AmountCircuit : public libsnark::gadget<FieldT>
{
public:
    const libsnark::pb_variable<FieldT>& x;
    const libsnark::pb_variable<FieldT>& max_amount;
    libsnark::pb_variable<FieldT> slack;

    AmountCircuit(
        libsnark::protoboard<FieldT>& pb,
        const libsnark::pb_variable<FieldT>& x,
        const libsnark::pb_variable<FieldT>& max_amount);

    void
    generate_r1cs_constraints();
    void
    generate_r1cs_witness(const FieldT& x_val, const FieldT& max);
};

#endif