#include <boost/test/unit_test.hpp>
#include "libxrpl/zkp/circuits/SufficientFundsCircuit.h"
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>

using namespace libsnark;

BOOST_AUTO_TEST_SUITE(SufficientFundsCircuitTest)

using FieldT = FrType;

BOOST_AUTO_TEST_CASE(SufficientFunds_AmountLessThanBalance)
{
    default_r1cs_ppzksnark_pp::init_public_params();
    protoboard<FieldT> pb;
    size_t num_bits = 8;

    SufficientFundsCircuit<FieldT> circuit(pb, num_bits);

    FieldT balance_val = FieldT("100");
    FieldT amount_val = FieldT("50");

    circuit.generate_r1cs_constraints();
    circuit.generate_r1cs_witness(balance_val, amount_val);

    BOOST_CHECK(pb.is_satisfied());
}

BOOST_AUTO_TEST_CASE(SufficientFunds_AmountEqualsBalance)
{
    default_r1cs_ppzksnark_pp::init_public_params();
    protoboard<FieldT> pb;
    size_t num_bits = 8;

    SufficientFundsCircuit<FieldT> circuit(pb, num_bits);

    FieldT balance_val = FieldT("75");
    FieldT amount_val = FieldT("75");

    circuit.generate_r1cs_constraints();
    circuit.generate_r1cs_witness(balance_val, amount_val);

    BOOST_CHECK(pb.is_satisfied());
}

BOOST_AUTO_TEST_CASE(SufficientFunds_AmountGreaterThanBalance)
{
    default_r1cs_ppzksnark_pp::init_public_params();
    protoboard<FieldT> pb;
    size_t num_bits = 8;

    SufficientFundsCircuit<FieldT> circuit(pb, num_bits);

    FieldT balance_val = FieldT("30");
    FieldT amount_val = FieldT("40");

    circuit.generate_r1cs_constraints();
    circuit.generate_r1cs_witness(balance_val, amount_val);

    BOOST_CHECK(!pb.is_satisfied());
}

BOOST_AUTO_TEST_CASE(SufficientFunds_ZeroAmount)
{
    default_r1cs_ppzksnark_pp::init_public_params();
    protoboard<FieldT> pb;
    size_t num_bits = 8;

    SufficientFundsCircuit<FieldT> circuit(pb, num_bits);

    FieldT balance_val = FieldT("10");
    FieldT amount_val = FieldT("0");

    circuit.generate_r1cs_constraints();
    circuit.generate_r1cs_witness(balance_val, amount_val);

    BOOST_CHECK(pb.is_satisfied());
}

BOOST_AUTO_TEST_CASE(SufficientFunds_ZeroBalance)
{
    default_r1cs_ppzksnark_pp::init_public_params();
    protoboard<FieldT> pb;
    size_t num_bits = 8;

    SufficientFundsCircuit<FieldT> circuit(pb, num_bits);

    FieldT balance_val = FieldT("0");
    FieldT amount_val = FieldT("0");

    circuit.generate_r1cs_constraints();
    circuit.generate_r1cs_witness(balance_val, amount_val);

    BOOST_CHECK(pb.is_satisfied());
}

BOOST_AUTO_TEST_CASE(SufficientFunds_AmountNonZeroZeroBalance)
{
    default_r1cs_ppzksnark_pp::init_public_params();
    protoboard<FieldT> pb;
    size_t num_bits = 8;

    SufficientFundsCircuit<FieldT> circuit(pb, num_bits);

    FieldT balance_val = FieldT("0");
    FieldT amount_val = FieldT("1");

    circuit.generate_r1cs_constraints();
    circuit.generate_r1cs_witness(balance_val, amount_val);

    BOOST_CHECK(!pb.is_satisfied());
}

BOOST_AUTO_TEST_SUITE_END()