#include <xrpl/beast/unit_test.h>
#include <libxrpl/zkp/circuits/BalanceCircuit.h>
#include <libxrpl/zkp/circuits/SufficientFundsCircuit.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <vector>

namespace ripple {

using namespace libsnark;
using namespace libff;
using CurveType = alt_bn128_pp;
using FieldT = Fr<CurveType>;  

class BalanceCircuit_test : public beast::unit_test::suite
{
public:
    void run() override
    {
        testBalanceCircuitValid();
        testBalanceCircuitInvalidSum();
        testBalanceCircuitZeroFee();
        testBalanceCircuitInvalidInputSize();
    }

    void testBalanceCircuitValid()
    {
        testcase("Balance Circuit Valid");
        
        protoboard<FieldT> pb;
        size_t num_inputs = 2;
        size_t num_outputs = 2;
        ripple::zkp::BalanceCircuit<FieldT> circuit(pb, num_inputs, num_outputs, "balance");

        circuit.generate_r1cs_constraints();

        std::vector<FieldT> input_values = {FieldT("10"), FieldT("5")};
        std::vector<FieldT> output_values = {FieldT("8"), FieldT("5")};
        FieldT fee = FieldT("2");

        circuit.generate_r1cs_witness(input_values, output_values, fee);

        BEAST_EXPECT(pb.is_satisfied());
    }

    void testBalanceCircuitInvalidSum()
    {
        testcase("Balance Circuit Invalid Sum");
        
        protoboard<FieldT> pb;
        size_t num_inputs = 2;
        size_t num_outputs = 2;
        ripple::zkp::BalanceCircuit<FieldT> circuit(pb, num_inputs, num_outputs, "balance");

        circuit.generate_r1cs_constraints();

        std::vector<FieldT> input_values = {FieldT("10"), FieldT("5")};
        std::vector<FieldT> output_values = {FieldT("8"), FieldT("4")}; // output sum = 12
        FieldT fee = FieldT("2"); // total outflow = 14, input sum = 15

        circuit.generate_r1cs_witness(input_values, output_values, fee);

        // Should fail: input_sum (15) != total_outflow (14)
        BEAST_EXPECT(!pb.is_satisfied());
    }

    void testBalanceCircuitZeroFee()
    {
        testcase("Balance Circuit Zero Fee");
        
        protoboard<FieldT> pb;
        size_t num_inputs = 1;
        size_t num_outputs = 1;
        ripple::zkp::BalanceCircuit<FieldT> circuit(pb, num_inputs, num_outputs, "balance");

        circuit.generate_r1cs_constraints();

        std::vector<FieldT> input_values = {FieldT("100")};
        std::vector<FieldT> output_values = {FieldT("100")};
        FieldT fee = FieldT("0");

        circuit.generate_r1cs_witness(input_values, output_values, fee);

        BEAST_EXPECT(pb.is_satisfied());
    }

    void testBalanceCircuitInvalidInputSize()
    {
        testcase("Balance Circuit Invalid Input Size");
        
        protoboard<FieldT> pb;
        size_t num_inputs = 2;
        size_t num_outputs = 2;
        ripple::zkp::BalanceCircuit<FieldT> circuit(pb, num_inputs, num_outputs, "balance");

        circuit.generate_r1cs_constraints();

        std::vector<FieldT> input_values = {FieldT("10")}; // only 1 input
        std::vector<FieldT> output_values = {FieldT("8"), FieldT("2")};
        FieldT fee = FieldT("0");

        try
        {
            circuit.generate_r1cs_witness(input_values, output_values, fee);
            BEAST_EXPECT(false); // Should have thrown
        }
        catch (const std::invalid_argument&)
        {
            BEAST_EXPECT(true); // Expected exception
        }
    }
};

BEAST_DEFINE_TESTSUITE(BalanceCircuit, test, ripple);

} // namespace ripple
