// #ifndef SUFFICIENT_FUNDS_CIRCUIT_H
// #define SUFFICIENT_FUNDS_CIRCUIT_H

// #include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
// #include <libsnark/gadgetlib1/protoboard.hpp>

// using namespace libsnark;
// // using namespace libsnark::gadgetlib1;

// /**
//  * @brief Gadget that verifies an account has sufficient funds for a purchase
//  *
//  * Public inputs:
//  * - amount to be spent
//  *
//  * Private inputs:
//  * - account balance
//  */
// template <typename FieldT>
// class sufficient_funds_gadget : public gadget<FieldT>
// {
// private:
//     // Input wires
//     pb_variable<FieldT> account_balance;
//     pb_variable<FieldT> purchase_amount;

//     pb_variable<FieldT> less;        // Will be true if purchase < balance
//     pb_variable<FieldT> less_or_eq;  // Will be true if purchase <= balance

//     // Internal gadgets
//     std::unique_ptr<comparison_gadget<FieldT>> comparison;

//     // Bit length
//     static constexpr size_t BIT_LENGTH = 64;

// public:
//     sufficient_funds_gadget(
//         protoboard<FieldT>& pb,
//         const pb_variable<FieldT>& account_balance,
//         const pb_variable<FieldT>& purchase_amount,
//         const std::string& annotation_prefix);

//     void
//     generate_r1cs_constraints();
//     void
//     generate_r1cs_witness();
// };

// /**
//  * @brief Creates the circuit for verifying sufficient funds
//  */
// template <typename FieldT>
// class SufficientFundsCircuit
// {
// private:
//     protoboard<FieldT> pb;
//     pb_variable<FieldT> account_balance;
//     pb_variable<FieldT> purchase_amount;
//     std::vector<pb_variable<FieldT>> balance_bits;
//     std::vector<pb_variable<FieldT>> amount_bits;
//     sufficient_funds_gadget<FieldT> gadget;
//     static constexpr size_t BIT_LENGTH = 64;

// public:
//     SufficientFundsCircuit();

//     // Generate the constraints for the circuit
//     void
//     generate_r1cs_constraints();

//     // Generate the witness for the circuit
//     void
//     generate_r1cs_witness(const FieldT& balance, const FieldT& amount);

//     // Get the constraint system
//     r1cs_constraint_system<FieldT>
//     get_constraint_system() const;

//     // Check if the constraint system is satisfied
//     bool
//     is_satisfied() const;

//     // Get the primary input
//     r1cs_primary_input<FieldT>
//     get_primary_input() const;

//     // Get the auxiliary input
//     r1cs_auxiliary_input<FieldT>
//     get_auxiliary_input() const;
// };

// // #include "SufficientFundsCircuit.cpp"

// #endif  // SUFFICIENT_FUNDS_CIRCUIT_H