// #include "SufficientFundsCircuit.h"

// /**
//  * Implementation of sufficient_funds_gadget
//  */
// template <typename FieldT>
// sufficient_funds_gadget<FieldT>::sufficient_funds_gadget(
//     protoboard<FieldT>& pb,
//     const pb_variable<FieldT>& account_balance,
//     const pb_variable<FieldT>& purchase_amount,
//     const std::string& annotation_prefix)
//     : gadget<FieldT>(pb, annotation_prefix)
//     , account_balance(account_balance)
//     , purchase_amount(purchase_amount)
// {
//     // First allocate variables
//     less.allocate(pb, FMT(annotation_prefix, " less"));
//     less_or_eq.allocate(pb, FMT(annotation_prefix, " less_or_eq"));

//     // Then create the comparison gadget directly (don't assign)
//     comparison = std::unique_ptr<comparison_gadget<FieldT>>(
//         new comparison_gadget<FieldT>(
//             pb,
//             BIT_LENGTH,
//             purchase_amount,
//             account_balance,
//             less,
//             less_or_eq,
//             FMT(annotation_prefix, " comparison")));
// }

// template <typename FieldT>
// void
// printFieldValue(std::ostream& os, const FieldT& value)
// {
//     // This is a simplified representation - just outputs "non-zero" or "zero"
//     // You could also output specific fields in the type if needed
//     if (value == FieldT::zero())
//         os << "0";
//     else if (value == FieldT::one())
//         os << "1";
//     else
//         os << "non-zero";
// }

// template <typename FieldT>
// void
// sufficient_funds_gadget<FieldT>::generate_r1cs_constraints()
// {
//     // Add constraints for the comparison gadget
//     comparison->generate_r1cs_constraints();

//     // This adds a constraint that purchase_amount*less_or_eq = purchase_amount
//     // Which can only be satisfied when less_or_eq = 1 (i.e., purchase_amount <=
//     // account_balance)
//     this->pb.add_r1cs_constraint(
//         r1cs_constraint<FieldT>(purchase_amount, less_or_eq, purchase_amount),
//         FMT(this->annotation_prefix, " enforce_sufficient_funds"));
// }

// template <typename FieldT>
// void
// sufficient_funds_gadget<FieldT>::generate_r1cs_witness()
// {
//     comparison->generate_r1cs_witness();

//     // Add explicit check to output the actual numeric values if possible
//     std::cout << "Balance numeric: " << this->pb.val(account_balance).as_ulong()
//               << std::endl;
//     std::cout << "Purchase numeric: "
//               << this->pb.val(purchase_amount).as_ulong() << std::endl;

//     // For debugging, enforce the constraint explicitly
//     FieldT difference =
//         this->pb.val(purchase_amount) - this->pb.val(account_balance);
//     bool is_sufficient = this->pb.val(less_or_eq) == FieldT::one();

//     if (!is_sufficient)
//     {
//         std::cout << "EXPLICIT CHECK: Purchase is greater than balance, "
//                      "setting less_or_eq to 0"
//                   << std::endl;
//         // The comparison gadget should have already set this
//         this->pb.val(less_or_eq) = FieldT::zero();
//     }
//     else
//     {
//         std::cout
//             << "EXPLICIT CHECK: Purchase is <= balance, setting less_or_eq to 1"
//             << std::endl;
//         // The comparison gadget should have already set this
//         this->pb.val(less_or_eq) = FieldT::one();
//     }

//     std::cout << "Account balance: ";
//     printFieldValue(std::cout, this->pb.val(account_balance));
//     std::cout << std::endl;

//     std::cout << "Purchase amount: ";
//     printFieldValue(std::cout, this->pb.val(purchase_amount));
//     std::cout << std::endl;

//     std::cout << "less_or_eq value: ";
//     printFieldValue(std::cout, this->pb.val(less_or_eq));
//     std::cout << std::endl;

//     std::cout << "less value: ";
//     printFieldValue(std::cout, this->pb.val(less));
//     std::cout << std::endl;
// }

// /**
//  * Implementation of SufficientFundsCircuit
//  */
// template <typename FieldT>
// SufficientFundsCircuit<FieldT>::SufficientFundsCircuit()
//     : pb()
//     , account_balance()
//     , purchase_amount()
//     , balance_bits(BIT_LENGTH)
//     , amount_bits(BIT_LENGTH)
//     , gadget(pb, account_balance, purchase_amount, "sufficient_funds_gadget")
// {
//     // Allocate variables first
//     account_balance.allocate(pb, "account_balance");
//     purchase_amount.allocate(pb, "purchase_amount");

//     // Allocate bit representations
//     for (size_t i = 0; i < BIT_LENGTH; i++)
//     {
//         balance_bits[i].allocate(pb, FMT("balance_bits_%zu", i));
//         amount_bits[i].allocate(pb, FMT("amount_bits_%zu", i));
//     }

//     // First only purchase_amount is public (primary input)
//     pb.set_input_sizes(1);
// }

// template <typename FieldT>
// void
// SufficientFundsCircuit<FieldT>::generate_r1cs_constraints()
// {
//     // Generate constraints for binary representation
//     // Need to apply constraints to each bit individually
//     for (size_t i = 0; i < BIT_LENGTH; i++)
//     {
//         // Ensure balance_bits[i] is boolean (0 or 1)
//         this->pb.add_r1cs_constraint(
//             r1cs_constraint<FieldT>(balance_bits[i], 1 - balance_bits[i], 0),
//             FMT("balance_bits_%zu", i));

//         // Ensure amount_bits[i] is boolean (0 or 1)
//         this->pb.add_r1cs_constraint(
//             r1cs_constraint<FieldT>(amount_bits[i], 1 - amount_bits[i], 0),
//             FMT("amount_bits_%zu", i));
//     }

//     // Create packing constraint for account_balance
//     // We need to create a linear combination to represent the binary value
//     linear_combination<FieldT> balance_lc;
//     for (size_t i = 0; i < BIT_LENGTH; i++)
//     {
//         balance_lc = balance_lc + (balance_bits[i] * FieldT(1ULL << i));
//     }

//     // Constrain account_balance to equal the binary representation
//     this->pb.add_r1cs_constraint(
//         r1cs_constraint<FieldT>(1, balance_lc, account_balance),
//         "balance_packing");

//     // Create packing constraint for purchase_amount
//     linear_combination<FieldT> amount_lc;
//     for (size_t i = 0; i < BIT_LENGTH; i++)
//     {
//         amount_lc = amount_lc + (amount_bits[i] * FieldT(1ULL << i));
//     }

//     // Constrain purchase_amount to equal the binary representation
//     this->pb.add_r1cs_constraint(
//         r1cs_constraint<FieldT>(1, amount_lc, purchase_amount),
//         "amount_packing");

//     // Generate constraints for the sufficient_funds_gadget
//     gadget.generate_r1cs_constraints();
// }

// template <typename FieldT>
// void
// SufficientFundsCircuit<FieldT>::generate_r1cs_witness(
//     const FieldT& balance,
//     const FieldT& amount)
// {
//     // Set values for the input variables
//     this->pb.val(account_balance) = balance;
//     this->pb.val(purchase_amount) = amount;

//     // Set bit representations
//     size_t bal_val = balance.as_ulong();
//     size_t amt_val = amount.as_ulong();

//     for (size_t i = 0; i < BIT_LENGTH; i++)
//     {
//         this->pb.val(balance_bits[i]) =
//             (bal_val & (1ul << i)) ? FieldT::one() : FieldT::zero();
//         this->pb.val(amount_bits[i]) =
//             (amt_val & (1ul << i)) ? FieldT::one() : FieldT::zero();
//     }

//     // Generate witness for the gadget
//     gadget.generate_r1cs_witness();

//     // Debug output
//     std::cout << "Balance bits: ";
//     for (int i = BIT_LENGTH - 1; i >= 0; i--)
//     {
//         std::cout
//             << (this->pb.val(balance_bits[i]) == FieldT::one() ? "1" : "0");
//     }
//     std::cout << std::endl;

//     std::cout << "Amount bits: ";
//     for (int i = BIT_LENGTH - 1; i >= 0; i--)
//     {
//         std::cout
//             << (this->pb.val(amount_bits[i]) == FieldT::one() ? "1" : "0");
//     }
//     std::cout << std::endl;
// }

// template <typename FieldT>
// r1cs_constraint_system<FieldT>
// SufficientFundsCircuit<FieldT>::get_constraint_system() const
// {
//     return pb.get_constraint_system();
// }

// template <typename FieldT>
// bool
// SufficientFundsCircuit<FieldT>::is_satisfied() const
// {
//     return pb.is_satisfied();
// }

// template <typename FieldT>
// r1cs_primary_input<FieldT>
// SufficientFundsCircuit<FieldT>::get_primary_input() const
// {
//     return pb.primary_input();
// }

// template <typename FieldT>
// r1cs_auxiliary_input<FieldT>
// SufficientFundsCircuit<FieldT>::get_auxiliary_input() const
// {
//     return pb.auxiliary_input();
// }

// #include <libff/algebra/curves/bn128/bn128_pp.hpp>
// template class SufficientFundsCircuit<
//     libff::Fp_model<4l, libff::bn128_modulus_r>>;
