// #pragma once

// #include <libsnark/gadgetlib1/gadget.hpp>
// #include <libsnark/gadgetlib1/protoboard.hpp>
// #include <libsnark/gadgetlib1/pb_variable.hpp>
// // #include <libsnark/gadgetlib1/pb_variable_array.hpp>
// // #include <libsnark/gadgetlib1/gadgets/pairing/pairing_params.hpp>
// // #include <libsnark/gadgetlib1/gadgets/curves/curve_point_gadget.hpp>

// namespace ripple {

// template<typename FieldT>
// class pedersen_hash_gadget : public libsnark::gadget<FieldT> {
// private:
//     // Input bits to hash
//     const libsnark::pb_variable_array<FieldT> input_bits;
    
//     // Output hash result
//     libsnark::pb_variable<FieldT> output;
    
//     // Intermediate variables for computation
//     std::vector<libsnark::pb_variable<FieldT>> intermediate_results;
    
//     // Fixed base points (elliptic curve points converted to field elements)
//     std::vector<FieldT> base_points;

//     void initialize_base_points();
    
//     // Helper gadgets (e.g., for scalar multiplication)
//     // ...

// public:
//     // Constructor
//     pedersen_hash_gadget(
//         libsnark::protoboard<FieldT> &pb,
//         const libsnark::pb_variable_array<FieldT> &input_bits,
//         const libsnark::pb_variable<FieldT> &output,
//         const std::string &annotation_prefix);
    
//     // Generate constraints for the circuit
//     void generate_r1cs_constraints();
    
//     // Generate the witness (actual values during execution)
//     void generate_r1cs_witness();
// };

// } // namespace ripple