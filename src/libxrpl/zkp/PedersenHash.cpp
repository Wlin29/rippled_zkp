// #include "PedersenHash.h"
// #include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
// #include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

// using libff::alt_bn128_Fr;
// using libff::bigint;

// static void initialize_libff() {
//     static bool initialized = false;
//     if (!initialized) {
//         libff::alt_bn128_pp::init_public_params();
//         initialized = true;
//     }
// }

// namespace ripple {

// template<typename FieldT>
// pedersen_hash_gadget<FieldT>::pedersen_hash_gadget(
//     libsnark::protoboard<FieldT> &pb,
//     const libsnark::pb_variable_array<FieldT> &input_bits,
//     const libsnark::pb_variable<FieldT> &output,
//     const std::string &annotation_prefix) :
//     libsnark::gadget<FieldT>(pb, annotation_prefix),
//     input_bits(input_bits),
//     output(output)
// {
//     // Initialize libff if needed
//     initialize_libff();
    
//     // Initialize base points
//     initialize_base_points();
    
//     // Allocate intermediate variables
//     // Fix: use allocate_variable instead of allocate 
//     // Fix: Allocate one extra element for i+1 access
//     intermediate_results.resize(input_bits.size() + 1);
//     for (size_t i = 0; i <= input_bits.size(); i++) {
//         intermediate_results[i].allocate(
//             this->pb, annotation_prefix + "_intermediate_" + std::to_string(i));
//     }
// }

// template<typename FieldT>
// void pedersen_hash_gadget<FieldT>::initialize_base_points() {
//     // Generate or load precomputed base points
//     // For a secure implementation, these should be generated using a
//     // "nothing up my sleeve" method
    
//     // Example (not secure, just for illustration):
//     for (size_t i = 0; i < 256; i++) {
//         // In a real implementation, these would be proper elliptic curve points
//         base_points.push_back(FieldT(i + 1000));
//     }
// }

// template<typename FieldT>
// void pedersen_hash_gadget<FieldT>::generate_r1cs_constraints() {
//     // Starting point
//     this->pb.add_r1cs_constraint(
//         libsnark::r1cs_constraint<FieldT>(1, 
//                                          intermediate_results[0], 
//                                          FieldT::one()),
//         "initial_value");
    
//     // For each bit, conditionally add the corresponding base point
//     for (size_t i = 0; i < input_bits.size(); i++) {
//         // If bit is 1, add the base point to the current sum
//         // intermediate_results[i+1] = intermediate_results[i] + (input_bits[i] * base_points[i])
        
//         FieldT base_point = base_points[i];
        
//         // Create a constraint that says:
//         // intermediate_results[i+1] = intermediate_results[i] + (input_bits[i] * base_point)
//         this->pb.add_r1cs_constraint(
//             libsnark::r1cs_constraint<FieldT>(
//                 input_bits[i],
//                 base_point,
//                 intermediate_results[i+1] - intermediate_results[i]),
//             "accumulate_bit_" + std::to_string(i));
//     }
    
//     // Final output constraint
//     this->pb.add_r1cs_constraint(
//         libsnark::r1cs_constraint<FieldT>(1, 
//                                          intermediate_results.back(), 
//                                          output),
//         "output_constraint");
// }

// template<typename FieldT>
// void pedersen_hash_gadget<FieldT>::generate_r1cs_witness() {
//     // Initialize first intermediate result to identity element (0 or 1 depending on your EC)
//     this->pb.val(intermediate_results[0]) = FieldT::one();
    
//     // Compute intermediate results
//     for (size_t i = 0; i < input_bits.size(); i++) {
//         FieldT current = this->pb.val(intermediate_results[i]);
        
//         // If the bit is set, add the base point
//         if (this->pb.val(input_bits[i]) == FieldT::one()) {
//             current = current + base_points[i];
//         }
        
//         this->pb.val(intermediate_results[i+1]) = current;
//     }
    
//     // Set the output
//     this->pb.val(output) = this->pb.val(intermediate_results.back());
// }

// // Explicit instantiation for common field types
// template class pedersen_hash_gadget<libff::alt_bn128_Fr>;
// // Add other field types as needed

// } // namespace ripple