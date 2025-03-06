// #include "SufficientFundsVerification.h"
// #include <libsnark/serialization.hpp>

// namespace ripple {

// ProofType 
// ZKPProof::generateSufficientFundsProof(
//     uint64_t balance, 
//     uint64_t amount, 
//     size_t bit_length) 
// {
//     // Initialize the curve parameters if not already done
//     static bool init_done = false;
//     if (!init_done) {
//         libff::alt_bn128_pp::init_public_params();
//         init_done = true;
//     }
    
//     // Create a typecast function for cleaner value assignment
//     auto fr = [](uint64_t x) -> libsnark::FrType { 
//         return libsnark::FrType(x); 
//     };
    
//     // Create a protoboard
//     libsnark::protoboard<libsnark::FrType> pb;
    
//     // Set up the circuit
//     libsnark::SufficientFundsCircuit<libsnark::FrType> circuit(pb, bit_length);
//     circuit.generate_r1cs_constraints();
//     circuit.generate_r1cs_witness(fr(balance), fr(amount));
    
//     // Make sure constraints are satisfied
//     if (!circuit.is_satisfied()) {
//         throw std::runtime_error("Constraints not satisfied - can't generate valid proof");
//     }
    
//     // Get or generate the proving key
//     auto [pk, vk] = generateKeypair(bit_length);
    
//     // Generate the proof
//     return libsnark::r1cs_ppzksnark::r1cs_ppzksnark_prover<libsnark::CurveType>(
//         pk, 
//         pb.primary_input(), 
//         pb.auxiliary_input());
// }

// bool 
// ZKPProof::verifySufficientFundsProof(
//     const ProofType& proof,
//     uint64_t amount,
//     const VerificationKeyType& vk) 
// {
//     // Initialize the curve parameters if not already done
//     static bool init_done = false;
//     if (!init_done) {
//         libff::alt_bn128_pp::init_public_params();
//         init_done = true;
//     }
    
//     // Create the public input from the amount (balance is kept private)
//     libsnark::r1cs_primary_input<libsnark::FrType> public_input;
//     public_input.push_back(libsnark::FrType(amount));
    
//     // Verify the proof
//     return libsnark::r1cs_ppzksnark::r1cs_ppzksnark_verifier<libsnark::CurveType>(
//         vk, 
//         public_input, 
//         proof);
// }

// std::vector<unsigned char> 
// ZKPProof::serializeProof(const ProofType& proof) 
// {
//     std::stringstream ss;
//     ss << proof;
//     std::string proof_str = ss.str();
//     return std::vector<unsigned char>(proof_str.begin(), proof_str.end());
// }

// ProofType 
// ZKPProof::deserializeProof(const std::vector<unsigned char>& serialized) 
// {
//     std::string proof_str(serialized.begin(), serialized.end());
//     std::stringstream ss(proof_str);
//     ProofType proof;
//     ss >> proof;
//     return proof;
// }

// VerificationKeyType 
// ZKPProof::getVerificationKey(size_t bit_length) 
// {
//     return generateKeypair(bit_length).second;
// }

// std::pair<libsnark::r1cs_ppzksnark::r1cs_ppzksnark_proving_key<libsnark::CurveType>,
//           VerificationKeyType>
// ZKPProof::generateKeypair(size_t bit_length) 
// {
//     // Initialize the curve parameters if not already done
//     static bool init_done = false;
//     if (!init_done) {
//         libff::alt_bn128_pp::init_public_params();
//         init_done = true;
//     }
    
//     // Generate an empty protoboard
//     libsnark::protoboard<libsnark::FrType> pb;
    
//     // Create the circuit just for setup
//     libsnark::SufficientFundsCircuit<libsnark::FrType> circuit(pb, bit_length);
//     circuit.generate_r1cs_constraints();
    
//     // Generate the keypair
//     return libsnark::r1cs_ppzksnark::r1cs_ppzksnark_generator<libsnark::CurveType>(
//         pb.get_constraint_system());
// }

// } // namespace ripple