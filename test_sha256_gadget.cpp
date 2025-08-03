#define CURVE_ALT_BN128
#include <iostream>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <openssl/sha.h>
#include <iomanip>
#include <vector>

using namespace libsnark;

typedef libff::Fr<default_r1cs_gg_ppzksnark_pp> FieldT;

// Helper functions to convert between hex strings and bits
std::vector<bool> hexToBits(const std::string& hex) {
    std::vector<bool> bits;
    for (size_t i = 0; i < hex.length(); i += 2) {
        uint8_t byte = std::stoi(hex.substr(i, 2), nullptr, 16);
        for (int j = 0; j < 8; ++j) {
            bits.push_back((byte >> j) & 1);
        }
    }
    return bits;
}

std::string bitsToHex(const std::vector<bool>& bits) {
    std::string hex;
    for (size_t i = 0; i < bits.size(); i += 8) {
        uint8_t byte = 0;
        for (int j = 0; j < 8 && i + j < bits.size(); ++j) {
            if (bits[i + j]) {
                byte |= (1 << j);
            }
        }
        hex += (char)('0' + (byte / 16) + (byte / 16 > 9 ? 7 : 0));
        hex += (char)('0' + (byte % 16) + (byte % 16 > 9 ? 7 : 0));
    }
    return hex;
}

void printBits(const std::string& label, const std::vector<bool>& bits, int count = 16) {
    std::cout << label << ": ";
    for (int i = 0; i < std::min((int)bits.size(), count); ++i) {
        std::cout << (bits[i] ? "1" : "0");
    }
    if (count < bits.size()) std::cout << "...";
    std::cout << std::endl;
}

// Convert from protoboard variable array to bits
std::vector<bool> pbVarArrayToBits(const protoboard<FieldT>& pb, const pb_variable_array<FieldT>& var_array) {
    std::vector<bool> bits;
    for (size_t i = 0; i < var_array.size(); ++i) {
        bits.push_back(pb.val(var_array[i]) == FieldT::one());
    }
    return bits;
}

int main() {
    // Initialize curve
    default_r1cs_gg_ppzksnark_pp::init_public_params();
    
    std::cout << "=== SHA256 Two-to-One Hash Gadget Test ===" << std::endl;
    
    // Test inputs
    std::string a_sk_hex = "4242424242424242424242424242424242424242424242424242424242424242";
    std::string rho_hex = "8484848484848484848484848484848484848484848484848484848484848484";
    
    std::cout << "Input A (a_sk): " << a_sk_hex << std::endl;
    std::cout << "Input B (rho):  " << rho_hex << std::endl;
    
    // Convert to bits (little-endian)
    std::vector<bool> a_sk_bits = hexToBits(a_sk_hex);
    std::vector<bool> rho_bits = hexToBits(rho_hex);
    
    printBits("A bits", a_sk_bits);
    printBits("B bits", rho_bits);
    
    // OpenSSL reference computation
    std::vector<uint8_t> a_sk_bytes, rho_bytes, combined;
    for (size_t i = 0; i < 32; ++i) {
        a_sk_bytes.push_back(std::stoi(a_sk_hex.substr(i*2, 2), nullptr, 16));
        rho_bytes.push_back(std::stoi(rho_hex.substr(i*2, 2), nullptr, 16));
    }
    combined.insert(combined.end(), a_sk_bytes.begin(), a_sk_bytes.end());
    combined.insert(combined.end(), rho_bytes.begin(), rho_bytes.end());
    
    uint8_t openssl_result[32];
    SHA256(combined.data(), 64, openssl_result);
    
    std::cout << "OpenSSL SHA256: ";
    for (int i = 0; i < 32; ++i) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (unsigned int)openssl_result[i];
    }
    std::cout << std::dec << std::endl;
    
    // Test libsnark sha256_two_to_one_hash_gadget
    protoboard<FieldT> pb;
    
    digest_variable<FieldT> left_digest(pb, 256, "left_digest");
    digest_variable<FieldT> right_digest(pb, 256, "right_digest");
    digest_variable<FieldT> output_digest(pb, 256, "output_digest");
    
    sha256_two_to_one_hash_gadget<FieldT> hasher(pb, left_digest, right_digest, output_digest, "hasher");
    
    // Generate constraints
    hasher.generate_r1cs_constraints();
    
    std::cout << "Circuit has " << pb.num_constraints() << " constraints" << std::endl;
    
    // Set input values
    for (size_t i = 0; i < 256; ++i) {
        pb.val(left_digest.bits[i]) = a_sk_bits[i] ? FieldT::one() : FieldT::zero();
        pb.val(right_digest.bits[i]) = rho_bits[i] ? FieldT::one() : FieldT::zero();
    }
    
    // Generate witness
    hasher.generate_r1cs_witness();
    
    // Extract result
    std::vector<bool> circuit_result_bits = pbVarArrayToBits(pb, output_digest.bits);
    std::string circuit_result_hex = bitsToHex(circuit_result_bits);
    
    std::cout << "Circuit result: " << circuit_result_hex << std::endl;
    
    printBits("Circuit result bits", circuit_result_bits);
    
    // Compare
    std::string openssl_hex;
    for (int i = 0; i < 32; ++i) {
        openssl_hex += (char)('0' + (openssl_result[i] / 16) + (openssl_result[i] / 16 > 9 ? 7 : 0));
        openssl_hex += (char)('0' + (openssl_result[i] % 16) + (openssl_result[i] % 16 > 9 ? 7 : 0));
    }
    
    std::cout << "Matches OpenSSL: " << (circuit_result_hex == openssl_hex ? "YES" : "NO") << std::endl;
    
    // Check if circuit satisfies constraints
    std::cout << "Circuit satisfied: " << (pb.is_satisfied() ? "YES" : "NO") << std::endl;
    
    // Test with different endianness interpretation
    std::cout << "\n=== Testing with big-endian interpretation ===" << std::endl;
    
    // Convert hex to big-endian bits
    auto hexToBitsBigEndian = [](const std::string& hex) {
        std::vector<bool> bits;
        for (size_t i = 0; i < hex.length(); i += 2) {
            uint8_t byte = std::stoi(hex.substr(i, 2), nullptr, 16);
            for (int j = 7; j >= 0; --j) {
                bits.push_back((byte >> j) & 1);
            }
        }
        return bits;
    };
    
    std::vector<bool> a_sk_bits_be = hexToBitsBigEndian(a_sk_hex);
    std::vector<bool> rho_bits_be = hexToBitsBigEndian(rho_hex);
    
    printBits("A bits (BE)", a_sk_bits_be);
    printBits("B bits (BE)", rho_bits_be);
    
    // Set big-endian values
    for (size_t i = 0; i < 256; ++i) {
        pb.val(left_digest.bits[i]) = a_sk_bits_be[i] ? FieldT::one() : FieldT::zero();
        pb.val(right_digest.bits[i]) = rho_bits_be[i] ? FieldT::one() : FieldT::zero();
    }
    
    // Generate witness
    hasher.generate_r1cs_witness();
    
    // Extract result
    std::vector<bool> circuit_result_bits_be = pbVarArrayToBits(pb, output_digest.bits);
    
    printBits("Circuit result bits (BE)", circuit_result_bits_be);
    
    // Check if this matches OpenSSL when converted back
    auto bitsToHexBigEndian = [](const std::vector<bool>& bits) {
        std::string hex;
        for (size_t i = 0; i < bits.size(); i += 8) {
            uint8_t byte = 0;
            for (int j = 0; j < 8 && i + j < bits.size(); ++j) {
                if (bits[i + j]) {
                    byte |= (1 << (7 - j));
                }
            }
            hex += (char)('0' + (byte / 16) + (byte / 16 > 9 ? 7 : 0));
            hex += (char)('0' + (byte % 16) + (byte % 16 > 9 ? 7 : 0));
        }
        return hex;
    };
    
    std::string circuit_result_hex_be = bitsToHexBigEndian(circuit_result_bits_be);
    std::cout << "Circuit result (BE): " << circuit_result_hex_be << std::endl;
    std::cout << "Matches OpenSSL (BE): " << (circuit_result_hex_be == openssl_hex ? "YES" : "NO") << std::endl;
    
    return 0;
}
