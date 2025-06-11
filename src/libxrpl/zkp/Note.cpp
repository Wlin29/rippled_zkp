#include "Note.h"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <cstring>
#include <random>

namespace ripple {
namespace zkp {

uint256 Note::computeCommitment() const {
    /**
     * Zcash note commitment formula (simplified):
     * cm = SHA256(SHA256(a_pk) || SHA256(value || rho))
     * 
     * This matches the circuit implementation:
     * - First half: a_pk (256 bits) 
     * - Second half: hash(value || rho) (256 bits)
     * - Final: SHA256(first_half || second_half)
     */
    
    std::cout << "Computing Zcash note commitment..." << std::endl;
    
    // 1. FIRST HALF: a_pk (already 256 bits)
    auto a_pk_bytes = MerkleCircuit::bitsToBytes(a_pk);
    
    // 2. SECOND HALF: hash(value || rho)
    // Prepare value||rho input (8 + 32 = 40 bytes)
    std::vector<uint8_t> value_rho_input(40);
    
    // Pack value (8 bytes, little-endian)
    std::memcpy(value_rho_input.data(), &value, 8);
    
    // Pack rho (32 bytes from field element)
    auto rho_bits = MerkleCircuit::fieldElementToBits(rho);
    auto rho_bytes = MerkleCircuit::bitsToBytes(rho_bits);
    std::memcpy(value_rho_input.data() + 8, rho_bytes.data(), 32);
    
    // Hash value||rho to get second half
    std::array<uint8_t, 32> second_half_hash;
    SHA256(value_rho_input.data(), 40, second_half_hash.data());
    
    // 3. FINAL COMMITMENT: SHA256(a_pk || hash(value||rho))
    std::vector<uint8_t> final_input(64); // 32 + 32 = 64 bytes
    std::memcpy(final_input.data(), a_pk_bytes.data(), 32);           // first half
    std::memcpy(final_input.data() + 32, second_half_hash.data(), 32); // second half
    
    // Compute final SHA256
    std::array<uint8_t, 32> commitment_hash;
    SHA256(final_input.data(), 64, commitment_hash.data());
    
    // Convert to uint256
    uint256 commitment;
    std::memcpy(commitment.begin(), commitment_hash.data(), 32);
    
    std::cout << "Value: " << value << std::endl;
    std::cout << "Rho (first 8 bytes): ";
    for (int i = 0; i < 8; ++i) std::cout << std::hex << (int)rho_bytes[i] << " ";
    std::cout << std::endl;
    std::cout << "A_pk (first 8 bytes): ";
    for (int i = 0; i < 8; ++i) std::cout << std::hex << (int)a_pk_bytes[i] << " ";
    std::cout << std::endl;
    auto second_half_uint256_array = MerkleCircuit::bitsToUint256(MerkleCircuit::bytesToBits(second_half_hash));
    uint256 second_half_uint256;
    std::memcpy(second_half_uint256.begin(), second_half_uint256_array.data(), 32);
    std::cout << "Second half hash: " << second_half_uint256 << std::endl;
    std::cout << "Final commitment: " << commitment << std::endl;
    
    return commitment;
}

uint256 Note::computeNullifier(const std::vector<bool>& a_sk) const {
    /**
     * Zcash nullifier formula:
     * nf = SHA256(a_sk || rho)
     * 
     * Layout: 32 + 32 = 64 bytes input
     */
    
    std::vector<uint8_t> input(64); // 32 + 32 = 64 bytes
    
    // 1. a_sk (32 bytes from 256 bits)
    auto a_sk_bytes = MerkleCircuit::bitsToBytes(a_sk);
    std::memcpy(input.data(), a_sk_bytes.data(), 32);
    
    // 2. rho (32 bytes from field element)
    auto rho_bits = MerkleCircuit::fieldElementToBits(rho);
    auto rho_bytes = MerkleCircuit::bitsToBytes(rho_bits);
    std::memcpy(input.data() + 32, rho_bytes.data(), 32);
    
    // Compute SHA256
    std::array<uint8_t, 32> hash;
    SHA256(input.data(), 64, hash.data());
    
    // Convert to uint256
    uint256 nullifier;
    std::memcpy(nullifier.begin(), hash.data(), 32);
    return nullifier;
}

Note Note::createRandom(uint64_t value, const std::vector<bool>& recipient_pk) {
    Note note;
    note.value = value;
    note.rho = generateRandomFieldElement();
    note.r = generateRandomFieldElement();
    note.a_pk = recipient_pk;
    return note;
}

FieldT Note::generateRandomFieldElement() {
    // Generate 32 random bytes
    std::array<uint8_t, 32> random_bytes;
    RAND_bytes(random_bytes.data(), 32);
    
    std::vector<bool> random_bits(253); // Use 253 bits to ensure < field modulus
    for (size_t i = 0; i < 253; ++i) {
        size_t byte_idx = i / 8;
        size_t bit_idx = i % 8;
        random_bits[i] = (random_bytes[byte_idx] >> bit_idx) & 1;
    }
    
    // Convert to field element (using only 253 bits to ensure < field modulus)
    random_bits.resize(253);
    return MerkleCircuit::bitsToFieldElement(random_bits);
}

bool Note::isValid() const {
    // Check value is reasonable
    if (value == 0 && rho == FieldT::zero() && r == FieldT::zero()) {
        return false; // Empty note
    }
    
    // Check a_pk is not all zeros
    bool all_zero = true;
    for (bool bit : a_pk) {
        if (bit) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) return false;
    
    // Check field elements are valid (non-zero for randomness)
    if (rho == FieldT::zero() || r == FieldT::zero()) {
        return false;
    }
    
    return true;
}

std::vector<uint8_t> Note::serialize() const {
    std::vector<uint8_t> data;
    data.reserve(8 + 32 + 32 + 32); // value + rho + r + a_pk
    
    // Serialize value (8 bytes)
    const uint8_t* value_ptr = reinterpret_cast<const uint8_t*>(&value);
    data.insert(data.end(), value_ptr, value_ptr + 8);
    
    // Serialize rho (32 bytes)
    auto rho_bits = MerkleCircuit::fieldElementToBits(rho);
    auto rho_bytes = MerkleCircuit::bitsToBytes(rho_bits);  // Use bitsToBytes
    data.insert(data.end(), rho_bytes.begin(), rho_bytes.end());
    
    // Serialize r (32 bytes)
    auto r_bits = MerkleCircuit::fieldElementToBits(r);
    auto r_bytes = MerkleCircuit::bitsToBytes(r_bits);  // Use bitsToBytes
    data.insert(data.end(), r_bytes.begin(), r_bytes.end());
    
    // Serialize a_pk (32 bytes)
    auto a_pk_bytes = MerkleCircuit::bitsToBytes(a_pk);  // Use bitsToBytes
    data.insert(data.end(), a_pk_bytes.begin(), a_pk_bytes.end());
    
    return data;
}

Note Note::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() != 104) {
        throw std::invalid_argument("Invalid note data size");
    }
    
    Note note;
    size_t offset = 0;
    
    // Deserialize value
    std::memcpy(&note.value, data.data() + offset, 8);
    offset += 8;
    
    // Deserialize rho
    std::array<uint8_t, 32> rho_bytes;
    std::memcpy(rho_bytes.data(), data.data() + offset, 32);
    auto rho_bits = MerkleCircuit::bytesToBits(rho_bytes);  // Use bytesToBits
    note.rho = MerkleCircuit::bitsToFieldElement(rho_bits);
    offset += 32;
    
    // Deserialize r
    std::array<uint8_t, 32> r_bytes;
    std::memcpy(r_bytes.data(), data.data() + offset, 32);
    auto r_bits = MerkleCircuit::bytesToBits(r_bytes);  // Use bytesToBits
    note.r = MerkleCircuit::bitsToFieldElement(r_bits);
    offset += 32;
    
    // Deserialize a_pk
    std::array<uint8_t, 32> a_pk_bytes;
    std::memcpy(a_pk_bytes.data(), data.data() + offset, 32);
    note.a_pk = MerkleCircuit::bytesToBits(a_pk_bytes);  // Use bytesToBits
    
    return note;
}

// AddressKeyPair implementation
AddressKeyPair AddressKeyPair::generate() {
    AddressKeyPair keypair;
    
    // Generate random secret key
    std::array<uint8_t, 32> sk_bytes;
    RAND_bytes(sk_bytes.data(), 32);
    
    // Convert to bits
    for (size_t i = 0; i < 256; ++i) {
        size_t byte_idx = i / 8;
        size_t bit_idx = i % 8;
        keypair.a_sk[i] = (sk_bytes[byte_idx] >> bit_idx) & 1;
    }
    
    // Derive public key and viewing key
    keypair.derivePublicKey();
    keypair.deriveViewingKey();
    
    return keypair;
}

void AddressKeyPair::derivePublicKey() {
    // a_pk = SHA256(a_sk)
    auto a_sk_bytes = MerkleCircuit::bitsToBytes(a_sk);  // Use bitsToBytes
    
    std::array<uint8_t, 32> pk_hash;
    SHA256(a_sk_bytes.data(), 32, pk_hash.data());
    
    // Convert back to bits
    a_pk = MerkleCircuit::bytesToBits(pk_hash);  // Use bytesToBits
}

void AddressKeyPair::deriveViewingKey() {
    // ivk = SHA256(a_sk || "ivk")
    std::vector<uint8_t> input(35); // 32 + 3 bytes
    
    auto a_sk_bytes = MerkleCircuit::bitsToBytes(a_sk);  // Use bitsToBytes
    std::memcpy(input.data(), a_sk_bytes.data(), 32);
    std::memcpy(input.data() + 32, "ivk", 3);
    
    std::array<uint8_t, 32> ivk_hash;
    SHA256(input.data(), 35, ivk_hash.data());
    
    // Convert to bits
    ivk = MerkleCircuit::bytesToBits(ivk_hash);  // Use bytesToBits
}

uint256 AddressKeyPair::getAddressHash() const {
    // Return hash of public key for address identification
    auto a_pk_bytes = MerkleCircuit::bitsToBytes(a_pk);  // Use bitsToBytes
    
    std::array<uint8_t, 32> addr_hash;
    SHA256(a_pk_bytes.data(), 32, addr_hash.data());
    
    uint256 result;
    std::memcpy(result.begin(), addr_hash.data(), 32);
    return result;
}

bool AddressKeyPair::canSpend(const Note& note) const {
    // Check if our public key matches the note's recipient
    return note.a_pk == a_pk;
}

} // namespace zkp
} // namespace ripple