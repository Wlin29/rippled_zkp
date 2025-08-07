#include "Note.h"
#include "circuits/MerkleCircuit.h"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <cstring>
#include <random>

namespace ripple {
namespace zkp {

uint256 Note::commitment() const {
    return MerkleCircuit::computeNoteCommitment(value, rho, r, a_pk);
}

uint256 Note::nullifier(const uint256& a_sk) const {
    // Use circuit-based computation to ensure consistency with proofs
    return MerkleCircuit::computeNullifierWithCircuit(a_sk, rho);
}

std::vector<bool> Note::toBits() const {
    std::vector<bool> bits;
    bits.reserve(64 + 256 + 256 + 256); // value + rho + r + a_pk
    
    // Convert value to 64 bits (little-endian)
    for (int i = 0; i < 64; ++i) {
        bits.push_back((value >> i) & 1);
    }
    
    // Convert rho to 256 bits
    std::vector<bool> rho_bits = MerkleCircuit::uint256ToBits(rho);
    bits.insert(bits.end(), rho_bits.begin(), rho_bits.end());
    
    // Convert r to 256 bits
    std::vector<bool> r_bits = MerkleCircuit::uint256ToBits(r);
    bits.insert(bits.end(), r_bits.begin(), r_bits.end());
    
    // Convert a_pk to 256 bits
    std::vector<bool> a_pk_bits = MerkleCircuit::uint256ToBits(a_pk);
    bits.insert(bits.end(), a_pk_bits.begin(), a_pk_bits.end());
    
    return bits;
}

Note Note::fromBits(const std::vector<bool>& bits) {
    if (bits.size() < 64 + 256 + 256 + 256) {
        throw std::invalid_argument("Insufficient bits for Note reconstruction");
    }
    
    Note note;
    
    // Extract value (64 bits)
    note.value = 0;
    for (int i = 0; i < 64; ++i) {
        if (bits[i]) {
            note.value |= (1ULL << i);
        }
    }
    
    // Extract rho (256 bits)
    std::vector<bool> rho_bits(bits.begin() + 64, bits.begin() + 64 + 256);
    note.rho = MerkleCircuit::bitsToUint256(rho_bits);
    
    // Extract r (256 bits)
    std::vector<bool> r_bits(bits.begin() + 64 + 256, bits.begin() + 64 + 256 + 256);
    note.r = MerkleCircuit::bitsToUint256(r_bits);
    
    // Extract a_pk (256 bits)
    std::vector<bool> a_pk_bits(bits.begin() + 64 + 256 + 256, bits.begin() + 64 + 256 + 256 + 256);
    note.a_pk = MerkleCircuit::bitsToUint256(a_pk_bits);
    
    return note;
}

Note Note::random(uint64_t value) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dis;
    
    auto randomUint256 = [&]() {
        uint256 result;
        for (int i = 0; i < 8; ++i) {
            uint32_t randomValue = dis(gen);
            std::memcpy(result.begin() + i * 4, &randomValue, 4);
        }
        return result;
    };
    
    return Note(value, randomUint256(), randomUint256(), randomUint256());
}

Note Note::createRandom(uint64_t value, const std::vector<bool>& recipient_a_pk) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dis;
    
    auto randomUint256 = [&]() {
        uint256 result;
        for (int i = 0; i < 8; ++i) {
            uint32_t randomValue = dis(gen);
            std::memcpy(result.begin() + i * 4, &randomValue, 4);
        }
        return result;
    };
    
    // Convert recipient public key bits to uint256
    uint256 a_pk = MerkleCircuit::bitsToUint256(recipient_a_pk);
    
    return Note(value, randomUint256(), randomUint256(), a_pk);
}

std::vector<uint8_t> Note::serialize() const {
    std::vector<uint8_t> data;
    data.reserve(8 + 32 + 32 + 32); // value + rho + r + a_pk
    
    // Serialize value (8 bytes, little-endian)
    for (int i = 0; i < 8; ++i) {
        data.push_back((value >> (i * 8)) & 0xFF);
    }
    
    // Serialize rho (32 bytes)
    data.insert(data.end(), rho.begin(), rho.end());
    
    // Serialize r (32 bytes)
    data.insert(data.end(), r.begin(), r.end());
    
    // Serialize a_pk (32 bytes)
    data.insert(data.end(), a_pk.begin(), a_pk.end());
    
    return data;
}

Note Note::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 8 + 32 + 32 + 32) {
        throw std::invalid_argument("Insufficient data for Note deserialization");
    }
    
    Note note;
    
    // Deserialize value (8 bytes, little-endian)
    note.value = 0;
    for (int i = 0; i < 8; ++i) {
        note.value |= (static_cast<uint64_t>(data[i]) << (i * 8));
    }
    
    // Deserialize rho (32 bytes)
    std::memcpy(note.rho.begin(), data.data() + 8, 32);
    
    // Deserialize r (32 bytes)
    std::memcpy(note.r.begin(), data.data() + 8 + 32, 32);
    
    // Deserialize a_pk (32 bytes)
    std::memcpy(note.a_pk.begin(), data.data() + 8 + 32 + 32, 32);
    
    return note;
}

FieldT Note::generateRandomFieldElement() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    
    // Generate a random field element (be careful with field modulus)
    return FieldT(dis(gen));
}

bool Note::isValid() const {
    // Basic validation - value should be non-zero and components should be non-zero
    if (value == 0) return false;
    
    // Check if uint256 values are not all zeros
    auto isZero = [](const uint256& val) {
        for (size_t i = 0; i < 32; ++i) {
            if (val.begin()[i] != 0) return false;
        }
        return true;
    };
    
    return !isZero(rho) && !isZero(r) && !isZero(a_pk);
}

// AddressKeyPair implementation
AddressKeyPair AddressKeyPair::generate() {
    AddressKeyPair keypair;
    
    // Generate random 256-bit spend key
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dis;
    
    for (size_t i = 0; i < 256; ++i) {
        keypair.a_sk[i] = (dis(gen) % 2) == 1;
    }
    
    // Derive public key and viewing key
    keypair.derivePublicKey();
    keypair.deriveViewingKey();
    
    return keypair;
}

void AddressKeyPair::derivePublicKey() {
    // a_pk = SHA256(a_sk)
    auto a_sk_bytes = MerkleCircuit::bitsToBytes(a_sk);
    
    std::array<uint8_t, 32> pk_hash;
    SHA256(a_sk_bytes.data(), a_sk_bytes.size(), pk_hash.data());
    
    // Convert back to bits
    a_pk = MerkleCircuit::bytesToBits(std::vector<uint8_t>(pk_hash.begin(), pk_hash.end()));
}

void AddressKeyPair::deriveViewingKey() {
    // ivk = SHA256(a_sk || "ivk")
    auto a_sk_bytes = MerkleCircuit::bitsToBytes(a_sk);
    
    std::vector<uint8_t> input;
    input.insert(input.end(), a_sk_bytes.begin(), a_sk_bytes.end());
    input.insert(input.end(), {'i', 'v', 'k'});
    
    std::array<uint8_t, 32> ivk_hash;
    SHA256(input.data(), input.size(), ivk_hash.data());
    
    // Convert to bits
    ivk = MerkleCircuit::bytesToBits(std::vector<uint8_t>(ivk_hash.begin(), ivk_hash.end()));
}

uint256 AddressKeyPair::getAddressHash() const {
    // Return hash of public key for address identification
    auto a_pk_bytes = MerkleCircuit::bitsToBytes(a_pk);
    
    uint256 addr_hash;
    SHA256(a_pk_bytes.data(), a_pk_bytes.size(), addr_hash.begin());
    
    return addr_hash;
}

bool AddressKeyPair::canSpend(const Note& note) const {
    // Check if this keypair can spend the given note
    // This would involve checking if a_pk matches the note's recipient
    auto our_pk_bytes = MerkleCircuit::bitsToBytes(a_pk);
    uint256 our_pk_hash;
    SHA256(our_pk_bytes.data(), our_pk_bytes.size(), our_pk_hash.begin());
    
    return our_pk_hash == note.a_pk;
}

std::vector<uint8_t> AddressKeyPair::serialize() const {
    std::vector<uint8_t> data;
    data.reserve(3 * 32); // 3 keys * 32 bytes each (256 bits)
    
    // Serialize each key
    auto a_sk_bytes = MerkleCircuit::bitsToBytes(a_sk);
    auto a_pk_bytes = MerkleCircuit::bitsToBytes(a_pk);
    auto ivk_bytes = MerkleCircuit::bitsToBytes(ivk);
    
    data.insert(data.end(), a_sk_bytes.begin(), a_sk_bytes.end());
    data.insert(data.end(), a_pk_bytes.begin(), a_pk_bytes.end());
    data.insert(data.end(), ivk_bytes.begin(), ivk_bytes.end());
    
    return data;
}

AddressKeyPair AddressKeyPair::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 3 * 32) {
        throw std::invalid_argument("Insufficient data for AddressKeyPair deserialization");
    }
    
    AddressKeyPair keypair;
    
    // Deserialize each key
    std::vector<uint8_t> a_sk_bytes(data.begin(), data.begin() + 32);
    std::vector<uint8_t> a_pk_bytes(data.begin() + 32, data.begin() + 64);
    std::vector<uint8_t> ivk_bytes(data.begin() + 64, data.begin() + 96);
    
    keypair.a_sk = MerkleCircuit::bytesToBits(a_sk_bytes);
    keypair.a_pk = MerkleCircuit::bytesToBits(a_pk_bytes);
    keypair.ivk = MerkleCircuit::bytesToBits(ivk_bytes);
    
    return keypair;
}

} // namespace zkp
} // namespace ripple