#pragma once

#include <xrpl/basics/base_uint.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <vector>
#include <string>
#include <array>

// Forward declare MerkleCircuit to avoid circular dependency
namespace ripple { namespace zkp { class MerkleCircuit; } }

namespace ripple {
namespace zkp {

using DefaultCurve = libff::alt_bn128_pp;
using FieldT = libff::Fr<DefaultCurve>;

/**
 * Note structure
 * A note contains:
 * - value: the amount of the note (uint64_t)
 * - rho: uniqueness randomizer (prevents double-spending) (uint256)
 * - r: commitment randomness (for hiding) (uint256)
 * - a_pk: paying key (spend authority) (uint256)
 */
struct Note {
    uint64_t value;          // Amount in the note
    uint256 rho;             // Uniqueness randomizer (32 bytes)
    uint256 r;               // Commitment randomness (32 bytes)
    uint256 a_pk;            // Paying key (32 bytes)
    
    Note() = default;
    
    Note(uint64_t val, const uint256& uniqueness, const uint256& randomness, const uint256& payingKey)
        : value(val), rho(uniqueness), r(randomness), a_pk(payingKey) {}
    
    /**
     * Compute the note commitment using commitment scheme:
     * cm = SHA256(value || rho || r || a_pk)
     */
    uint256 commitment() const;
    
    /**
     * Alternative name for commitment()
     */
    uint256 computeCommitment() const { return commitment(); }
    
    /**
     * Compute the nullifier using nullifier derivation:
     * nf = SHA256(a_sk || rho) where a_sk is the spend key corresponding to a_pk
     */
    uint256 nullifier(const uint256& a_sk) const;
    
    /**
     * Alternative name for nullifier() 
     */
    uint256 computeNullifier(const uint256& a_sk) const { return nullifier(a_sk); }
    
    /**
     * Convert note to bits for circuit input
     */
    std::vector<bool> toBits() const;
    
    /**
     * Create note from bits
     */
    static Note fromBits(const std::vector<bool>& bits);
    
    /**
     * Generate a random note for testing
     */
    static Note random(uint64_t value);
    
    /**
     * Create a random note with specific recipient (needed by test)
     */
    static Note createRandom(uint64_t value, const std::vector<bool>& recipient_a_pk);
    
    /**
     * Serialize note for storage/transmission (encrypted)
     */
    std::vector<uint8_t> serialize() const;
    
    /**
     * Deserialize note from storage
     */
    static Note deserialize(const std::vector<uint8_t>& data);
    
    /**
     * Generate random field element for rho/r
     */
    static FieldT generateRandomFieldElement();
    
    /**
     * Validate note parameters
     */
    bool isValid() const;
};

/**
 * Address Key Pair
 * Represents a shielded address with viewing and spending capabilities
 */
struct AddressKeyPair {
    std::vector<bool> a_sk;  // Secret key (256 bits) - for spending
    std::vector<bool> a_pk;  // Public key (256 bits) - for receiving
    std::vector<bool> ivk;   // Incoming viewing key (256 bits) - for scanning
    
    // Default constructor
    AddressKeyPair() : a_sk(256, false), a_pk(256, false), ivk(256, false) {}
    
    /**
     * Generate a new random address key pair
     */
    static AddressKeyPair generate();
    
    /**
     * Derive public key from secret key using SHA256
     */
    void derivePublicKey();
    
    /**
     * Derive viewing key from secret key using SHA256
     */
    void deriveViewingKey();
    
    /**
     * Get address hash for identification
     */
    uint256 getAddressHash() const;
    
    /**
     * Check if this keypair can spend the given note
     */
    bool canSpend(const Note& note) const;
    
    /**
     * Serialize keypair for storage
     */
    std::vector<uint8_t> serialize() const;
    
    /**
     * Deserialize keypair from storage
     */
    static AddressKeyPair deserialize(const std::vector<uint8_t>& data);
};

} // namespace zkp
} // namespace ripple