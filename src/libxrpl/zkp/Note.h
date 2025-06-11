#pragma once
#include <libxrpl/zkp/circuits/MerkleCircuit.h>
#include <xrpl/protocol/UintTypes.h>  // ADD THIS - for uint256
#include <openssl/sha.h>
#include <random>
#include <optional>  // ADD THIS - for std::optional

namespace ripple {
namespace zkp {

/**
 * Zcash-style Note structure (Sapling/Orchard compatible)
 * Based on ZCash Protocol Specification Section 4.1.2
 */
struct Note {
    // Core note data
    uint64_t value;                    // Note value in atomic units
    FieldT rho;                       // Nullifier seed (random 32 bytes)
    FieldT r;                         // Randomness for commitment (random 32 bytes)
    std::vector<bool> a_pk;           // Address public key (256 bits)
    
    // Constructor
    Note() : value(0), rho(FieldT::zero()), r(FieldT::zero()), a_pk(256, false) {}
    
    Note(uint64_t val, const FieldT& rho_val, const FieldT& r_val, const std::vector<bool>& pk)
        : value(val), rho(rho_val), r(r_val), a_pk(pk) {}
    
    /**
     * Compute note commitment using Zcash formula:
     * cm = SHA256(a_pk || value || rho || r)
     * This is the value stored as a leaf in the Merkle tree
     */
    uint256 computeCommitment() const;
    
    /**
     * Compute nullifier using Zcash formula:
     * nf = SHA256(a_sk || rho)
     * Used to prevent double-spending
     */
    uint256 computeNullifier(const std::vector<bool>& a_sk) const;
    
    /**
     * Create a new note with random parameters
     */
    static Note createRandom(uint64_t value, const std::vector<bool>& recipient_pk);
    
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
 * Zcash-style Address Key Pair
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
     * Derive public key from secret key: a_pk = SHA256(a_sk)
     */
    void derivePublicKey();
    
    /**
     * Derive incoming viewing key: ivk = SHA256(a_sk || "ivk")
     */
    void deriveViewingKey();
    
    /**
     * Get the shielded address hash (for public reference)
     */
    uint256 getAddressHash() const;
    
    /**
     * Check if this key pair can spend a note
     */
    bool canSpend(const Note& note) const;
    
    /**
     * Serialize key pair for wallet storage
     */
    std::vector<uint8_t> serialize() const;
    
    /**
     * Deserialize from wallet storage
     */
    static AddressKeyPair deserialize(const std::vector<uint8_t>& data);
};

/**
 * Note Plaintext - unencrypted note data for transmission
 * Used when sending notes to recipients
 */
struct NotePlaintext {
    Note note;
    std::vector<uint8_t> memo;  // 512-byte memo field
    
    /**
     * Encrypt note for recipient
     */
    std::vector<uint8_t> encrypt(const std::vector<bool>& recipient_pk) const;
    
    /**
     * Decrypt note with viewing key
     */
    static std::optional<NotePlaintext> decrypt(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<bool>& viewing_key);
};

} // namespace zkp
} // namespace ripple