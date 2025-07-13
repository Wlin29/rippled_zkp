// #include "CommitmentGenerator.h"
// #include <xrpl/protocol/digest.h>
// #include <xrpl/basics/StringUtilities.h>
// #include <openssl/rand.h>
// #include <sstream>
// #include <iomanip>

// namespace ripple {
// namespace zkp {

// Commitment CommitmentGenerator::generateCommitment(uint64_t amount, const AccountID& recipient) {
//     // Generate a random blinding factor
//     std::string blindingFactor = generateRandomBlindingFactor();
    
//     // Create the commitment hash
//     uint256 commitmentHash = hashCommitment(amount, recipient, blindingFactor);
    
//     // Generate the nullifier
//     uint256 nullifier = generateNullifier(commitmentHash, blindingFactor);
    
//     // Return the complete commitment structure
//     Commitment result;
//     result.commitment = commitmentHash;
//     result.nullifier = nullifier;
//     result.blindingFactor = blindingFactor;
//     result.amount = amount;
//     result.recipient = recipient;
    
//     return result;
// }

// uint256 CommitmentGenerator::generateNullifier(const uint256& commitment, const std::string& secret) {
//     // Concatenate commitment and secret
//     std::string preimage = strHex(commitment) + secret;
    
//     return sha512Half(preimage);
// }

// std::string CommitmentGenerator::generateRandomBlindingFactor() {
//     // Generate 32 bytes of random data
//     unsigned char buffer[32];
//     RAND_bytes(buffer, sizeof(buffer));
    
//     // Convert to hex string
//     std::stringstream ss;
//     for (int i = 0; i < 32; i++) {
//         ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]);
//     }
    
//     return ss.str();
// }

// uint256 CommitmentGenerator::hashCommitment(
//     uint64_t amount, 
//     const AccountID& recipient, 
//     const std::string& blindingFactor) 
// {
//     // Concatenate all components
//     std::string amountStr = std::to_string(amount);
//     std::string recipientStr = strHex(recipient);
    
//     std::string preimage = amountStr + recipientStr + blindingFactor;
    
//     return sha512Half(preimage);
// }

// } // namespace zkp
// } // namespace ripple
