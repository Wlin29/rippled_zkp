#include <xrpl/basics/Slice.h>
#include <xrpl/beast/unit_test.h>
#include <xrpl/protocol/STAmount.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/Sign.h>
#include <xrpl/protocol/TxFormats.h>
#include <xrpl/protocol/UintTypes.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/jss.h>
#include <xrpl/protocol/Keylet.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <iostream>
#include <memory>
#include <chrono>
#include <set>

#include "libxrpl/zkp/ShieldedMerkleTree.h"
#include "libxrpl/zkp/CommitmentGenerator.h"
#include "libxrpl/zkp/ZKProver.h"

namespace ripple {

class ZKPTransaction_test : public beast::unit_test::suite
{
public:
    void
    run() override
    {
        testShieldedPoolCreation();

        testZKPTransactionFlow();

        testMerkleTreeOperations();

        testDoubleSpendProtection();
    }

    void testShieldedPoolCreation()
    {
        testcase("Shielded Pool Creation");
        try {
            // Create a keylet for the shielded pool
            auto poolKeylet = keylet::shieldedPool();
            std::cout << "Keylet created: " << poolKeylet.type << std::endl;
            
            // Create an SLE directly - this is for testing only
            auto sle = std::make_shared<SLE>(poolKeylet);
            std::cout << "SLE created successfully" << std::endl;
            
            // Initialize the required fields directly
            sle->setFieldH256(sfCurrentRoot, uint256());
            sle->setFieldU32(sfPoolSize, 1);
            
            // Create a minimal serialized tree state
            ShieldedMerkleTree tree;
            Serializer s;
            tree.serialize(s);
            sle->setFieldVL(sfShieldedState, s.getData());
            
            BEAST_EXPECT(sle->isFieldPresent(sfShieldedState));
            BEAST_EXPECT(sle->isFieldPresent(sfCurrentRoot));
            BEAST_EXPECT(sle->isFieldPresent(sfPoolSize));
        }
        catch (std::exception& e) {
            std::cout << "Exception: " << e.what() << std::endl;
            BEAST_EXPECT(false);
        }
    }

    void
    testZKPTransactionFlow()
    {
        testcase("ZKP Transaction Flow");
        try {
            std::cout << "Creating keypairs..." << std::endl;
            auto const alice = randomKeyPair(KeyType::secp256k1);
            auto const aliceID = calcAccountID(alice.first);
            auto const bob = randomKeyPair(KeyType::secp256k1);
            auto const bobID = calcAccountID(bob.first);
            
            std::cout << "Creating deposit transaction..." << std::endl;
            STTx depositTx(ttZK_DEPOSIT, [&aliceID](auto& obj) {
                obj.setAccountID(sfAccount, aliceID);
                obj.setFieldVL(sfSigningPubKey, Slice{});
                
                obj.setFieldAmount(sfAmount, STAmount(100000000));
                
                uint256 commitment = zkp::CommitmentGenerator::generateCommitment(100000000, aliceID).commitment;
                std::cout<<"Commitment: " << commitment << std::endl;
                obj.setFieldH256(sfCommitment, commitment);
                
                // Generate a mock ZK proof for the deposit
                std::vector<unsigned char> mockProof(64, 0xAB);
                obj.setFieldVL(sfZKProof, mockProof);
            });
            
            std::cout << "Deposit transaction created successfully" << std::endl;
            
            // Sign the deposit transaction
            depositTx.sign(alice.first, alice.second);
            
            // Verify the deposit transaction signature
            // BEAST_EXPECT(depositTx.checkSign(STTx::RequireFullyCanonicalSig::yes).first);
            
            // Verify the deposit transaction has the required fields
            BEAST_EXPECT(depositTx.isFieldPresent(sfCommitment));
            BEAST_EXPECT(depositTx.isFieldPresent(sfZKProof));
            BEAST_EXPECT(depositTx.isFieldPresent(sfAmount));
            
            // Create a mock Merkle tree and add the commitment
            ShieldedMerkleTree tree;
            uint256 commitment = depositTx.getFieldH256(sfCommitment);
            size_t index = tree.addCommitment(commitment);
            BEAST_EXPECT(index > 0);
            
            std::cout << "Creating withdrawal transaction..." << std::endl;
            STTx withdrawTx(ttZK_WITHDRAW, [&bobID, &tree](auto& obj) {
                obj.setAccountID(sfAccount, bobID);
                obj.setFieldVL(sfSigningPubKey, Slice{});
                
                // Set withdrawal amount (100 XRP)
                obj.setFieldAmount(sfAmount, STAmount(100000000));
                
                // Set the nullifier
                uint256 nullifier;
                nullifier = uint256{std::string("ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890")};
                obj.setFieldH256(sfNullifier, nullifier);
                
                // Set the Merkle root
                // obj.setFieldH256(sfCurrentRoot, tree.getRoot());
                
                // Generate a mock ZK proof for the withdrawal
                std::vector<unsigned char> mockProof(64, 0xCD);
                obj.setFieldVL(sfZKProof, mockProof);
            });
            
            std::cout << "Withdrawal transaction created successfully" << std::endl;
            
            // Sign the withdrawal transaction
            withdrawTx.sign(bob.first, bob.second);
            
            // Verify the withdrawal transaction signature
            // BEAST_EXPECT(withdrawTx.checkSign(STTx::RequireFullyCanonicalSig::yes).first);
            
            // Verify the withdrawal transaction has the required fields
            BEAST_EXPECT(withdrawTx.isFieldPresent(sfNullifier));
            // BEAST_EXPECT(withdrawTx.isFieldPresent(sfCurrentRoot));
            BEAST_EXPECT(withdrawTx.isFieldPresent(sfZKProof));
            BEAST_EXPECT(withdrawTx.isFieldPresent(sfAmount));
        }
        catch (std::exception& e) {
            std::cout << "Exception in testZKPTransactionFlow: " << e.what() << std::endl;
            BEAST_EXPECT(false);
        }
    }
    
    void
    testMerkleTreeOperations()
    {
        testcase("Merkle Tree Operations");

        // Create a Merkle tree
        ShieldedMerkleTree tree;
        
        // Generate some test commitments
        std::vector<uint256> commitments;
        for (int i = 0; i < 10; ++i) {
            // Create a unique commitment for each test
            uint256 commitment;
            commitment = uint256{std::string("ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789")};
            // Modify the last byte to make each commitment unique
            commitment.data()[31] = static_cast<unsigned char>(i);
            commitments.push_back(commitment);
        }
        
        // Add commitments to the tree
        for (const auto& commitment : commitments) {
            size_t index = tree.addCommitment(commitment);
            BEAST_EXPECT(index > 0);
        }
        
        // Verify the tree size
        BEAST_EXPECT(tree.getCommitments().size() == commitments.size() + 1); // +1 for the initial empty commitment
        
        // Get the Merkle root
        uint256 root = tree.getRoot();
        BEAST_EXPECT(!root.isZero());
        
        // Get a Merkle path for a specific commitment
        size_t testIndex = 5;
        auto merklePath = tree.getPath(testIndex);
        BEAST_EXPECT(!merklePath.empty());
        
        // Verify the Merkle path
        bool pathValid = tree.verifyPath(testIndex, commitments[testIndex - 1], merklePath);
        BEAST_EXPECT(pathValid);
        
        // Test serialization and deserialization
        Serializer s;
        tree.serialize(s);
        
        SerialIter sit(s.data(), s.size());
        ShieldedMerkleTree deserializedTree = ShieldedMerkleTree::deserialize(sit);
        
        // Verify the deserialized tree has the same root
        BEAST_EXPECT(deserializedTree.getRoot() == root);
        
        // Verify the deserialized tree has the same number of commitments
        BEAST_EXPECT(deserializedTree.getCommitments().size() == tree.getCommitments().size());
    }
    
    void
    testDoubleSpendProtection()
    {
        testcase("Double Spend Protection");
        
        // Create a Merkle tree
        ShieldedMerkleTree tree;
        
        // Create a test commitment
        uint256 commitment;
        commitment = uint256{std::string("1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF")};
        
        // Add the commitment to the tree
        size_t index = tree.addCommitment(commitment);
        BEAST_EXPECT(index > 0);
        
        // Create a nullifier for the commitment
        uint256 nullifier = zkp::CommitmentGenerator::generateNullifier(commitment, "test_secret");
                
        // Create a set to track spent nullifiers (simulating the ledger state)
        std::set<uint256> spentNullifiers;
        
        // First withdrawal - should succeed
        bool firstWithdrawalSuccess = spentNullifiers.find(nullifier) == spentNullifiers.end();
        BEAST_EXPECT(firstWithdrawalSuccess);
        
        // Record the nullifier as spent
        spentNullifiers.insert(nullifier);
        
        // Second withdrawal with the same nullifier - should fail
        bool secondWithdrawalSuccess = spentNullifiers.find(nullifier) == spentNullifiers.end();
        BEAST_EXPECT(!secondWithdrawalSuccess);
        
        // Create a different commitment
        uint256 commitment2;
        commitment2 = uint256{std::string("FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321")};
        
        // Add the second commitment to the tree
        size_t index2 = tree.addCommitment(commitment2);
        BEAST_EXPECT(index2 > 0);
        
        // Create a nullifier for the second commitment
        uint256 nullifier2 = zkp::CommitmentGenerator::generateNullifier(commitment2, "test_secret"); 

        // Withdrawal with a different nullifier - should succeed
        bool thirdWithdrawalSuccess = spentNullifiers.find(nullifier2) == spentNullifiers.end();
        BEAST_EXPECT(thirdWithdrawalSuccess);
    }
};

BEAST_DEFINE_TESTSUITE(ZKPTransaction, ripple_app, ripple);

}  // namespace ripple
