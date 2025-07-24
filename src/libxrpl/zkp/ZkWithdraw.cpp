#include "ZkWithdraw.h"
#include "ZKProver.h"
#include "Note.h"
#include <xrpld/ledger/ApplyViewImpl.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/jss.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/basics/Log.h>
#include <xrpl/protocol/digest.h>

namespace ripple {

// Add this to create Keylet for shielded pools
static Keylet
shieldedPoolKeylet()
{
    return Keylet(ltSHIELDED_POOL, uint256());
}

// In the Keylet namespace
namespace keylet {
inline Keylet nullifier(uint256 const& id)
{
    return Keylet(ltNULLIFIER, id);
}

inline Keylet shielded_pool()
{
    return ::ripple::shieldedPoolKeylet();
}
}

NotTEC
ZkWithdraw::preflight(PreflightContext const& ctx)
{
    // Check if zero-knowledge privacy feature is enabled
    if (!ctx.rules.enabled(featureZeroKnowledgePrivacy))
    {
        JLOG(ctx.j.debug()) << "ZK Privacy feature not enabled";
        return temDISABLED;
    }

    // Validate required fields are present
    if (!ctx.tx.isFieldPresent(sfZKProof))
    {
        JLOG(ctx.j.debug()) << "Missing ZKProof field";
        return temMALFORMED;
    }

    if (!ctx.tx.isFieldPresent(sfNullifier))
    {
        JLOG(ctx.j.debug()) << "Missing Nullifier field";
        return temMALFORMED;
    }

    if (!ctx.tx.isFieldPresent(sfMerkleRoot))
    {
        JLOG(ctx.j.debug()) << "Missing MerkleRoot field";
        return temMALFORMED;
    }

    if (!ctx.tx.isFieldPresent(sfDestination))
    {
        JLOG(ctx.j.debug()) << "Missing Destination field";
        return temMALFORMED;
    }

    if (!ctx.tx.isFieldPresent(sfAmount))
    {
        JLOG(ctx.j.debug()) << "Missing Amount field";
        return temMALFORMED;
    }

    // Validate amount is positive XRP
    auto const amount = ctx.tx.getFieldAmount(sfAmount);
    if (!amount.native() || amount <= beast::zero)
    {
        JLOG(ctx.j.debug()) << "Invalid withdrawal amount";
        return temBAD_AMOUNT;
    }

    // Basic validation of ZK proof length
    auto const zkProofBlob = ctx.tx.getFieldVL(sfZKProof);
    if (zkProofBlob.empty() || zkProofBlob.size() > 10000) // Reasonable size limits
    {
        JLOG(ctx.j.debug()) << "Invalid ZK proof size: " << zkProofBlob.size();
        return temMALFORMED;
    }

    return preflight2(ctx);
}

TER
ZkWithdraw::preclaim(PreclaimContext const& ctx)
{
    // Initialize ZK system if not already done
    if (!zkp::ZkProver::isInitialized)
    {
        zkp::ZkProver::initialize();
    }

    // Check if nullifier has already been used (prevent double-spending)
    auto const nullifier = ctx.tx.getFieldH256(sfNullifier);
    auto nullifierKeylet = keylet::nullifier(nullifier);
    
    if (ctx.view.exists(nullifierKeylet))
    {
        JLOG(ctx.j.warn()) << "Nullifier already used: " << nullifier;
        return tecDUPLICATE;
    }

    // Verify the zero-knowledge proof
    if (!verifyZkProof(ctx))
    {
        JLOG(ctx.j.warn()) << "ZK proof verification failed";
        return temBAD_PROOF;
    }

    // Check shielded pool has sufficient balance
    Keylet poolKeylet = keylet::shielded_pool();
    auto shieldedPoolSLE = ctx.view.read(poolKeylet);
    
    if (!shieldedPoolSLE)
    {
        JLOG(ctx.j.warn()) << "Shielded pool does not exist";
        return tecNO_ENTRY;
    }

    auto const withdrawalAmount = ctx.tx.getFieldAmount(sfAmount);
    auto const poolBalance = shieldedPoolSLE->getFieldAmount(sfBalance);
    
    if (poolBalance < withdrawalAmount)
    {
        JLOG(ctx.j.warn()) << "Insufficient balance in shielded pool. Pool: " 
                          << poolBalance << ", Requested: " << withdrawalAmount;
        return tecINSUFFICIENT_FUNDS;
    }

    return tesSUCCESS;
}

TER
ZkWithdraw::doApply()
{
    // Get withdrawal details from transaction
    auto const& tx = ctx_.tx;
    auto const destination = tx.getAccountID(sfDestination);
    auto const amount = tx.getFieldAmount(sfAmount);
    auto const nullifier = tx.getFieldH256(sfNullifier);

    JLOG(j_.info()) << "Processing ZK withdrawal: " << amount.getText() 
                    << " to " << toBase58(destination);

    // Update shielded pool balance
    Keylet poolKeylet = keylet::shielded_pool();
    auto shieldedPoolSLE = view().peek(poolKeylet);
    
    if (!shieldedPoolSLE)
    {
        JLOG(j_.error()) << "Shielded pool SLE not found during apply";
        return tecINTERNAL;
    }

    // Decrease pool balance
    auto currentBalance = shieldedPoolSLE->getFieldAmount(sfBalance);
    auto newBalance = currentBalance - amount;
    
    if (newBalance < beast::zero)
    {
        JLOG(j_.error()) << "Pool balance would go negative";
        return tecINSUFFICIENT_FUNDS;
    }
    
    shieldedPoolSLE->setFieldAmount(sfBalance, newBalance);
    view().update(shieldedPoolSLE);

    JLOG(j_.debug()) << "Updated pool balance from " << currentBalance.getText() 
                     << " to " << newBalance.getText();

    // Record nullifier to prevent double-spending
    auto nullifierKeylet = keylet::nullifier(nullifier);
    auto nullifierSLE = std::make_shared<SLE>(nullifierKeylet);
    nullifierSLE->setFieldH256(sfNullifier, nullifier);
    nullifierSLE->setFieldU32(sfTimestamp, view().parentCloseTime().time_since_epoch().count());
    view().insert(nullifierSLE);

    JLOG(j_.debug()) << "Recorded nullifier: " << nullifier;

    // Transfer XRP to destination account
    TER transferResult = transferXRP(destination, amount);
    if (!isTesSuccess(transferResult))
    {
        JLOG(j_.error()) << "Failed to transfer XRP to destination: " << transferResult;
        return transferResult;
    }

    JLOG(j_.info()) << "ZK withdrawal completed successfully. "
                    << "Amount: " << amount.getText() 
                    << ", Destination: " << toBase58(destination)
                    << ", Nullifier: " << nullifier;

    return tesSUCCESS;
}

bool
ZkWithdraw::verifyZkProof(PreclaimContext const& ctx)
{
    try {
        // Extract transaction data
        auto const& tx = ctx.tx;
        auto const zkProofBlob = tx.getFieldVL(sfZKProof);
        auto const merkleRoot = tx.getFieldH256(sfMerkleRoot);
        auto const nullifier = tx.getFieldH256(sfNullifier);

        JLOG(ctx.j.debug()) << "Verifying ZK proof for withdrawal";
        JLOG(ctx.j.trace()) << "Merkle root: " << merkleRoot;
        JLOG(ctx.j.trace()) << "Nullifier: " << nullifier;

        // Convert proof data to vector
        std::vector<unsigned char> proofData(zkProofBlob.begin(), zkProofBlob.end());

        // Create ProofData structure for new verification method
        zkp::ProofData proofDataStruct;
        proofDataStruct.proof = proofData;

        // Convert merkle root to FieldT
        proofDataStruct.anchor = zkp::MerkleCircuit::uint256ToFieldElement(merkleRoot);

        // Convert nullifier to FieldT  
        proofDataStruct.nullifier = zkp::MerkleCircuit::uint256ToFieldElement(nullifier);

        // For value commitment, we need to extract it from the transaction or compute it
        // For now, use a placeholder - this should be provided in the transaction
        auto amount = tx.getFieldAmount(sfAmount);
        uint256 valueCommitmentHash = sha512Half(std::to_string(amount.xrp().drops()));
        proofDataStruct.value_commitment = zkp::MerkleCircuit::uint256ToFieldElement(valueCommitmentHash);

        JLOG(ctx.j.trace()) << "Anchor field: " << proofDataStruct.anchor;
        JLOG(ctx.j.trace()) << "Nullifier field: " << proofDataStruct.nullifier;  
        JLOG(ctx.j.trace()) << "Value commitment field: " << proofDataStruct.value_commitment;

        // Verify using the new ProofData structure
        bool verificationResult = zkp::ZkProver::verifyWithdrawalProof(proofDataStruct);

        JLOG(ctx.j.debug()) << "ZK proof verification result: " 
                           << (verificationResult ? "PASS" : "FAIL");

        return verificationResult;

    } catch (std::exception const& e) {
        JLOG(ctx.j.error()) << "Exception during ZK proof verification: " << e.what();
        return false;
    } catch (...) {
        JLOG(ctx.j.error()) << "Unknown exception during ZK proof verification";
        return false;
    }
}

TER
ZkWithdraw::transferXRP(AccountID const& destination, STAmount const& amount)
{
    try {
        // Get or create destination account
        auto const destinationKeylet = keylet::account(destination);
        auto destinationSLE = view().peek(destinationKeylet);

        if (!destinationSLE)
        {
            // Create account if it doesn't exist (assuming we have permission)
            auto const reserve = view().fees().accountReserve(0);
            if (amount < reserve)
            {
                JLOG(j_.warn()) << "Cannot create account: insufficient amount for reserve";
                return tecNO_DST_INSUF_XRP;
            }

            destinationSLE = std::make_shared<SLE>(destinationKeylet);
            destinationSLE->setAccountID(sfAccount, destination);
            destinationSLE->setFieldAmount(sfBalance, amount);
            
            view().insert(destinationSLE);
            
            JLOG(j_.info()) << "Created new account for destination: " << toBase58(destination);
        }
        else
        {
            // Add amount to existing account
            auto currentBalance = destinationSLE->getFieldAmount(sfBalance);
            auto newBalance = currentBalance + amount;
            
            destinationSLE->setFieldAmount(sfBalance, newBalance);
            view().update(destinationSLE);
            
            JLOG(j_.debug()) << "Updated destination balance from " << currentBalance.getText()
                            << " to " << newBalance.getText();
        }

        return tesSUCCESS;

    } catch (std::exception const& e) {
        JLOG(j_.error()) << "Exception during XRP transfer: " << e.what();
        return tecINTERNAL;
    }
}

// Add helper function to create withdrawal proof 
zkp::ProofData
ZkWithdraw::createWithdrawalProof(
    const zkp::Note& inputNote,
    const uint256& spendingKey,
    const std::vector<uint256>& authPath,
    size_t position,
    const uint256& merkleRoot)
{
    try {
        if (!zkp::ZkProver::isInitialized) {
            zkp::ZkProver::initialize();
        }

        std::cout << "Creating withdrawal proof using Zcash-style approach" << std::endl;
        std::cout << "Input note value: " << inputNote.value << std::endl;
        std::cout << "Input note commitment: " << inputNote.commitment() << std::endl;
        std::cout << "Merkle root: " << merkleRoot << std::endl;
        std::cout << "Auth path length: " << authPath.size() << std::endl;
        std::cout << "Position: " << position << std::endl;

        auto proofData = zkp::ZkProver::createWithdrawalProof(
            inputNote, spendingKey, authPath, position, merkleRoot);

        std::cout << "Withdrawal proof created successfully" << std::endl;
        std::cout << "Proof size: " << proofData.proof.size() << " bytes" << std::endl;

        return proofData;

    } catch (std::exception const& e) {
        std::cerr << "Error creating withdrawal proof: " << e.what() << std::endl;
        return {};
    }
}

} // namespace ripple