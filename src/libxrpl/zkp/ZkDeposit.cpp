#include "ZkDeposit.h"
#include "ZKProver.h"
#include "circuits/MerkleCircuit.h"
#include "Note.h"
#include <xrpld/ledger/ApplyViewImpl.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/jss.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/basics/Log.h>

namespace ripple {

// Add keylet for shielded pool
static Keylet
shieldedPoolKeylet()
{
    return Keylet(ltSHIELDED_POOL, uint256());
}

namespace keylet {
inline Keylet shielded_pool()
{
    return ::ripple::shieldedPoolKeylet();
}
}

NotTEC
ZkDeposit::preflight(PreflightContext const& ctx)
{
    // Check if zero-knowledge privacy feature is enabled
    if (!ctx.rules.enabled(featureZeroKnowledgePrivacy))
    {
        JLOG(ctx.j.debug()) << "ZK Privacy feature not enabled";
        return temDISABLED;
    }

    // Basic transaction validation
    if (auto const ret = preflight1(ctx); !isTesSuccess(ret))
        return ret;

    // Validate required fields are present
    if (!ctx.tx.isFieldPresent(sfZKProof))
    {
        JLOG(ctx.j.debug()) << "Missing ZKProof field";
        return temMALFORMED;
    }

    if (!ctx.tx.isFieldPresent(sfCommitment))
    {
        JLOG(ctx.j.debug()) << "Missing Commitment field";
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
        JLOG(ctx.j.debug()) << "Invalid deposit amount";
        return temBAD_AMOUNT;
    }

    // Basic validation of ZK proof length
    auto const zkProofBlob = ctx.tx.getFieldVL(sfZKProof);
    if (zkProofBlob.empty() || zkProofBlob.size() > 10000)
    {
        JLOG(ctx.j.debug()) << "Invalid ZK proof size: " << zkProofBlob.size();
        return temMALFORMED;
    }

    return preflight2(ctx);
}

TER
ZkDeposit::preclaim(PreclaimContext const& ctx)
{
    // Initialize ZK system if not already done
    if (!zkp::ZkProver::isInitialized)
    {
        zkp::ZkProver::initialize();
    }

    // Verify the zero-knowledge proof
    if (!verifyZkProof(ctx))
    {
        JLOG(ctx.j.warn()) << "ZK proof verification failed";
        return temBAD_PROOF;
    }

    return tesSUCCESS;
}

TER
ZkDeposit::doApply()
{
    // Get deposit details from transaction
    auto const& tx = ctx_.tx;
    auto const account = tx.getAccountID(sfAccount);
    auto const amount = tx.getFieldAmount(sfAmount);
    auto const commitment = tx.getFieldH256(sfCommitment);

    JLOG(j_.info()) << "Processing ZK deposit: " << amount.getText() 
                    << " from " << toBase58(account);

    // Get or create shielded pool
    auto shieldedPoolSLE = getShieldedPool(true);
    if (!shieldedPoolSLE)
    {
        JLOG(j_.error()) << "Failed to get/create shielded pool";
        return tecINTERNAL;
    }

    // Transfer XRP from account to pool
    TER transferResult = transferToPool(account, amount);
    if (!isTesSuccess(transferResult))
    {
        JLOG(j_.error()) << "Failed to transfer XRP to pool: " << transferResult;
        return transferResult;
    }

    // Update pool balance
    auto currentBalance = shieldedPoolSLE->getFieldAmount(sfBalance);
    auto newBalance = currentBalance + amount;
    shieldedPoolSLE->setFieldAmount(sfBalance, newBalance);

    // Update pool commitment count
    auto commitmentCount = shieldedPoolSLE->getFieldU32(sfPoolSize);
    shieldedPoolSLE->setFieldU32(sfPoolSize, commitmentCount + 1);

    // Store the latest commitment (for reference)
    shieldedPoolSLE->setFieldH256(sfCurrentRoot, commitment);

    view().update(shieldedPoolSLE);

    JLOG(j_.info()) << "ZK deposit completed successfully. "
                    << "Amount: " << amount.getText() 
                    << ", Pool balance: " << newBalance.getText()
                    << ", Commitment: " << commitment;

    return tesSUCCESS;
}

bool
ZkDeposit::verifyZkProof(PreclaimContext const& ctx)
{
    try {
        // Extract transaction data
        auto const& tx = ctx.tx;
        auto const zkProofBlob = tx.getFieldVL(sfZKProof);
        auto const commitment = tx.getFieldH256(sfCommitment);

        JLOG(ctx.j.debug()) << "Verifying ZK proof for deposit";
        JLOG(ctx.j.trace()) << "Commitment: " << commitment;

        // Convert proof data to vector
        std::vector<unsigned char> proofData(zkProofBlob.begin(), zkProofBlob.end());

        // For deposits, we need to extract the ProofData structure from transaction
        // The transaction should contain the serialized ProofData
        
        // Deserialize the proof to get all public inputs
        // Note: This assumes the transaction stores a complete ProofData structure
        
        // For now, create a ProofData structure with extracted values
        zkp::ProofData proofDataStruct;
        proofDataStruct.proof = proofData;
        
        // Extract other public inputs from transaction fields
        // Convert commitment to FieldT (use as anchor for deposits)
        proofDataStruct.anchor = zkp::MerkleCircuit::uint256ToFieldElement(commitment);

        // For deposits, nullifier might be stored in a different field or computed
        auto nullifier = tx.getFieldH256(sfNullifier);
        proofDataStruct.nullifier = zkp::MerkleCircuit::uint256ToFieldElement(nullifier);

        // Value commitment should be extracted from the proof or computed
        // For now, use commitment as placeholder
        proofDataStruct.value_commitment = zkp::MerkleCircuit::uint256ToFieldElement(commitment);

        JLOG(ctx.j.trace()) << "Anchor field: " << proofDataStruct.anchor;
        JLOG(ctx.j.trace()) << "Nullifier field: " << proofDataStruct.nullifier;
        JLOG(ctx.j.trace()) << "Value commitment field: " << proofDataStruct.value_commitment;

        // Verify using the new ProofData structure
        bool verificationResult = zkp::ZkProver::verifyDepositProof(proofDataStruct);

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
ZkDeposit::transferToPool(AccountID const& source, STAmount const& amount)
{
    try {
        // Get source account SLE
        auto const sourceKeylet = keylet::account(source);
        auto sourceSLE = view().peek(sourceKeylet);

        if (!sourceSLE)
        {
            JLOG(j_.warn()) << "Source account does not exist: " << toBase58(source);
            return terNO_ACCOUNT;
        }

        // Check source account balance
        auto sourceBalance = sourceSLE->getFieldAmount(sfBalance);
        if (sourceBalance < amount)
        {
            JLOG(j_.warn()) << "Insufficient balance. Available: " << sourceBalance.getText()
                           << ", Required: " << amount.getText();
            return terINSUF_FEE_B;
        }

        // Deduct amount from source account
        auto newSourceBalance = sourceBalance - amount;
        sourceSLE->setFieldAmount(sfBalance, newSourceBalance);
        view().update(sourceSLE);

        JLOG(j_.debug()) << "Transferred " << amount.getText() 
                        << " from " << toBase58(source)
                        << ". New balance: " << newSourceBalance.getText();

        return tesSUCCESS;

    } catch (std::exception const& e) {
        JLOG(j_.error()) << "Exception during XRP transfer: " << e.what();
        return tecINTERNAL;
    }
}

std::shared_ptr<SLE>
ZkDeposit::getShieldedPool(bool create)
{
    Keylet poolKeylet = keylet::shielded_pool();
    auto shieldedPoolSLE = view().peek(poolKeylet);

    if (!shieldedPoolSLE && create)
    {
        JLOG(j_.info()) << "Creating new shielded pool";

        // Create the shielded pool SLE
        shieldedPoolSLE = std::make_shared<SLE>(poolKeylet);

        // Initialize pool with zero balance
        shieldedPoolSLE->setFieldAmount(sfBalance, STAmount{});

        // Initialize commitment count
        shieldedPoolSLE->setFieldU32(sfPoolSize, 0);

        // Initialize with empty root
        shieldedPoolSLE->setFieldH256(sfCurrentRoot, uint256{});

        view().insert(shieldedPoolSLE);

        JLOG(j_.info()) << "Created shielded pool with zero balance";
    }

    return shieldedPoolSLE;
}

// Helper function to create a complete deposit proof (for client use)
zkp::ProofData
ZkDeposit::createDepositProof(
    uint64_t amount,
    const std::string& spendKey)
{
    try {
        // Initialize ZK system
        if (!zkp::ZkProver::isInitialized)
        {
            zkp::ZkProver::initialize();
        }

        std::cout << "Creating deposit proof using Zcash-style approach" << std::endl;
        std::cout << "Amount: " << amount << std::endl;
        std::cout << "Spend key: " << spendKey << std::endl;

        // Create note
        zkp::Note depositNote = zkp::ZkProver::createRandomNote(amount);

        std::cout << "Created note:" << std::endl;
        std::cout << "  Value: " << depositNote.value << std::endl;
        std::cout << "  Commitment: " << depositNote.commitment() << std::endl;

        // Then create proof using the note
        auto proofData = zkp::ZkProver::createDepositProof(depositNote);

        std::cout << "Deposit proof created successfully" << std::endl;
        std::cout << "Proof size: " << proofData.proof.size() << " bytes" << std::endl;

        return proofData;

    } catch (std::exception const& e) {
        std::cerr << "Error creating deposit proof: " << e.what() << std::endl;
        return {};
    }
}

} // namespace ripple