#include "ZkPayment.h"
#include <ripple/app/ledger/Ledger.h>
#include <ripple/protocol/STObject.h>

namespace ripple {
  TER ZKPayment::preCheck() {
    auto const& tx = ctx_.tx;

    // 1. Check if ZK proof exists
    if (!tx.isFieldPresent(sfZKProof))
      return temMALFORMED;

    // 2. Verify the ZK proof (use your library, e.g., libsnark)
    if (!verify_zk_proof(tx.getFieldVL(sfZKProof), tx.getAccountID(sfAccount)))
      return temINVALID_PROOF;

    // 3. Check if nullifier is already used
    if (ctx_.view().exists(keylet::nullifier(tx[sfNullifier])))
      return temDUPLICATE_NULLIFIER;

    return Transactor::preCheck();
  }

  TER ZKPayment::doApply() {
    auto const& tx = ctx_.tx;
  
    // 1. Add the new commitment to the shielded pool
    auto slePool = ctx_.view().peek(keylet::shielded_pool());
    if (!slePool)
      return tefINTERNAL; // Handle missing pool
  
    STArray& commitments = slePool->peekFieldArray(sfCommitments);
    commitments.push_back(STObject(sfCommitment, tx[sfCommitment]));
  
    // 2. Add the nullifier to prevent reuse
    auto sleNullifier = std::make_shared<SLE>(keylet::nullifier(tx[sfNullifier]));
    sleNullifier->setFieldU32(sfFlags, 0);
    ctx_.view().insert(sleNullifier);
  
    // 3. Deduct fees, burn tokens, etc. (if needed)
    return tesSUCCESS;
  }
}