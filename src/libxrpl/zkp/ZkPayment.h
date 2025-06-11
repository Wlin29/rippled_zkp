#pragma once
#include <xrpld/app/tx/detail/Transactor.h>

namespace ripple {

class ZKPayment : public Transactor
{
public:
    static NotTEC preflight(PreflightContext const& ctx);
    static TER preclaim(PreclaimContext const& ctx);

    TER doApply() override;

private:
    static bool verify_zk_proof(Blob const& proof, AccountID const& account);
};

} // namespace ripple