#ifndef RIPPLE_TX_ZKDEPOSIT_H_INCLUDED
#define RIPPLE_TX_ZKDEPOSIT_H_INCLUDED

#include <xrpld/app/tx/detail/Transactor.h>

namespace ripple {

class ZkDeposit : public Transactor
{
public:
    static constexpr ConsequencesFactoryType ConsequencesFactory{Normal};

    explicit ZkDeposit(ApplyContext& ctx) : Transactor(ctx) {}

    static NotTEC preflight(PreflightContext const& ctx);
    static TER preclaim(PreclaimContext const& ctx);
    TER doApply() override;
    
    static TER accountSend(ApplyView& view,
                           AccountID const& src,
                           AccountID const& dst,
                           STAmount const& amount);

private:
    std::shared_ptr<SLE> getShieldedPool(bool create = false);
    bool verifyProof();
};

} // namespace ripple

#endif