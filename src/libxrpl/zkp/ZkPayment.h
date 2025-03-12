#pragma once
#include <xrpld/app/tx/detail/Transactor.h>
#include <xrpld/basics/Log.h>

namespace ripple {
  class ZKPayment : public Transactor {
    TER preCheck() override;
    TER doApply() override;
  };
}