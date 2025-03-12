#include "STZKProof.h"
#include <xrpl/basics/StringUtilities.h>

namespace ripple {

std::string
STZKProof::getText() const
{
    return "ZKProof(" + strHex(value()) + ")";
}

} // namespace ripple