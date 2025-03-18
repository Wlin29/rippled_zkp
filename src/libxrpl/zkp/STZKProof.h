#ifndef RIPPLE_PROTOCOL_STZKPROOF_H_INCLUDED
#define RIPPLE_PROTOCOL_STZKPROOF_H_INCLUDED

#include <xrpl/protocol/STBlob.h>
#include <xrpl/basics/Buffer.h> 

namespace ripple {

class STZKProof final : public STBlob
{
public:
    STZKProof() = default;
    
    STZKProof(SerialIter& sit, SField const& f) : STBlob(sit, f) {}
    STZKProof(SField const& f, Blob const& v)
        : STBlob(f, Buffer(v.data(), v.size()))
    {}
    STZKProof(SField const& f, Blob&& v)
        : STBlob(f, Buffer(v.data(), v.size()))
    {}
    
    SerializedTypeID getSType() const override { return STI_ZKPROOF; }
    std::string getText() const override;
};

} // namespace ripple

#endif