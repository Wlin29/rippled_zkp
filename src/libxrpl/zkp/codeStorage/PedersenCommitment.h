// #ifndef PEDERSEN_COMMITMENT_H_INCLUDED
// #define PEDERSEN_COMMITMENT_H_INCLUDED

// #include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
// #include <utility>

// namespace ripple {

// template <typename FieldT>
// class PedersenCommitment
// {
// public:
//     // Returns fixed generator constants (for illustrative purposes)
//     static FieldT
//     get_G_x();
//     static FieldT
//     get_G_y();
//     static FieldT
//     get_H_x();
//     static FieldT
//     get_H_y();

//     // Returns a Pedersen commitment as a pair of field elements (x, y)
//     static std::pair<FieldT, FieldT>
//     commit(const FieldT& value, const FieldT& blinding);
// };

// }  // namespace ripple

// #endif  // PEDERSEN_COMMITMENT_H_INCLUDED
