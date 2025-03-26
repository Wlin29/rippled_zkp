// #include <xrpl/protocol/Keylet.h>
// #include <xrpl/protocol/LedgerFormats.h>

// namespace ripple {
// namespace keylet {

// // Generate a keylet for a shielded pool associated with an account
// static Keylet
// shieldedPool(AccountID const& account)
// {
//     // Use LedgerEntryType from the macro definition we saw (0x0082)
//     return {ltSHIELDED_POOL, uint256::createFromAccount(account)};
// }

// // Generate a keylet for a nullifier
// static Keylet
// nullifier(uint256 const& nullifierValue)
// {
//     // Use LedgerEntryType from the macro definition we saw (0x0083)
//     return {ltNULLIFIER, nullifierValue};
// }

// } // namespace keylet
// } // namespace ripple
