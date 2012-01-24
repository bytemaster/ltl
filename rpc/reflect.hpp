#ifndef _LTL_RPC_REFLECT_HPP_
#define _LTL_RPC_REFLECT_HPP_
#include <boost/reflect/any_ptr.hpp>
#include <ltl/rpc/session.hpp>
#include <ltl/rpc/types.hpp>
#include <ltl/rpc/messages.hpp>

BOOST_REFLECT_FWD( ltl::rpc::identity )
BOOST_REFLECT_FWD( ltl::rpc::voucher )
BOOST_REFLECT_FWD( ltl::rpc::asset )
BOOST_REFLECT_FWD( ltl::rpc::asset_note )
BOOST_REFLECT_FWD( ltl::rpc::signature_line )
BOOST_REFLECT_FWD( ltl::rpc::transaction )
BOOST_REFLECT_FWD( ltl::rpc::account )
BOOST_REFLECT_FWD( ltl::rpc::market_offer )

BOOST_REFLECT( ltl::rpc::msg::allocate_signatures, 
  (account_id)(count) )

BOOST_REFLECT( ltl::rpc::msg::create_account, 
  (owner_id)(asset_note_id) )
BOOST_REFLECT( ltl::rpc::msg::sign_transaction,
  (transaction_id)(sig) )

BOOST_REFLECT( ltl::rpc::msg::balance_agreement,
  (account_id)(owner_signature)(new_date)(new_balance)(open_sig_ids)(open_new_sig_ids) )

BOOST_REFLECT( ltl::rpc::msg::balance_agreement_reply,
  (status)(server_account_signature) 
)
BOOST_REFLECT( ltl::rpc::msg::account_request,
  (account_id)(date)(signature) )

BOOST_REFLECT_IMPL( ltl::rpc::identity,
  (id)
  (pub_key)
  (name)
  (date)
  (properties)
  (signature)

  (nonce)
  (vouchers)
)

BOOST_REFLECT_IMPL( ltl::rpc::voucher,
  (identity_id)
  (trust)
  (voucher_identity_id)
  (voucher_signature)
)

BOOST_REFLECT_IMPL( ltl::rpc::asset,
  (id)
  (name)
  (properties)
)

BOOST_REFLECT_IMPL( ltl::rpc::asset_note,
  (id)
  (asset_id)
  (issuer_id)
  (name)
  (properties)
  (issuer_sig)
)

BOOST_REFLECT_IMPL( ltl::rpc::signature_line,
  (account_id)
  (date)
  (sig_num)
  (state)
  (note)
  (sig)
)

BOOST_REFLECT_IMPL( ltl::rpc::transaction,
  (id)
  (date)
  (description)
  (actions)
  (signatures)
  (host_note)
  (host_sig)
)


BOOST_REFLECT_IMPL( ltl::rpc::account,
  (id)
  (host_id)
  (owner_id)
  (asset_note_id)
  (date)
  (balance)
  (sig_nums)
  (new_sig_nums)
  (owner_sig)
  (server_sig)
  
  (in_box)
  (out_box)
  (applied)
)

BOOST_REFLECT_IMPL( ltl::rpc::market_offer,
  (id)
  (buy_asset_id)
  (sell_asset_id)
  (buy_count)
  (max_price)
  (min_size)
  (start_date)
  (expire_date)
)


BOOST_REFLECT_ANY( ltl::rpc::session,
  (get_host_identity)
  (get_identity)
  (get_asset)
  (get_asset_note)
  (get_transaction)
  (authenticate)
  (get_account)
  (create_identity)
  (create_asset)
  (create_asset_note)
  (create_account)

  (post_transaction)

  (post_market_offer)
  (cancel_market_offer)
  (get_market_offers)

  (allocate_signature_numbers)
  (sign_transaction)
  (sign_balance_agreement)
)

#endif
