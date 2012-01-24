#ifndef _LTL_PROTOCOL_HPP_
#define _LTL_PROTOCOL_HPP_
#include <boost/reflect/reflect.hpp>
#include <ltl/identity.hpp>
#include <ltl/asset.hpp>
#include <ltl/transaction.hpp>

/**
 *  @file protocol.hpp
 *  @brief defines message structures used to communicate among nodes
 */

namespace ltl {

struct allocate_sig_num_request {
   public_identity::id account_id; 
   int                 num_new;
};

struct allocate_sig_num_response {
  std::vector<uint64_t>            new_sig_nums;
  int64_t                          old_balance_date; // last agreed date
  int64_t                          new_balance_date; // new date (if host accepts)
  public_identity::signature_type  host_signature;   // signature with last agreed state + new trx + new date
};
/*
struct transfer_request {
  transfer_request( int64_t am, const asset_note::id& ani, const identity::id& from, const public_identity::id& to )
  :amount(am),note_id(ani),from_aid(from),to_aid(to){}
  transfer_request();

  int64_t                amount; 
  asset_note::id         note_id; 
  identity::id           from_aid;
  public_identity::id    to_aid;
};

*/

struct account_confirmation {
   account_confirmation(){};
   account_confirmation( const public_identity::id& aid, const public_identity::signature_type& s ) 
   :account_id(aid),owner_sig(s){}

   public_identity::id              account_id;
   public_identity::signature_type  owner_sig;
};

struct post_transaction_request {
    public_identity::id aid; 
    signed_transaction  trx;
};

} // namespace ltl

BOOST_REFLECT( ltl::allocate_sig_num_request, (account_id)(num_new) )
BOOST_REFLECT( ltl::allocate_sig_num_response, (new_sig_nums)(old_balance_date)(new_balance_date)(host_signature) )
BOOST_REFLECT( ltl::account_confirmation, (account_id)(owner_sig) )
//BOOST_REFLECT( ltl::transfer_request, (amount)(note_id)(from_aid)(to_aid) )


#endif // _LTL_PROTOCOL_HPP_
