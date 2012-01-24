#ifndef _LTL_RPC_SESSION_HPP_
#define _LTL_RPC_SESSION_HPP_
#include <string>
#include <ltl/rpc/types.hpp>
#include <ltl/rpc/messages.hpp>
#include <boost/function.hpp>

namespace ltl { 
  class server;
  namespace rpc {

  typedef boost::function<void(const json::value&)> event_handler;

  /**
   *  This class manages an RPC session to ltl::server 
   *
   *  The RPC interface does not assume complete ownership of
   *  all data and therefore requires that signatures be provided instead of
   *  using local private identities to do the signing.
   *
   *  The client will also have a ltl::server that maintains the list of objects
   *  it knows about and will take care of signing things before making the RPC call.
   */
  class session {
    public:
       session( const boost::shared_ptr<ltl::server>& s  );
       ~session();
       identity                         get_host_identity();

       identity                         get_identity( const std::string& id );
       asset                            get_asset( const std::string& id );
       asset_note                       get_asset_note( const std::string& id );
       transaction                      get_transaction( const std::string& trx_id );

       /// this method requires proper authorization... 
       bool                             authenticate( const std::string& identity_id,
                                                      uint64_t timestamp, 
                                                      const std::string& identity_sig );

       account                          get_account( const std::string& acnt_id );
                                        
       std::string                      create_identity( const identity& a );
       std::string                      create_asset( const asset& a );
       std::string                      create_asset_note( const asset_note& a );
       std::string                      create_account( const msg::create_account& acnt );

       std::string                      post_transaction( const transaction& trx );
                                        
       std::string                      post_market_offer( const market_offer& off );
       std::string                      cancel_market_offer( const std::string& off_id );
       std::vector<market_offer>        get_market_offers( const std::string& buy_asset_id, 
                                                           const std::string& sell_asset_id, 
                                                           int64_t max_price );


                                        
       std::vector<uint64_t>            allocate_signature_numbers( const msg::allocate_signatures& as);
       std::string                      sign_transaction( const msg::sign_transaction& st );
       msg::balance_agreement_reply     sign_balance_agreement( const msg::balance_agreement& );


       /** 
        *   Subscribe to events on various objects.  This allows 
       std::string                      watch_market( const std::string& buy_asset_id, 
                                                      const std::string& sell_asset_id, const event_handler& eh );
       std::string                      watch_transaction( const std::string& trx_id, const event_handler& eh );
       std::string                      watch_account( const std::string& trx_id, const event_handler& eh );
        */

    private:
       class session_private* my;
  };


} } // namespace ltl::rpc


#endif
