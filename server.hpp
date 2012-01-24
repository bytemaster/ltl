#ifndef _LTL_SERVER_HPP_
#define _LTL_SERVER_HPP_
#include <boost/filesystem.hpp>
#include <ltl/dbo_traits.hpp>
#include <ltl/date_time.hpp>
#include <ltl/market.hpp>

namespace ltl {

  /**
   *  The central location that manages the market database
   *  and performs common actions.  
   */
  class server {
    public:
     typedef boost::shared_ptr<server> ptr;
     server( const boost::filesystem::path& db_dir );
     ~server();

     const dbo::ptr<identity>& server_identity();

     dbo::ptr<identity>     get_identity( const std::string& id );
     dbo::ptr<asset>        get_asset( const std::string& id );
     dbo::ptr<asset_note>   get_asset_note( const std::string& id );
     dbo::ptr<account>      get_account( const std::string& id );
     dbo::ptr<transaction>  get_transaction( const std::string& id );


     dbo::ptr<identity>     create_identity( const std::string& name, const std::string& properties ); 

     dbo::ptr<identity>     create_identity( const public_key& pk, const std::string& name, 
                                               uint64_t date, const std::string& props, 
                                               const signature& sig, uint64_t nonce = 0 );

     dbo::ptr<asset>        create_asset( const std::string& name, const std::string& properties );
     dbo::ptr<asset_note>   create_asset_note(  const dbo::ptr<identity>& issuer, const dbo::ptr<asset>& a,
                                               const std::string& name, const std::string& props );
     dbo::ptr<asset_note>   create_asset_note(  const dbo::ptr<identity>& issuer, const dbo::ptr<asset>& a,
                                               const std::string& name, const std::string& props, const signature& s );

     dbo::ptr<account>      create_account( const dbo::ptr<identity>& owner, const dbo::ptr<asset_note>& type );
     dbo::ptr<transaction>  transfer( const std::string& desc, 
                                      int64_t amount, 
                                      const dbo::ptr<account>& from, const dbo::ptr<account>& to );

     std::vector<uint64_t>  allocate_signature_numbers( const dbo::ptr<account>& acnt, uint32_t num );
     void                   accept_applied_transactions( const dbo::ptr<account>& acnt );

     void                   sign_balance_agreement( const dbo::ptr<account>& acnt, uint64_t newdate, const signature& ownersig );

     void                   sign_transaction( const dbo::ptr<transaction>& trx, const dbo::ptr<account>& acnt );
     void                   sign_transaction( const dbo::ptr<transaction>& trx, const dbo::ptr<account>& acnt,
                                             const std::string& state, uint64_t  utime, uint64_t  sig_num,
                                             const signature& sig   );


     dbo::ptr<market_order> submit_order( market_order::order_type t, 
                                          const dbo::ptr<account>& stock_acnt,
                                          const dbo::ptr<account>& currency_acnt,
                                          uint64_t num, uint64_t price, uint64_t min_unit,
                                          ptime start, ptime end );

    private:
      class server_private* my;
  };

} // namespace ltl

#endif
