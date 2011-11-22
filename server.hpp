#ifndef _LTL_SERVER_HPP_
#define _LTL_SERVER_HPP_
#include <boost/filesystem.hpp>
#include <ltl/dbo_traits.hpp>

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

     dbo::ptr<identity>     create_identity( const std::string& name, const std::string& properties ); 
     dbo::ptr<asset>        create_asset( const std::string& name, const std::string& properties );
     dbo::ptr<asset_note>   create_asset_note(  const dbo::ptr<identity>& issuer, const dbo::ptr<asset>& a,
                                               const std::string& name, const std::string& props );

     dbo::ptr<account>      create_account( const dbo::ptr<identity>& owner, const dbo::ptr<asset_note>& type );
     dbo::ptr<transaction>  transfer( const std::string& desc, 
                                      int64_t amount, 
                                      const dbo::ptr<account>& from, const dbo::ptr<account>& to );

     std::vector<uint64_t>  allocate_signature_numbers( const dbo::ptr<account>& acnt, uint32_t num );
     void                   accept_applied_transactions( const dbo::ptr<account>& acnt );

     void                   sign_transaction( const dbo::ptr<transaction>& trx, const dbo::ptr<account>& acnt );
    private:
      class server_private* my;
  };

} // namespace ltl

#endif
