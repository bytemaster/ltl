#ifndef _LTL_NODE_HPP_
#define _LTL_NODE_HPP_
#include <ltl/account.hpp>
#include <ltl/protocol.hpp>

#include <boost/filesystem/path.hpp>
#include <boost/reflect/any_ptr.hpp>

namespace ltl {

  /**
   *  This is the high-level API to the node that should be suitable
   *  for scripting or JSON-RPC over telnet
   *
   */
  class node {
    public:
      node( const std::string& nid, const boost::filesystem::path& datadir );
      ~node();

      allocate_sig_num_response  allocate_new_sig_numbers( const allocate_sig_num_request& req );
      bool                  confirm_account( const account_confirmation& );


      bool                  add_signature( const signed_transaction::id&, 
                                           const public_identity::signature_type& sig,
                                           const boost::optional<json::value>& reply 
                                             = boost::optional<json::value>());

      // manage private idents
      identity::id                     create_identity( const std::string& pub_name, const std::string& priv_name = "" );
      std::vector<identity::id>        get_identities()const;
      identity                         get_identity(const identity::id&)const;
      identity                         get_identity_by_name(const std::string& pub_name )const;

      // public identities
      std::vector<identity::id>        get_public_identities()const;
      public_identity                  get_public_identity(const public_identity::id&)const;
      public_identity                  get_public_identity_by_name(const std::string& pub_name )const;

      // managing asset types
      asset::id                        create_asset( const std::string& name, json::value props = json::value() );
      asset                            get_asset( const asset::id& )const;
      asset                            get_asset_by_name( const std::string& name );
      std::vector<asset::id>           get_asset_types()const;

      // managing asset notes
      asset_note::id                   create_asset_note( const asset::id&, const identity::id& issuer,
                                                          const json::value& props = json::value() );
      asset_note                       get_asset_note( const asset_note::id& )const;
      asset_note                       get_asset_note_by_name( const std::string& asset_name, const std::string& issuer_name );
      std::vector<asset_note::id>      get_asset_note_types()const;

      // managing accounts
      signed_account                   create_account(const public_identity::id& for_id ); 
      signed_account                   get_verified_account(const public_identity::id& for_id)const;
      signed_account                   get_account(const public_identity::id& for_id)const;
      std::vector<public_identity::id> get_accounts()const;

      // managing transactions
      bool post_transaction( const signed_transaction& );
      std::string  get_signature_state( const signed_transaction&, const public_identity::id& );
      bool sign_transaction( const public_identity::id&, const transaction::id& id, const std::string& status  );


      // these methods add the identities and assets to our db
      void register_identity( const identity& pi );
      void register_public_identity( const public_identity& pi );
      void register_asset( const asset& a );
      void register_asset_note( const asset_note& a );


    private:
      class node_private* my;
  };

}

BOOST_REFLECT_ANY( ltl::node, 
  (allocate_new_sig_numbers)
  (confirm_account)
  (post_transaction)
  (create_identity)
  (get_identities)
  (get_public_identities)
  (get_identity)
  (get_identity_by_name)
  (get_public_identity)
  (get_public_identity_by_name)
  (get_asset_types)
  (get_asset_note_types)
  (create_asset)
  (get_asset)
  (get_asset_by_name)
  (create_asset_note)
  (get_asset_note)
  (create_account)
  (get_accounts)
  (get_account)
  (get_verified_account)
  (register_identity)
  (register_public_identity)
  (register_asset)
  (register_asset_note)
)

#endif
