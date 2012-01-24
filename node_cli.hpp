#ifndef _NODE_CLI_HPP_
#define _NODE_CLI_HPP_
#include <ltl/node.hpp>
#include <boost/rpc/json/server.hpp>
#include <sstream>

namespace ltl {


  /**
   *  Provides a command line interface to the node. 
   *
   *  Using straight JSON was not an effective user interface, so this class adapts methods and provides
   *  helpers that would not otherwise be in the API. For example, there is no need to print out the
   *  full public / private key and signatures.  Names instead of IDs should be used where possible.
   *
   *  This class is ment to be used with the cli adaptor from boost::reflect
   */
  class node_cli {
    public:
      node_cli( const boost::reflect::any_ptr<ltl::node>& an )
      :m_node(an) {
        m_con = boost::rpc::json::connection::ptr(new boost::rpc::json::connection());
        m_serv = boost::rpc::json::server<ltl::node>::ptr( new boost::rpc::json::server<ltl::node>(m_node,m_con) ); 
      }

      std::string help( const std::string& method ) {
        std::stringstream ss;
        ss << "   help [method]           - print this message or detailed help regarding 'method'\n";
        ss << "   call_json method params - invoke a method on the node given the name and parameters.\n";
        ss << "   exit                    - exit cleanly\n";

        return ss.str();
      }
      std::string call_json( const std::string& method, const std::string& json_params ) {
         boost::rpc::json::value param;
         boost::rpc::json::read( json_params, param );
         std::stringstream ss;
         boost::rpc::json::write(ss, m_con->call(method,param), true );
         return ss.str();
      }

      std::string exit() {
        return "Do graceful shutdown";
      }

      std::string create_identity( const std::string& pub_name, const std::string& priv_name = "" ) {
        std::stringstream ss;
        ss << "Created identity with id '"<<m_node->create_identity(pub_name,priv_name)<<"'\n";
        return ss.str();
      }

      std::string get_identities()const {
        std::stringstream ss;
        std::vector<identity::id> ids = m_node->get_identities();
        for( uint32_t i = 0; i < ids.size(); ++i ) {
          ss << (std::string)ids[i];
          identity ident = m_node->get_identity(ids[i]);
          ss << "  =>  \""<< ident.properties.get("name").to_str()  << "\"\n";
        }
        return ss.str();
      }

      std::string get_public_identities()const {
        std::stringstream ss;
        std::vector<public_identity::id> ids = m_node->get_public_identities();
        for( uint32_t i = 0; i < ids.size(); ++i ) {
          ss << (std::string)ids[i];
          public_identity ident = m_node->get_public_identity(ids[i]);
          ss << "  =>  \""<< ident.properties.get("name").to_str()  << "\"\n";
        }
        return ss.str();
      }
      std::string get_identity(const std::string& iid)const {
        std::stringstream ss;
        ss << boost::rpc::json::to_string( m_node->get_identity( identity::id(iid) ), true );
        return ss.str();
      }
      std::string get_public_identity(const std::string& iid)const {
        std::stringstream ss;
        ss << boost::rpc::json::to_string( m_node->get_public_identity( public_identity::id(iid) ), true );
        return ss.str();
      }
      std::string get_identity_by_name(const std::string& pub_name )const {
        identity iid = m_node->get_identity_by_name(pub_name);
        std::stringstream ss;
        ss << iid.get_id() << "=>" <<boost::rpc::json::to_string( iid, true );
        return ss.str();
      }
      std::string get_public_identity_by_name(const std::string& pub_name )const {
        public_identity iid = m_node->get_public_identity_by_name(pub_name);
        std::stringstream ss;
        ss << iid.get_id() << "=>" <<boost::rpc::json::to_string( iid, true );
        return ss.str();
      }

      std::string create_account( const std::string& public_id ) {
        m_node->create_account( public_identity::id(public_id) );
        return get_account( public_id );
      }


      std::string list_accounts()const {
        std::stringstream ss;
        std::vector<public_identity::id> act = m_node->get_accounts();
        for( uint32_t i = 0; i < act.size(); ++i ) {
          ss << (std::string)act[i];
          public_identity ident = m_node->get_public_identity(act[i]);
          ss << "  =>  \""<< ident.properties.get("name").to_str()  << "\"\n";
        }
        return ss.str();
      }

      std::string sign_account( const std::string& iid ) {
        signed_account acnt = m_node->get_account( public_identity::id(iid) );
        identity owner = m_node->get_identity( identity::id(acnt.owner) );
        acnt.sign( owner );
        if( !m_node->confirm_account( account_confirmation( owner.get_id(), *acnt.owner_sig ) ) ) {
          elog( "Host reject signature" );
        }
        return get_account( iid );
      }

      std::string get_account( const std::string& iid ) {
        std::stringstream ss;

        signed_account acnt = m_node->get_account(public_identity::id(iid) );
        public_identity owner = m_node->get_public_identity( acnt.owner );
        slog( "%1%", json::to_string(acnt,true) );

        ss << "ID: " << iid << std::endl;
        ss << "Owner Name: " << owner.properties["name"].to_str() << std::endl;

        public_identity host_id = m_node->get_public_identity(acnt.host);

        ss << "Date: " << (boost::chrono::system_clock::time_point() + boost::chrono::microseconds(acnt.balance_date)) << "\n";
        ss << "Owner Signature: "<<(acnt.signed_by(owner) ? "Yes" : "No") << "\n";
        ss << "Host  Signature: "<<(acnt.signed_by(host_id) ? "Yes" : "No") << "\n";
        ss << "Open Signature Numbers: ";
        for( uint32_t i = 0; i < acnt.sig_nums.size(); ++i )
          ss << acnt.sig_nums[i] << " ";
        ss << "\n";
        ss << "Balances: \n";
        std::map<asset_note::id,int64_t>::const_iterator itr = acnt.balance.begin();
        while( itr != acnt.balance.end() ) {
          asset_note      an = m_node->get_asset_note( itr->first );
          asset            a = m_node->get_asset( an.asset_type );
          public_identity ai = m_node->get_public_identity(an.issuer);
          ss << "\t"<<itr->second<< " " << a.name<<" issued by " << ai.properties["name"].to_str() <<"\n";
          ++itr;
        }
        return ss.str();
      }

      std::string list_assets()const {
        std::stringstream ss;
        std::vector<asset::id> ids = m_node->get_asset_types();
        for( uint32_t i = 0; i < ids.size(); ++i ) {
          asset a = m_node->get_asset(ids[i]);
          ss << std::string(ids[i]) <<  " => " << a.name << std::endl;  
        }
        return ss.str();
      }

      std::string list_asset_notes()const {
        std::stringstream ss;
        std::vector<asset_note::id> ids = m_node->get_asset_note_types();
        for( uint32_t i = 0; i < ids.size(); ++i ) {
          asset_note an = m_node->get_asset_note(ids[i]);
          asset a = m_node->get_asset(an.asset_type);
          public_identity pi = m_node->get_public_identity(an.issuer);
          ss << std::string(ids[i]) <<  " => " << a.name <<  " issued by " << pi.properties["name"].to_str() << std::endl;  
        }
        return ss.str();
      }

      std::string issue_asset( const std::string& account_id, const std::string& asset_id, const std::string& notes ) {
         asset_note::id ani = m_node->create_asset_note( asset::id(asset_id), identity::id(account_id), notes );
         return ani;
      }
      

      /**
       *  Create a transaction and post it 
       *
       */
      std::string transfer( int64_t amount, const std::string& asset_note_id, 
                            const std::string& from_aid,  const std::string& to_aid ) {
        ltl::transfer tran( amount, asset_note::id(asset_note_id), public_identity::id(from_aid), public_identity::id(to_aid) );
        signed_transaction trx(tran);
        if( m_node->post_transaction(trx) ) {
          return "Transaction Posted";
        }
        return "Error Posting Transaction";
      }
          

    private:
      boost::reflect::any_ptr<ltl::node>       m_node;
      boost::rpc::json::connection::ptr        m_con;
      boost::rpc::json::server<ltl::node>::ptr m_serv;
  };

} // namespace ltl

BOOST_REFLECT_ANY( ltl::node_cli,
  (help)
  (exit)
  (call_json)
  (create_identity)
  (get_identities)
  (get_identity)
  (get_identity_by_name)
  (get_public_identities)
  (get_public_identity)
  (get_public_identity_by_name)
  (list_accounts)
  (list_assets)
  (list_asset_notes)
  (create_account)
  (get_account)
  (sign_account)
  (issue_asset)
  (transfer)
)

#endif
