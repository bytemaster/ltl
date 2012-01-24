#include <boost/rpc/json/value_io.hpp>
#include <boost/filesystem.hpp>
#include <boost/chrono.hpp>
#include <scrypt/super_fast_hash.hpp>

#include <ltl/node.hpp>
#include <ltl/keyvalue_db.hpp>
#include <ltl/error.hpp>
#include <ltl/protocol.hpp>

namespace ltl {
  using namespace boost::chrono;

  typedef keyvalue_db<transaction::id,transaction>           transaction_db;
  typedef keyvalue_db<public_identity::id,signed_account>    account_db;
  typedef keyvalue_db<asset_note::id,asset_note>             asset_note_db;
  typedef keyvalue_db<asset::id,asset>                       asset_db;
  typedef keyvalue_db<public_identity::id,public_identity>   public_identity_db;
  typedef keyvalue_db<identity::id,identity>                 identity_db;

  class node_private {
    public:
      identity                node_id;
      boost::filesystem::path datadir;   

      transaction_db      transactions;
      account_db          verified_accounts;   ///<- accounts signed by owner + node
      account_db          unverified_accounts; ///<- accounts that are not signed by owner
      asset_db            assets;
      asset_note_db       asset_notes;
      public_identity_db  public_identities;
      identity_db         identities;

  };
  
  node::node( const std::string& nid, const boost::filesystem::path& datadir ) {
    my = new node_private();
    my->datadir = datadir;

    boost::filesystem::create_directories(datadir);

    my->transactions.open(datadir/"transactions.db");
    my->verified_accounts.open(datadir/"verified_accounts.db");
    my->unverified_accounts.open(datadir/"unverified_acounts.db");
    my->assets.open(datadir/"assets.db");
    my->asset_notes.open(datadir/"asset_notes.db");
    my->public_identities.open(datadir/"public_identities.db");
    my->identities.open(datadir/"identities.db");

    try {
      my->node_id = get_identity_by_name( nid );
    } catch ( ... ) {
      slog( "Creating new host id" );
      my->node_id.properties["name"] = std::string( "host_id" );
      my->node_id.initialize();
      register_identity(my->node_id);
      register_public_identity(my->node_id);
    }
  }

  node::~node() {
    delete my;
  }

  void node::register_public_identity( const public_identity& pi ) {
    if( !pi.verify_properties() ) {
      LTL_THROW( "Unsigned Properties for identity %1%", %pi.get_id() );
    }
    my->public_identities.set( pi.get_id(), pi );
    my->public_identities.sync();
  }
  void node::register_identity( const identity& pi ) {
    if( !pi.verify_properties() ) {
      LTL_THROW( "Unsigned Properties for identity %1%", %pi.get_id() );
    }
    my->identities.set( pi.get_id(), pi );
    my->identities.sync();
  }

  void node::register_asset( const asset& a ) {
    my->assets.set( a.get_id(), a );
    my->assets.sync();
  }

  void node::register_asset_note( const asset_note& a ) {
    public_identity pid;
    if( !my->public_identities.get( a.issuer, pid ) ) {
      LTL_THROW( "Unknown issuer identity %1%", %a.issuer );
    }
    my->asset_notes.set( a.get_id(), a );
    my->asset_notes.sync();
  }

  /**
   *  This method will throw if the account already exists or
   *  if the public identity is not known.
   */
  signed_account node::create_account( const public_identity::id& for_id ) {
    signed_account a;
    if( my->verified_accounts.get( for_id, a ) ) {
      LTL_THROW( "Verified account for %1% already exists", %for_id ); 
    }
    if( my->unverified_accounts.get( for_id, a ) ) {
      return a;
    }
    public_identity pid;
    if( !my->public_identities.get( for_id, pid ) ) 
      LTL_THROW( "Unknown Identity: %1%", %for_id ); 
    

    a.owner        = for_id;
    a.host         = my->node_id.get_id();
    a.balance_date = duration_cast<microseconds>(system_clock::now().time_since_epoch()).count();
    a.sign( my->node_id );
    assert( a.signed_by( my->node_id ) );


    std::string pjson = json::to_string(a,true);
    std::cerr<<"pjson:"<<pjson<<"\n";
    signed_account fjson;
    json::from_json( pjson, fjson );
    pjson = json::to_string(fjson,true);
    std::cerr<<"fjson:"<<pjson << "\n";;

    assert( fjson.signed_by( my->node_id ) );

    std::vector<char> test;
    boost::rpc::raw::pack_vec( test, a );
    signed_account at;
    boost::rpc::raw::unpack_vec( test, at );
    assert( at.signed_by( my->node_id ) );

    my->unverified_accounts.set( for_id, a );
    my->unverified_accounts.sync();

    return a;
  }


  identity::id node::create_identity( const std::string& pub_name, const std::string& priv_name ) {
     identity ident;
     ident.properties["name"] = pub_name;
     ident.private_properties["name"] = priv_name.size() ? priv_name : pub_name;
     ident.initialize();
     ident.sign_properties();

     slog( "created identity:\n%1%", json::to_string(ident,true) );
     register_identity( ident );
     register_public_identity( ident );
     return ident.get_id();
  }

  std::vector<identity::id> node::get_identities()const {
    std::vector<identity::id> idents;
    identity_db::iterator itr = my->identities.begin();
    while( !itr.end() ) {
      idents.push_back(itr.key());
      ++itr;
    }
    return idents;
  }
  std::vector<identity::id> node::get_public_identities()const {
    std::vector<public_identity::id> public_idents;
    public_identity_db::iterator itr = my->public_identities.begin();
    while( !itr.end() ) {
    //  slog( "%1% => %2%", itr.key(), json::to_string(itr.key()) );
      public_idents.push_back(itr.key());
      ++itr;
    }
    return public_idents;
  }

  identity node::get_identity( const identity::id& i )const {
    slog( "%1%", i );
    identity_db::iterator itr = my->identities.find(i);
    while( !itr.end() ) {
      return itr.value();
    }
    LTL_THROW( "Unknown private identity %1%", %i );
  }

  identity node::get_identity_by_name(const std::string& pub_name )const {
    identity_db::iterator itr = my->identities.begin();
    while( !itr.end() ) {
      if( itr.value().properties.get("name") == pub_name )
        return itr.value();
      ++itr;
    }
    LTL_THROW( "Unknown private identity with name '%1%'", %pub_name );
  }
  public_identity node::get_public_identity_by_name(const std::string& pub_name )const {
    public_identity_db::iterator itr = my->public_identities.begin();
    while( !itr.end() ) {
      if( itr.value().properties.get("name") == pub_name )
        return itr.value();
      ++itr;
    }
    LTL_THROW( "Unknown public identity with name '%1%'", %pub_name );
  }


  public_identity node::get_public_identity( const public_identity::id& i )const {
    public_identity_db::iterator itr = my->public_identities.find(i);
    while( !itr.end() ) {
      return itr.value();
    }
    LTL_THROW( "Unknown private public_identity %1%", %i );
  }


  asset::id node::create_asset( const std::string& name, json::value props  ) {
    asset a( name, props );
    register_asset( a ); 
    return a.get_id();
  }
  asset     node::get_asset( const asset::id& aid )const {
    asset a;
    if( !my->assets.get( aid, a ) ) {
      LTL_THROW( "No known assets with id '%1%'", %aid );
    }
    return a;
  }
  asset node::get_asset_by_name( const std::string& n ) {
    asset a;
   // if( !my->assets.get( aid, a ) ) {
      LTL_THROW( "No known assets with name '%1%'", %n );
   // }
    return a;
  }

  asset_note::id node::create_asset_note( const asset::id& aid, 
                                          const identity::id& issuer,
                                          const json::value& props ) {
    identity iid;
    asset a;

    if( !my->identities.get( issuer, iid ) ) { LTL_THROW( "Unknown private identity '%1%'", %issuer ); }
    if( !my->assets.get( aid, a ) ) { LTL_THROW( "No known assets with id '%1%'", %aid ); }

    asset_note an( aid );
    an.sign(iid);

    register_asset_note( an );

    return an.get_id();

  }
  asset_note node::get_asset_note( const asset_note::id& aid)const {
    asset_note a;
    if( !my->asset_notes.get( aid, a ) ) {
      LTL_THROW( "No known asset_notes with id '%1%'", %aid );
    }
    return a;
  }

  /**
   *  Add new empty transactions to the account with server-assigned unique numbers.  
   *
   *  The server must issue these numbers and their state must be tracked in the account otherwise
   *  the client and server would have to keep all transactions forever (or for a fixed period of time)
   *  to prevent 'double spending' of any 'client generated trx numbers'.  By agreeing in advance
   *  as to the valid 'outstanding numbers' the client and server only have to keep the transactions
   *  around until they have been processed.
   */
  allocate_sig_num_response  node::allocate_new_sig_numbers( const allocate_sig_num_request& req ) {
      signed_account sa; 
      if( !my->unverified_accounts.get( req.account_id, sa ) &&
          !my->verified_accounts.get( req.account_id, sa ) )  {
          LTL_THROW( "Unknown account %1%", %req.account_id );
      }
      identity host_id;
      if( !my->identities.get( sa.host, host_id ) ) {
          LTL_THROW( "Unknown host identity %1%", %sa.host );
      }
      int num_new = (std::min)(req.num_new,64);

      allocate_sig_num_response ctrx;
      ctrx.new_sig_nums.reserve(num_new);
      
      // issue new numbers starting at utc_us now up to now+new_num
      // use utc_us to enable automatic expiring of transaction numbers
      int64_t num = duration_cast<microseconds>(system_clock::now().time_since_epoch()).count();
      for( int64_t i = 0; i < num_new; ++i ) {
        ctrx.new_sig_nums.push_back( num + i );
        sa.sig_nums.push_back( num + i );
      }
      
      sa.balance_date = num;
      // sign the account and store it in the unverified account
      sa.sign( my->node_id );
      my->unverified_accounts.set( sa.owner, sa );
      
      ctrx.new_balance_date = sa.balance_date;
      ctrx.host_signature = *sa.host_sig;

      return ctrx;
  }


  /**
   *  Any time the node requests a change to the account it requires the owner to confirm the 
   *  new state.  This is achieved by providing the signature which when verified updates
   *  the verified account status.
   */
  bool node::confirm_account( const account_confirmation& c ) {
      signed_account sa; 
      if( !my->unverified_accounts.get( c.account_id, sa ) ) {
        if( !my->verified_accounts.get( c.account_id, sa ) )  {
          LTL_THROW( "Unknown account %1%", %c.account_id );
        } 
        if( *sa.owner_sig != c.owner_sig ) {
          LTL_THROW( "Attempt to confirm unknown changes on account %1%", %c.account_id );
        }
        return true;
      }
      if( sa.owner_sig && *sa.owner_sig == c.owner_sig )  {
        /// TODO: Owner sig should always be null for unverified account
         LTL_THROW( "Why is unverified account already signed?" );
      }
      sa.owner_sig = c.owner_sig;
      if( sa.signed_by( get_public_identity(sa.owner) ) ) {
        sa.sign( my->node_id );
        my->verified_accounts.set( sa.owner, sa );
        my->verified_accounts.sync(); // don't want to lose this sig!
        my->unverified_accounts.remove(sa.owner); // no need for this now, it is now in verified account
        return true;
      }
      sa.owner_sig = boost::none;
      return false;
  }

  /**
   *  This is the main transaction dispatch... the transaction must be posted to
   *  every account that is required to sign off on it.
   */
  bool node::post_transaction( const signed_transaction& trx ) {
    if( trx.trx_date > duration_cast<microseconds>(system_clock::now().time_since_epoch()).count() ) {
      LTL_THROW( "Transaction date is in the future!" );
    }

    std::set<public_identity::id> signatures = trx.get_signers();
    std::set<public_identity::id>::iterator itr = signatures.begin();
    while( itr != signatures.end() ) {
      signed_account   acnt = get_account(*itr);
      acnt.out_trx.insert(trx);
      my->unverified_accounts.set( acnt.owner, acnt );
      ++itr;
    }

    std::set<public_identity::id> required_signatures = trx.get_required_signers();
    itr = required_signatures.begin();
    while( itr != required_signatures.end() ) {
      signed_account   acnt = get_account(*itr);
      acnt.in_trx.insert(trx);
      my->unverified_accounts.set( acnt.owner, acnt );
      ++itr;
    }

    my->unverified_accounts.sync();
    return true;
  }

  signed_account node::get_verified_account(const public_identity::id& for_id)const {
      signed_account sa; 
      if( !my->verified_accounts.get( for_id, sa ) )  {
        LTL_THROW( "Unknown account %1%", %for_id );
      } 
      return sa;
  }
  signed_account node::get_account(const public_identity::id& for_id)const {
      signed_account sa; 
      if( !my->unverified_accounts.get( for_id, sa ) ) {
        if( !my->verified_accounts.get( for_id, sa ) )  {
          LTL_THROW( "Unknown account %1%", %for_id );
        } 
      }
      return sa;
  }

  std::vector<asset::id> node::get_asset_types()const {
    std::vector<asset::id> ids;
    asset_db::iterator itr = my->assets.begin();
    while( !itr.end() ) {
      ids.push_back( itr.key() );
      ++itr;
    }
    return ids;
  }

  std::vector<asset_note::id> node::get_asset_note_types()const {
    std::vector<asset_note::id> ids;
    asset_note_db::iterator itr = my->asset_notes.begin();
    while( !itr.end() ) {
      ids.push_back( itr.key() );
      ++itr;
    }
    return ids;
  }

  std::vector<public_identity::id> node::get_accounts()const {
    std::set<public_identity::id> idents;
    account_db::iterator itr = my->unverified_accounts.begin();
    while( !itr.end() ) {
      idents.insert(itr.key());
      ++itr;
    }

    itr = my->verified_accounts.begin();
    while( !itr.end() ) {
      idents.insert(itr.key());
      ++itr;
    }
    return std::vector<public_identity::id>( idents.begin(), idents.end() );
  }

  std::string node::get_signature_state( const signed_transaction& trx, const public_identity::id& pid ) {
    if( !trx.signatures ) return "unsigned";
    if( !(*trx.signatures).size() ) return "unsigned";

    uint32_t key = scrypt::super_fast_hash( (char*)pid.hash, sizeof(pid.hash) ); 
    for( uint32_t i = 0; i < (*trx.signatures).size(); ++i ) {
      if( (*trx.signatures)[i].id_hash == key ) {
        public_identity ident = get_public_identity(pid);
         
        scrypt::sha1_encoder sha; 
        boost::rpc::raw::pack( sha, trx.get_id() );
        boost::rpc::raw::pack( sha, (*trx.signatures)[i].status );
        boost::rpc::raw::pack( sha, (*trx.signatures)[i].meta_status );

        if( ident.public_key.verify( sha.result(), (*trx.signatures)[i].signature ) )
          return (*trx.signatures)[i].status;
        else
          return "invalid";
      }
    }
    return "unsigned";
  }

  
  /**
   *  Get the transaction from the user's account, sign it, and then notify everyone involved in the
   *  transaction about the updated state.  
   */
  bool node::sign_transaction( const public_identity::id&, const transaction::id& id, const std::string& status  ) {

  }


}
