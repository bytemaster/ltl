#include <ltl/server.hpp>
#include <ltl/persist.hpp>
#include <ltl/date_time.hpp>
#include <algorithm>

#include <Wt/Dbo/Dbo>
#include <Wt/Dbo/backend/Sqlite3>
#include <boost/exception/all.hpp>
#include <log/log.hpp>
#include <ltl/error.hpp>

namespace ltl {
  namespace dbo = Wt::Dbo;

  class server_private {
    public:
      dbo::Session          m_session;
      dbo::backend::Sqlite3 m_sql3;
      server&               self;
      market*               mark;

      ltl::dbo::ptr<ltl::identity>   host_ident; 


      server_private( const boost::filesystem::path& dbdir, server& s)
      :m_sql3( (dbdir/"ltl.db").native() ),self(s)
      {
        slog( "creating session" );
        m_session.setConnection(m_sql3);
        m_sql3.setProperty( "show-queries", "true" );

        m_session.mapClass<identity>("identity");
        m_session.mapClass<private_identity>("private_identity");
        m_session.mapClass<asset>("asset");
        m_session.mapClass<asset_note>("asset_note");
        m_session.mapClass<account>("account");
        m_session.mapClass<transaction>("transaction");
        m_session.mapClass<market_order>("market_order");
        m_session.mapClass<market_trade>("market_trade");

       {
          dbo::Transaction trx(m_session);
          try {
            m_session.createTables();
            slog( "created tables" );
          } catch ( const boost::exception& e ) {
            elog( "create tables: %1%", boost::diagnostic_information(e) );
          } catch ( const std::exception& e ) {
            elog( "create tables: %1%", boost::diagnostic_information(e) );
          }
          trx.commit();
       }
       m_session.flush();

       mark = new market( m_session );
      }
  };

  server::server( const boost::filesystem::path& db_dir ) {
    my = new server_private(db_dir,*this);
    slog( "creating host identity" );
    my->host_ident = create_identity( "my_host_id", "hostprops" );
  }
  server::~server() {
    delete my;
  }

  dbo::ptr<identity> server::get_identity( const std::string& id ) {
    dbo::Transaction trx(my->m_session);
      dbo::ptr<identity> ident = my->m_session.load<identity>( id );
    trx.commit();
    return ident;
  }
  dbo::ptr<asset> server::get_asset( const std::string& id ) {
    dbo::Transaction trx(my->m_session);
      dbo::ptr<asset> ident = my->m_session.load<asset>( id );
    trx.commit();
    return ident;
  }
  dbo::ptr<asset_note> server::get_asset_note( const std::string& id ) {
    dbo::Transaction trx(my->m_session);
      dbo::ptr<asset_note> ident = my->m_session.load<asset_note>( id );
    trx.commit();
    return ident;
  }
  dbo::ptr<transaction> server::get_transaction( const std::string& id ) {
    dbo::Transaction trx(my->m_session);
      dbo::ptr<transaction> ident = my->m_session.load<transaction>( id );
    trx.commit();
    return ident;
  }
  dbo::ptr<account> server::get_account( const std::string& id ) {
    dbo::Transaction trx(my->m_session);
      dbo::ptr<account> ident = my->m_session.load<account>( id );
    trx.commit();
    return ident;
  }

  /**
   *  Creates a new pub/priv key pair
   */
  dbo::ptr<identity>  server::create_identity( const std::string& name, const std::string& properties ) {
    public_key pubk;
    private_key privk;
    slog( "generating private keys..." );
    scrypt::generate_keys(pubk,privk);

    dbo::Transaction trx(my->m_session);

    dbo::ptr<private_identity> pi(new private_identity( privk ) );
    pi = my->m_session.add( pi );
    slog( "created private identiy...");

    dbo::ptr<identity> ident( new identity( pubk, pi, name, properties ) );
    ident = my->m_session.add(ident);
    ident.modify()->set_private_identity(pi);
    trx.commit();

    return ident;
  }

  /**
   *  Creates a new pub/priv key pair
   */
  dbo::ptr<identity>  server::create_identity( const public_key& pk, const std::string& name, 
                                               uint64_t date, const std::string& props, const signature& sig, uint64_t nonce ) {
    dbo::Transaction trx(my->m_session);

    dbo::ptr<ltl::identity> ident( new ltl::identity( pk, name, date, props, sig, nonce ) );
    ident = my->m_session.add(ident);
    trx.commit();

    return ident;
  }




  dbo::ptr<asset>  server::create_asset( const std::string& name, const std::string& properties ) {
    slog( "Creating asset %1%: %2%", name, properties );
    dbo::Transaction trx(my->m_session);
    dbo::ptr<asset> a( new asset( name, properties ) );
    a = my->m_session.add(a);
    trx.commit();
    return a;
  }
  dbo::ptr<asset_note> server::create_asset_note(  const dbo::ptr<identity>& issuer, const dbo::ptr<asset>& a,
                                                   const std::string& name, const std::string& props, const signature& sig ) {

    dbo::Transaction trx(my->m_session);
    dbo::ptr<asset_note> an( new asset_note( issuer, a, name, props, sig ) );
    an = my->m_session.add(an);
    trx.commit();
    return an;
  }

  /**
   *  Throws if no private_identity for issuer
   */
  dbo::ptr<asset_note> server::create_asset_note(  const dbo::ptr<identity>& issuer, const dbo::ptr<asset>& a,
                                                   const std::string& name, const std::string& props ) {
    dbo::Transaction trx(my->m_session);
    dbo::ptr<asset_note> an( new asset_note( issuer, a, name, props ) );
    an = my->m_session.add(an);
    trx.commit();
    return an;
  }


   dbo::ptr<account> server::create_account( const dbo::ptr<identity>& owner, const dbo::ptr<asset_note>& type ) {
    dbo::Transaction trx(my->m_session);
    account::ptr ac( new account( my->host_ident, owner, type, 0 ) );
    ac = my->m_session.add(ac);
    trx.commit();
    return ac;
   }


   dbo::ptr<transaction>  server::transfer( const std::string& desc, int64_t amount, const dbo::ptr<account>& from, const dbo::ptr<account>& to ) {
      dbo::Transaction dbtrx(my->m_session);
        if( from->get_pending_balance() < amount ) {
          if( from->owner() != from->type()->issuer() )
              LTL_THROW( "Insufficient funds." );
          else
            slog( "Issuing new funds!" );
        }

        std::vector<action::ptr> acts; 
        acts.push_back(  action::ptr(new ltl::transfer( amount, from->get_id(), to->get_id() )) );
        dbo::ptr<transaction> trx( new transaction( acts, desc, 0 ) );
        trx = my->m_session.add(trx);
        trx.modify()->post_to_accounts();
      dbtrx.commit();
      return trx;
   }
   std::vector<uint64_t>  server::allocate_signature_numbers( const dbo::ptr<account>& acnt, uint32_t num ) {
      std::vector<uint64_t> sigs( (std::min)(uint32_t(64),num) );
      if( sigs.size() ) {
        sigs[0] = system_clock::now().time_since_epoch().count(); 
        for( uint32_t i = 1; i < sigs.size(); ++i )
          sigs[i] = sigs[0]+i;
      }
      dbo::Transaction dbtrx(my->m_session);
      acnt.modify()->allocate_signature_numbers( sigs, signature() );
      dbtrx.commit();
      return sigs;
   }

   /**
    * Gets all applied transactions, calculates the balance change, updates the sig num list
    * signs it, asks the account to apply it.
    */
   void  server::accept_applied_transactions( const dbo::ptr<account>& acnt ) {
      dbo::Transaction dbtrx(my->m_session);
      std::vector<sha1> approved(acnt->get_applied_transactions().size());
      int i = 0;
      account::trx_collection::const_iterator itr = acnt->get_applied_transactions().begin();
      while( itr != acnt->get_applied_transactions().end() ) {
        approved[i] = (*itr)->get_id();
        ++i;
        ++itr;
      }
      std::vector<uint64_t> nsids = acnt->new_sig_ids();
      
      boost::posix_time::ptime n = to_ptime(system_clock::now());

      // calculate the signature
      int64_t newbal; 
      sha1 digest; 
      std::set<uint64_t> open_sig_ids; 
      std::vector<uint64_t> open_new_sig_ids;
      account::mtrx_map mtrx;
      acnt->get_accept_balance_digest( n, nsids, approved, newbal, digest, open_sig_ids, open_new_sig_ids, mtrx );
      
      signature ownersig;
      assert( acnt->owner() );
      assert( acnt->owner()->get_private_identity() );
      acnt->owner()->get_priv_key().sign( digest, ownersig );

      // apply it, or throw, can only be done by host
      acnt.modify()->host_accept_balance( ownersig, newbal, n, nsids, approved );

      dbtrx.commit();
   }


   /**
    * Gets all applied transactions, calculates the balance change, updates the sig num list
    * signs it, asks the account to apply it.
    */
   void  server::sign_balance_agreement( const dbo::ptr<account>& acnt, uint64_t new_date, const signature& ownersig ) {
      dbo::Transaction dbtrx(my->m_session);
      std::vector<sha1> approved(acnt->get_applied_transactions().size());
      int i = 0;
      account::trx_collection::const_iterator itr = acnt->get_applied_transactions().begin();
      while( itr != acnt->get_applied_transactions().end() ) {
        approved[i] = (*itr)->get_id();
        ++i;
        ++itr;
      }
      std::vector<uint64_t> nsids = acnt->new_sig_ids();
      
      boost::posix_time::ptime n = to_ptime(new_date);

      // calculate the signature
      int64_t newbal; 
      sha1 digest; 
      std::set<uint64_t> open_sig_ids; 
      std::vector<uint64_t> open_new_sig_ids;
      account::mtrx_map mtrx;
      acnt->get_accept_balance_digest( n, nsids, approved, newbal, digest, open_sig_ids, open_new_sig_ids, mtrx );
      
      assert( acnt->owner() );

      if( !acnt->owner()->get_pub_key().verify( digest, ownersig ) ) {
        LTL_THROW( "Invalid signature" );
      }

      // apply it, or throw, can only be done by host
      acnt.modify()->host_accept_balance( ownersig, newbal, n, nsids, approved );

      dbtrx.commit();
   }

   /**
    *  Server must have private identity for account
    *  Trx must require acnt signature.
    */
   void server::sign_transaction( const dbo::ptr<transaction>& trx, const dbo::ptr<account>& acnt ) {
      dbo::Transaction dbtrx(my->m_session);
      boost::optional<uint64_t> sig = trx->get_signature_num_for(acnt->get_id());
      if( sig ) {
        LTL_THROW( "Already signed with num %1%", %(*sig) );
      }
      std::vector<sha1> req = trx->get_required_signatures();
      if( req.end() == std::find( req.begin(), req.end(), acnt->get_id() ) )
        LTL_THROW( "No signature required by account %1%", %acnt->get_id() );
      
      slog("");
      std::vector<uint64_t> unused = acnt->find_unused_sig_ids();
      slog("");
      if( unused.size() == 0 ) {
        LTL_THROW( "No signature numbers available on account %1%", %acnt->get_id() );
      }
      signature_line sl;
      sl.account_id = acnt->get_id();
      sl.date       = to_milliseconds( to_ptime(system_clock::now()) );
      sl.sig_num    = unused.front();
      sl.state      = "Accepted";

      /// TODO: Factor this out to a helper func...
      scrypt::sha1_encoder enc;
      enc << trx->get_id();
      enc << sl.account_id;
      enc << *sl.date;
      enc << *sl.sig_num;
      enc.write( (*sl.state).c_str(), (*sl.state).size() );
      if( sl.note ) enc.write( (*sl.note).c_str(), (*sl.note).size() );
  
      sha1 digest = enc.result();
      sl.sig = signature();
      
      acnt->owner()->get_priv_key().sign( digest, *sl.sig );

      slog("Updating Signature");
      trx.modify()->update_signature( sl );
      dbtrx.commit();

   }

   /**
    *
    */
   void server::sign_transaction( const dbo::ptr<transaction>& trx, 
                                  const dbo::ptr<account>& acnt,
                                  const std::string& state,
                                  uint64_t  utime,
                                  uint64_t  sig_num,
                                  const signature& sign                            
                                  ) {
      dbo::Transaction dbtrx(my->m_session);
      boost::optional<uint64_t> sig = trx->get_signature_num_for(acnt->get_id());
      if( sig ) {
        LTL_THROW( "Already signed with num %1%", %(*sig) );
      }
      std::vector<sha1> req = trx->get_required_signatures();
      if( req.end() == std::find( req.begin(), req.end(), acnt->get_id() ) )
        LTL_THROW( "No signature required by account %1%", %acnt->get_id() );
      
      std::vector<uint64_t> unused = acnt->find_unused_sig_ids();
      if( unused.size() == 0 ) {
        LTL_THROW( "No signature numbers available on account %1%", %acnt->get_id() );
      }
      if( std::find( unused.begin(), unused.end(), sig_num ) == unused.end() ) {
        LTL_THROW( "Invalid signature number %1%", %sig_num );
      }
      uint64_t stime =to_milliseconds( to_ptime(system_clock::now()) ); 
      if( utime > stime ) {
        LTL_THROW( "Signature time is in the future by %1% ms", %(stime-utime) );
      }

      signature_line sl;
      sl.account_id = acnt->get_id();
      sl.date       = utime;
      sl.sig_num    = unused.front();
      sl.state      = state;

      /// TODO: Factor this out to a helper func...
      scrypt::sha1_encoder enc;
      enc << trx->get_id();
      enc << sl.account_id;
      enc << *sl.date;
      enc << *sl.sig_num;
      enc.write( (*sl.state).c_str(), (*sl.state).size() );
      if( sl.note ) enc.write( (*sl.note).c_str(), (*sl.note).size() );
  
      sha1 digest = enc.result();
      sl.sig = signature();
      
      if( !acnt->owner()->get_pub_key().verify( digest, *sl.sig ) ) {
        LTL_THROW( "Invalid signature" );
      }

      slog("Updating Signature");
      trx.modify()->update_signature( sl );
      dbtrx.commit();
   }













    
    /**
     *  Create and submit 
     */
    dbo::ptr<market_order> server::submit_order( market_order::order_type t, 
                                                 const dbo::ptr<account>& stock_acnt,
                                                 const dbo::ptr<account>& currency_acnt,
                                                 uint64_t num, uint64_t price, uint64_t min_unit,
                                                 ptime start, ptime end )
    {
       dbo::Transaction dbtrx(my->m_session);
         std::vector<action::ptr> acts; 
       
         offer off;
         off.order_type = (t == market_order::buy) ? "buy" : "sell";
         off.asset_account = stock_acnt->get_id();
         off.currency_account = currency_acnt->get_id();
         off.amount = num;
         off.min_amount = min_unit;
         off.offer_price = price;
         off.start = start;
         off.end = end;
         
         acts.push_back( action::ptr( new offer(off) ) );
         std::stringstream ss;
         ss << (t == market_order::buy ? "Buy" : "Sell" ) << " order: ";
         ss << num << " " << num << " " << stock_acnt->type()->name() << " @ " << price << " " << currency_acnt->type()->name();
       
         dbo::ptr<transaction> trx( new transaction( acts, ss.str(), 0 ) );
         trx = my->m_session.add(trx);
         trx.modify()->post_to_accounts();
       
         sign_transaction( trx, stock_acnt ); 
         sign_transaction( trx, currency_acnt ); 
       
       
         market_order::ptr mo( new market_order( trx ) );
         my->mark->submit_order(mo);
       dbtrx.commit();
    }


} // namespace ltl
