#include <ltl/persist.hpp>
#include <ltl/transaction.hpp>
#include <ltl/rpc/session.hpp>
#include <ltl/server.hpp>
#include <ltl/error.hpp>
#include <set>
#include <scrypt/base64.hpp>
#include <scrypt/scrypt.hpp>

namespace ltl { namespace rpc {

  class session_private {
    public:
      ltl::server::ptr      serv;
      std::set<std::string> authenticated_accounts;
  };


  session::session( const ltl::server::ptr& s ) {
    my = new session_private();
    my->serv = s;
  }
  session::~session() { delete my; }

  identity session::get_host_identity() {
    return identity();
  }

  /**
   *  Returns the identity or throws on error.
   */
  ltl::rpc::identity session::get_identity( const std::string& id ) {
    dbo::ptr<ltl::identity> ident = my->serv->get_identity(id); 
    if( !ident ) { LTL_THROW( "Unknown identity '%1%'", %id ); } 

    ltl::rpc::identity rpc_ident;
    rpc_ident.id         = id;
    rpc_ident.pub_key    = ident->get_pub_key_b64();
    rpc_ident.name       = ident->get_name();
    rpc_ident.date       = ident->get_date();
    rpc_ident.properties = ident->get_properties();
    rpc_ident.nonce      = ident->get_nonce();
    rpc_ident.signature  = ident->get_signature_b64();

    return rpc_ident;
  } 


  /**
   *  Returns the asset
   */
  ltl::rpc::asset session::get_asset( const std::string& id ) {
    dbo::ptr<ltl::asset> a = my->serv->get_asset( id );
    if( !a ) { LTL_THROW( "Unknown asset '%1%'", %id ); }

    ltl::rpc::asset ra;
    ra.id         = id;
    ra.name       = a->name();
    ra.properties = a->properties();

    return ra;
  }

  ltl::rpc::asset_note session::get_asset_note( const std::string& id ) {
    dbo::ptr<ltl::asset_note> a = my->serv->get_asset_note( id );
    if( !a ) { LTL_THROW( "Unknown asset note '%1%'", %id ); }

    ltl::rpc::asset_note ra;
    ra.id         = id;
    ra.asset_id   = a->asset_type()->get_id();
    ra.issuer_id  = a->issuer()->get_id();
    ra.name       = a->name();
    ra.properties = a->properties();
    ra.issuer_sig = a->get_signature_b64();

    return ra;
  }

  ltl::rpc::transaction session::get_transaction( const std::string& id ) {
    dbo::ptr<ltl::transaction> dbo_trx = my->serv->get_transaction( id );
    if( !dbo_trx ) { LTL_THROW( "Unknown transaction '%1%'", %id ); }
      
    ltl::rpc::transaction rpc_trx;
    rpc_trx.id          = id;
    rpc_trx.date        = to_milliseconds(dbo_trx->get_date());
    rpc_trx.description = dbo_trx->get_description();

    if( dbo_trx->get_host_signature_b64().size() )
      rpc_trx.host_sig = dbo_trx->get_host_signature_b64();
    if( dbo_trx->get_host_note().size() ) 
      rpc_trx.host_note = dbo_trx->get_host_note();

    
    const std::vector<action::ptr>& acts = dbo_trx->get_actions();
    rpc_trx.actions.resize(acts.size());
    for( uint32_t i = 0; i < acts.size(); ++i ) {
      rpc_trx.actions[i] = acts[i]->json();
    }

    if( dbo_trx->get_signatures().size() ) {
        rpc_trx.signatures = std::vector<ltl::rpc::signature_line>();
        std::vector<ltl::rpc::signature_line>& sigs = *rpc_trx.signatures;
        sigs.resize(dbo_trx->get_signatures().size());

        const std::vector<ltl::signature_line>& dbo_sigs=dbo_trx->get_signatures();

        for( uint32_t i = 0; i < sigs.size(); ++i ) {
            sigs[i].account_id = dbo_sigs[i].account_id;
            sigs[i].date       = dbo_sigs[i].date;
            sigs[i].sig_num    = dbo_sigs[i].sig_num;
            sigs[i].state      = dbo_sigs[i].state;
            sigs[i].note       = dbo_sigs[i].note;
            sigs[i].sig        = scrypt::to_base64(dbo_sigs[i].sig);
        }
    }
    return rpc_trx;
  }

  
  /**
   * Signature should be identity->pub_key().verify( sha1(id+timestamp), idsig)
   * TODO: timestamp must be within 30 seconds of now.
   */
  bool session::authenticate( const std::string& identity_id, 
                              uint64_t timestamp, const std::string& identity_sig )
  {
    dbo::ptr<ltl::identity> ident = my->serv->get_identity(identity_id); 
    if( !ident ) { LTL_THROW( "Unknown identity '%1%'", %identity_id ); } 
    scrypt::sha1_encoder enc;
    enc << ident->get_id();
    enc << timestamp;
    scrypt::sha1 r = enc.result();

    signature sig;
    std::stringstream ss(scrypt::base64_decode(identity_sig));
    ss >> sig;

    if( ident->get_pub_key().verify( r, sig ) ) {
        my->authenticated_accounts.insert(identity_id);
        return true;
    }

    return false;
  }


  /**
   *  Returns account state if you are logged in and have access 
   *  to that account.
   *
   *  The only other account which may be accessed by anyone is
   *  an issuer's account.  Such an account must be available to
   *  support audits.
   */
  ltl::rpc::account session::get_account( const std::string& id ) {
    dbo::ptr<ltl::account> dbo_acnt = my->serv->get_account( id );
    if( !dbo_acnt ) {
      LTL_THROW( "Unknown account '%1%'", %id );
    }
    if( my->authenticated_accounts.find( dbo_acnt->owner()->get_id() ) 
        == my->authenticated_accounts.end() ) {
        if( dbo_acnt->owner() != dbo_acnt->type()->issuer() ) {
          LTL_THROW( "Access Denied" );
        }
    }
    ltl::rpc::account acnt;
    acnt.id = id;
    acnt.host_id       = dbo_acnt->host()->get_id();
    acnt.owner_id      = dbo_acnt->owner()->get_id();
    acnt.asset_note_id = dbo_acnt->type()->get_id();

    acnt.date          = to_milliseconds(dbo_acnt->balance_date());
    acnt.balance       = dbo_acnt->balance();
    acnt.sig_nums      = dbo_acnt->sig_ids();
    acnt.new_sig_nums  = dbo_acnt->new_sig_ids();

    acnt.owner_sig     = scrypt::to_base64(dbo_acnt->owner_signature());
    acnt.server_sig    = scrypt::to_base64(dbo_acnt->host_signature());

    acnt.in_box        = dbo_acnt->get_inbox_ids();
    acnt.out_box       = dbo_acnt->get_outbox_ids();
    acnt.applied       = dbo_acnt->get_applied_ids();

    return acnt;
  }

  std::string session::create_identity( const ltl::rpc::identity& i ) {
    if( my->serv->get_identity( i.id ) ) 
      return "EXISTS";

    public_key pk;
    signature  sig;
    scrypt::from_base64( i.signature, sig );
    scrypt::from_base64( i.pub_key, pk );
    my->serv->create_identity( pk, i.name, i.date, i.properties, sig, 
                               (i.nonce ? *i.nonce : uint64_t(0)) );
    return "CREATED";
  }

  std::string session::create_asset( const ltl::rpc::asset& a ) {
    if( a.id && my->serv->get_asset( *a.id ) ) 
      return "EXISTS";

    my->serv->create_asset( a.name, a.properties ); 
    return "CREATED";
  }

  std::string session::create_asset_note( const ltl::rpc::asset_note& a ) {
    if( my->serv->get_asset_note( a.id ) ) 
      return "EXISTS";

    dbo::ptr<ltl::identity> ident = my->serv->get_identity( a.issuer_id );
    dbo::ptr<ltl::asset>    type  = my->serv->get_asset( a.asset_id );

    my->serv->create_asset_note( ident, type, a.name, a.properties, 
                                  scrypt::from_base64<signature>(a.issuer_sig) );
    return "CREATED";
  }

  std::string session::create_account( const msg::create_account& a ) {
    dbo::ptr<ltl::identity> owner = my->serv->get_identity( a.owner_id );
    if( !owner ) {
      LTL_THROW( "Unknown identity '%1%'", %a.owner_id );
    }
    dbo::ptr<ltl::asset_note> an = my->serv->get_asset_note( a.asset_note_id );
    if( !an ) {
      LTL_THROW( "Unknown asset note '%1%'", %a.asset_note_id );
    }
    my->serv->create_account( owner, an );
    return "OK";
  }

  std::string session::post_transaction( const ltl::rpc::transaction& trx ) {
    return "Error";
  }

  std::string session::post_market_offer( const market_offer& off ) {
    return "Error";
  }

  std::string session::cancel_market_offer( const std::string& oid ) {
    return "Error";
  }
  std::vector<market_offer> session::get_market_offers( const std::string& baid, const std::string& said,
                                                        int64_t max_price ) {
    return std::vector<market_offer>(); 
  }

  std::vector<uint64_t>  session::allocate_signature_numbers( const msg::allocate_signatures& as) {
    dbo::ptr<ltl::account> acnt = my->serv->get_account( as.account_id );
    if( !acnt ) LTL_THROW( "Invalid account id '%1%'", %as.account_id );
    return my->serv->allocate_signature_numbers( acnt, as.count );
  }

  std::string            session::sign_transaction( const msg::sign_transaction& st ) {
   return "Error";
  }

  msg::balance_agreement_reply session::sign_balance_agreement( const msg::balance_agreement& ba ) {
    msg::balance_agreement_reply bar;
    dbo::ptr<ltl::account> acnt = my->serv->get_account( ba.account_id );
    if( !acnt ) LTL_THROW( "Invalid account id '%1%'", %ba.account_id );

    my->serv->sign_balance_agreement( acnt, ba.new_date, scrypt::from_base64<signature>( ba.owner_signature ) );

    bar.status = "OK";
    bar.server_account_signature = scrypt::to_base64( acnt->host_signature() );
    return bar;
  }

} } 
