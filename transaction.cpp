#include <ltl/persist.hpp>
#include <boost/chrono.hpp>
#include <ltl/crypto.hpp>
#include <ltl/error.hpp>
#include <scrypt/base64.hpp>
#include <log/log.hpp>
#include <ltl/date_time.hpp>

namespace ltl {
  using namespace boost::chrono;

  json::value&       operator<<(json::value& v, const signature_line& s ) {
    v["account_id"] = std::string(s.account_id);
    if( s.date )    v["date"]    = s.date;
    if( s.sig_num ) v["sig_num"] = s.sig_num;
    if( s.state )   v["state"]   = s.state;
    if( s.note )    v["note"]    = s.note;
    if( s.sig )     v["sig"]     = scrypt::to_base64( *s.sig );
    return v;
  }
  const json::value& operator>>(const json::value& v, signature_line& s ) {
    s.account_id = sha1(std::string(v["account_id"]));
    if( v.contains("date") )    s.date    = (uint64_t)v["date"];    else s.date = boost::none;
    if( v.contains("sig_num") ) s.sig_num = (uint64_t)v["sig_num"]; else s.sig_num = boost::none;
    if( v.contains("state") )   s.state   = v["state"];             else s.state = boost::none;
    if( v.contains("note") )    s.note    = v["note"];              else s.note = boost::none;
    if( v.contains("sig") )     s.sig     = scrypt::from_base64<signature>( v["sig"] );
    else s.sig = boost::none;
  }

  transaction::transaction( const std::vector<action::ptr>& actions, 
                            const std::string& desc, uint64_t utc_ms ) {
    m_description = desc;
    if( utc_ms == 0 ) {
      utc_ms = to_milliseconds( to_ptime( system_clock::now() ) );
    }
    m_trx_date     = utc_ms;
    m_actions      = actions;
    m_json_actions = json::to_string( *m_actions );

    m_oid = get_digest();
    m_id  = *m_oid;
  }

  const std::string& transaction::get_description()const {
    return m_description;
  }
  boost::posix_time::ptime transaction::get_date()const {
     return to_ptime( m_trx_date );
  }


  const sha1& transaction::get_id()const {
    if( !m_oid ) {
      m_oid = sha1(m_id);
    }
    return *m_oid;
  }
  
  const std::vector<signature_line>& transaction::get_signatures()const {
    if( !m_signatures ) {
      json::value val;
      slog( "json sigs '%1%'", m_json_signatures );
      if( m_json_signatures.size() ) {
          json::from_string( m_json_signatures, val );
          m_signatures = std::vector<signature_line>();
          val >> *m_signatures;
      } else {
        m_signatures = std::vector<signature_line>();
      }
    }
    return *m_signatures;
  }
  const std::vector<action::ptr>&         transaction::get_actions()const {
    if( !m_actions ) {
      json::value val;
      json::from_string( m_json_actions, val );
      m_actions = std::vector<action::ptr>();
      val >> *m_actions;
    }
    return *m_actions;
  }

  sha1  transaction::get_digest()const {
    scrypt::sha1_encoder enc; 
    enc << m_trx_date;
    enc.write( m_json_actions.c_str(), m_json_actions.size() );
    return enc.result();
  }

  std::vector<sha1> transaction::get_required_signatures()const {
    const std::vector<action::ptr>& acts = get_actions();
    std::set<sha1> sigs;
    for( uint32_t i = 0; i < acts.size(); ++i ) {
       std::vector<sha1> req_s = acts[i]->required_signatures();
       for( uint32_t s = 0; s < req_s.size(); ++s )
        sigs.insert(req_s[s]);
    }
    std::vector<sha1> rtn;
    rtn.reserve(sigs.size());
    rtn.insert( rtn.begin(), sigs.begin(), sigs.end() );
    return rtn;
  }

  void transaction::post_to_accounts() {
    std::vector<sha1> req_sig = get_required_signatures();
    for( uint32_t i = 0; i < req_sig.size(); ++i ) {
        dbo::ptr<account>  acnt = session()->load<account>( std::string(req_sig[i]) );
        if( !acnt ) {
          LTL_THROW( "Unknown Account %1%", %std::string( req_sig[i]) );
        }
       /// TODO: If not signed by acnt...
        m_ref_in_accounts.insert(acnt);
       /// TODO Else post to out acnt
    }
  }

  /**
   *   get digest
   *   validate all signatures
   *   validate host sig
   */
  bool transaction::is_valid()const {
    return false; 
  }

  bool transaction::is_signed_by( const sha1& aid )const {
    return false;
  }

  bool transaction::is_signed_all()const {
    return false;
  }
  
  const dbo::collection<dbo::ptr<account> >&  transaction::referenced_applied() { 
    return m_ref_applied_accounts;
  }
  const dbo::collection<dbo::ptr<account> >&  transaction::referenced_in_box() {
    return m_ref_in_accounts;
  }
  const dbo::collection<dbo::ptr<account> >&  transaction::referenced_out_box() {
    return m_ref_out_accounts;
  }

  // after calling this, the caller should notify all clients about the change
  // throw on error
  void transaction::update_signature( const signature_line& sig ) {
    // do we already have a signature... what then
    std::vector<sha1> req_sig = get_required_signatures();
    if( std::find( req_sig.begin(), req_sig.end(), sig.account_id ) == req_sig.end() ) {
      LTL_THROW( "Signature form account %1% not required", %std::string(sig.account_id) );
    }

    // validate signature
    scrypt::sha1_encoder enc;
    enc << get_id();
    enc << sig.account_id;
    enc << *sig.date;
    enc << *sig.sig_num;
    enc.write( (*sig.state).c_str(), (*sig.state).size() );
    if( sig.note ) enc.write( (*sig.note).c_str(), (*sig.note).size() );

    sha1 digest = enc.result();

    dbo::ptr<account>  acnt = session()->load<account>( std::string(sig.account_id) );
    if( !acnt->owner()->get_pub_key().verify( digest, *sig.sig ) ) {
      LTL_THROW( "Invalid signature for account %1%", %acnt->owner()->get_name() );
    }
    

    get_signatures(); // read from json if necessary
    std::vector<signature_line>& slines = *m_signatures;

    for( uint32_t i = 0; i < slines.size(); ++i  ) {
      if( slines[i].account_id == sig.account_id ) { 
        
        // TODO Update Signature
        slines[i] = sig;   
        m_json_signatures = json::to_string( slines );
        slog( "json sigs '%1%'", m_json_signatures );

        m_ref_out_accounts.insert(acnt);
        m_ref_in_accounts.erase( acnt );
        // Notify Accounts
        return;
      }
    }
    slines.push_back(sig);
    m_json_signatures = json::to_string( slines ); 

    m_ref_out_accounts.insert(acnt);
    m_ref_in_accounts.erase( acnt );

    if( m_ref_in_accounts.size() == 0 ) {
      elog( "ACCEPT AND APPLY!" );
      if( sign_host() ) {
         std::vector<account::ptr> acnts;
         dbo::collection<account::ptr>::iterator itr = m_ref_out_accounts.begin();
         while( itr != m_ref_out_accounts.end() ) {
           acnts.push_back(*itr);
           ++itr;
         }
         for( uint32_t i = 0; i < acnts.size(); ++i ) {
           m_ref_applied_accounts.insert( acnts[i] );
           m_ref_out_accounts.erase(acnts[i]);
         }
      }
    }
    
    // is the sig.account_id a required account?
    // is the signature valid? 
    //    - sig_num currently valid in account?
    //    - is account in good standing after applying this trx?
    // add signature to m_sigs, update m_json_sigs
    // have all trx been applied? sign by host and move to applied
    // move trx from in box to out box
  }

  bool transaction::sign_host(){
    scrypt::sha1_encoder enc;
    const std::vector<signature_line>& sl = get_signatures();
    for( uint32_t i = 0; i < sl.size(); ++i ) {
      enc << *(sl[i].sig);
    }
    m_host_note = "Approved";
    enc.write( m_host_note.c_str(), m_host_note.size() );
    sha1 digest = enc.result();

    signature sig;
    (*m_ref_out_accounts.begin())->host()->get_priv_key().sign( digest, sig );
    std::stringstream ss; ss << sig;
    m_host_signature = scrypt::base64_encode( ss.str() );
    return true;

    // assert in_accounts.size == 0
    // assert all accounts in good standing (no over drafts etc)
    // sign it
    // move from in box to applied
    return false;
  }
  /// returns the delta balance of applying this transaction to the given account
  int64_t transaction::apply( const sha1& acnt_id )const {
     int64_t delta_b = 0;
     const std::vector<action::ptr>& acts = get_actions();
     for( uint32_t i = 0; i < acts.size(); ++i ) {
        delta_b += acts[i]->apply(acnt_id);
     }
     return delta_b;
  }
  boost::optional<uint64_t> transaction::get_signature_num_for( const sha1& account )const {
    const std::vector<signature_line>& sigs = get_signatures();
    for( uint32_t i = 0; i < sigs.size(); ++i ) {
     if( sigs[i].account_id == account )
      return sigs[i].sig_num;
    }
    return boost::optional<uint64_t>();
  }


}
