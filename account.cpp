#include <ltl/error.hpp>
#include <ltl/persist.hpp>
#include <ltl/date_time.hpp>
#include <scrypt/base64.hpp>
#include <log/log.hpp>


namespace ltl {


account::account( const identity::ptr& host,
       const identity::ptr& owner,
       const asset_note::ptr& type,
       uint64_t init_date )
{
  m_date    = init_date;
  m_balance = 0;
  m_host    = host;
  m_owner   = owner;
  m_type    = type;

  scrypt::sha1_encoder enc;
  enc.write( (char*)host->get_id().hash, sizeof(host->get_id().hash) );
  enc.write( (char*)owner->get_id().hash, sizeof(owner->get_id().hash) );
  enc.write( (char*)type->get_id().hash, sizeof(type->get_id().hash) );
  m_oid = enc.result();
  m_id  = *m_oid;
}


const sha1&               account::get_id()const {
  if( !m_oid ) { m_oid = sha1(m_id); }
  return *m_oid;
}

const signature&          account::owner_signature()const {
  if( !m_oowner_sig ) {
    std::string pk_decode = scrypt::base64_decode( m_owner_sig );
    std::stringstream ss( pk_decode  );
    m_oowner_sig = signature();
    ss >> *m_oowner_sig;
  }
  return *m_oowner_sig;
}

const signature&          account::host_signature()const {
  if( !m_ohost_sig ) {
    std::string pk_decode = scrypt::base64_decode( m_host_sig );
    std::stringstream ss( pk_decode  );
    m_ohost_sig = signature();
    ss >> *m_ohost_sig;
  }
  return *m_ohost_sig;
}
void account::set_signature( std::string& sig, const signature& s ) {
  sig = scrypt::base64_encode( (const unsigned char*)s.data, sizeof(s.data) );
}


const dbo::ptr<identity>& account::owner()const {
  return m_owner;
}

const dbo::ptr<identity>& account::host()const {
  return m_host;
}

const dbo::ptr<asset_note>& account::type()const {
  return m_type;
}


int64_t               account::balance()const {
  return m_balance;
}

/**
 *  Applied balance is the balance in the account after all transactions
 *  that all parties have signed and been approved by the server.
 */
int64_t  account::get_applied_balance()const {
  int64_t b = m_balance;
  dbo::collection<dbo::ptr<transaction> >::const_iterator itr = m_applied.begin();
  while( itr != m_applied.end() ) {
    b += (*itr)->apply( get_id() ); 
    ++itr;
  }
  return b;
}

/**
 *  Pending balance is the balance in the account after all transactions
 *  that you have signed have been applied.
 *
 */
int64_t  account::get_pending_balance()const {
  int64_t b = get_applied_balance();
  dbo::collection<dbo::ptr<transaction> >::const_iterator itr = m_out_box.begin();
  while( itr != m_out_box.end() ) {
    b += (*itr)->apply( get_id() ); 
    ++itr;
  }
  return b;
}

boost::posix_time::ptime  account::balance_date()const {
  return to_ptime( m_date );
}


const std::vector<uint64_t>& account::new_sig_ids()const {
  if( !m_onew_sig_ids ) {
    std::string data = scrypt::base64_decode( m_sig_nums );
    m_onew_sig_ids = std::vector<uint64_t>();
    (*m_onew_sig_ids).resize(data.size()/sizeof(uint64_t) );
    memcpy( (char*)&(*m_onew_sig_ids).front(), data.c_str(), data.size() );
  }
  return *m_onew_sig_ids;
}


/**
 *  all sig ids used in applied and pending trx
 */
std::vector<uint64_t> account::find_used_sig_ids()const {
  std::vector<uint64_t> uids;
  uids.reserve(sig_ids().size());

  dbo::collection<dbo::ptr<transaction> >::const_iterator itr = m_out_box.begin();
  while( itr != m_out_box.end() ) {
    boost::optional<uint64_t> sid = (*itr)->get_signature_num_for( get_id() );  
    if( sid ) uids.push_back( *sid );
    ++itr;
  }
  
  itr = m_applied.begin();
  while( itr != m_applied.end() ) {
    boost::optional<uint64_t> sid = (*itr)->get_signature_num_for( get_id() );  
    if( sid ) uids.push_back( *sid );
    ++itr;
  }
  return uids;
}

/**
 *  
 *  sig_ids() - find used sig
 */
std::vector<uint64_t> account::find_unused_sig_ids()const {
  std::vector<uint64_t> ids = sig_ids();
  std::vector<uint64_t> uids = find_used_sig_ids();
  for( uint32_t i = 0; i < uids.size(); ++i )
    std::remove(ids.begin(), ids.end(),uids[i]);
  return ids;
}


const std::vector<uint64_t>& account::sig_ids()const {
  if( !m_osig_ids ) {
    std::string data = scrypt::base64_decode( m_sig_nums );
    m_osig_ids = std::vector<uint64_t>();
    (*m_osig_ids).resize(data.size()/sizeof(uint64_t) );
    memcpy( (char*)&(*m_osig_ids).front(), data.c_str(), data.size() );
  }
  return *m_osig_ids;
}


bool account::is_valid()const {
  if( !m_host || !m_owner || !m_type ) 
    return false;
  scrypt::sha1_encoder enc;
  enc.write( (char*)m_host->get_id().hash, sizeof(m_host->get_id().hash) );
  enc.write( (char*)m_owner->get_id().hash, sizeof(m_owner->get_id().hash) );
  enc.write( (char*)m_type->get_id().hash, sizeof(m_type->get_id().hash) );
  if( get_id() != enc.result() ) 
    return false;
  return true;
}

/**
 *  Calculates the digest that is used to sign the account. This digest
 *  must include every piece of information that the owner and host must
 *  agree on.  
 *
 *  ID incoporates identities and asset
 *  AccountID, balance, date, and open signature IDs
 */
sha1 account::get_digest()const {
  scrypt::sha1_encoder enc; 
  enc.write( (const char*)get_id().hash, sizeof(get_id().hash) );
  enc << m_balance;
  enc << m_date;
  elog( "%1%  %2% %3%", get_id(), m_balance, m_date );
  for( uint32_t i = 0; i < sig_ids().size(); ++i ) 
      enc << sig_ids()[i];
  return enc.result();
}

/**
 *  This is the digest of the account after applying
 *  all 'applied' transactions and updating the reserved signature
 *  numbers by removing the 'used sigs' and adding the new sigs.
 */
sha1 account::get_applied_digest()const {

  scrypt::sha1_encoder enc; 
  enc.write( (const char*)get_id().hash, sizeof(get_id().hash) );

  int64_t applied_balance = get_applied_balance();

  enc << m_balance;
  enc << m_date;
  for( uint32_t i = 0; i < sig_ids().size(); ++i ) 
      enc << sig_ids()[i];
}


bool account::host_signed()const {
  scrypt::sha1_encoder enc; 
  enc << owner_signature();
  return m_host->get_pub_key().verify( enc.result(), host_signature() );
}

bool account::owner_signed()const {
  return m_owner->get_pub_key().verify( get_digest(), owner_signature() );
}


/**
 *  Sig must the host.sign( sha1(signums) ), proves the numbers were allocated
 *  by the server.
 *
 *  Makes sure signums are unique, not in use, and issued by the server
 *
 *  TODO: Validate Signature, store signature for proof?
 */
void account::allocate_signature_numbers( const std::vector<uint64_t>& signums, const signature& host_sig ) {
  std::vector<uint64_t>   used_sig = find_used_sig_ids(); 
  if( !m_onew_sig_ids ) 
    m_onew_sig_ids = std::vector<uint64_t>();

  std::vector<uint64_t>&  new_sigs = *m_onew_sig_ids;

  for( uint32_t i = 0; i < signums.size(); ++i ) {
    if( used_sig.end() != std::find( used_sig.begin(), used_sig.end(), signums[i] ) ) {
      LTL_THROW( "Signature number %1% is currently in use", %signums[i] );
    } 
    if( new_sigs.end() == std::find( new_sigs.begin(), new_sigs.end(), signums[i] ) )
      new_sigs.push_back(signums[i]);
  }

  // store the new sig nums into m_new_sig_nums
  if( new_sigs.size() )
      m_new_sig_nums = scrypt::base64_encode( (const unsigned char*)&new_sigs.front(), new_sigs.size()*sizeof(uint64_t) );
  else 
      m_new_sig_nums = "";
}


/**
 *  @brief provides human-readable debug output for the account.
 *
 */
std::string account::to_string()const {
  dbo::Transaction dbtrx(*session());
  using namespace boost::chrono;

  std::stringstream ss;
  ss << "Account: " << std::string(get_id()) << std::endl;
  ss << "Host: " << m_host->get_name() << "  (" << std::string(m_host->get_id()) <<")\n";
  ss << "Owner: " << m_owner->get_name() << "  (" << std::string(m_owner->get_id()) <<")\n";
  ss << "Type: " << m_type->asset_type()->name() << " issued by " << m_type->issuer()->get_name() << std::endl;
  ss << "Balance: " << balance() << " signed on "<<  balance_date() << std::endl;
  ss << "Pending Balance: " << get_pending_balance() << "\n";
  ss << "Reserved Sig #s: ";
  const std::vector<uint64_t>& rsg = sig_ids();
  for( uint32_t i = 0; i < rsg.size(); ++i ) {
    ss << rsg[i] <<" ";
    if( i % 30 == 29 ) ss<<"\n                ";
  }
  ss << "\n";
  ss << "New Sig #s: ";
  const std::vector<uint64_t>& nrsg = new_sig_ids();
  for( uint32_t i = 0; i < nrsg.size(); ++i ) {
    ss << nrsg[i] <<" ";
    if( i % 30 == 29 ) ss<<"\n                ";
  }
  ss << "\n";


  ss << "Owner Signed: " << (owner_signed() ? "Yes" : "No") <<std::endl;
  ss << "Host Signed: " << (host_signed() ? "Yes" : "No") <<std::endl;
  ss << std::left << std::setw(40) << "Description";
  ss << std::left << std::setw(10) << "Delta" ;
  ss << std::left << std::setw(10) << "Balance";
  ss << std::left << std::setw(25) << "Date";
  ss << std::left << std::setw(10) << "Sig #"<< "\n";
  ss << "-------------------------- Applied Transactions ----------------------------------------------------------\n";

  int64_t b = m_balance;
  dbo::collection<dbo::ptr<transaction> >::const_iterator itr = m_applied.begin();
  while( itr != m_applied.end() ) {
    int64_t delta = (*itr)->apply( get_id() ); 
    ss << std::left << std::setw(40) << (*itr)->get_description(); 
    ss << std::left << std::setw(10) << delta;
    ss << std::left << std::setw(10) << (b += delta);
    std::stringstream ss2; ss2 << (*itr)->get_date(); 
    ss << std::left << std::setw(25) << ss2.str();
    ss << std::left << std::setw(20) << *((*itr)->get_signature_num_for( get_id() )); 
    ss << "\n";
    ++itr;
  }
  ss << "-------------------------- Pending Transactions ----------------------------------------------------------\n";
  itr = m_out_box.begin();
  while( itr != m_out_box.end() ) {
    int64_t delta = (*itr)->apply( get_id() ); 
    ss << std::left << std::setw(40) << (*itr)->get_description(); 
    ss << std::left << std::setw(10) << delta;
    ss << std::left << std::setw(10) << (b += delta);
    std::stringstream ss2; ss2 << (*itr)->get_date(); 
    ss << std::left << std::setw(25) << ss2.str();
    ss << std::left << std::setw(20) << *((*itr)->get_signature_num_for( get_id() )); 
    ss << "\n";
    ++itr;
  }
  ss << "-------------------------- Proposed Transactions ---------------------------------------------------------\n";
  itr = m_in_box.begin();
  while( itr != m_out_box.end() ) {
    int64_t delta = (*itr)->apply( get_id() ); 
    ss << std::left << std::setw(40) << (*itr)->get_description(); 
    ss << std::left << std::setw(10) << delta;
    ss << std::left << std::setw(10) << (b += delta);
    std::stringstream ss2; ss2 << (*itr)->get_date(); 
    ss << std::left << std::setw(25) << ss2.str();
    ss << std::left << std::setw(20) << "---";
    ss << "\n";
    ++itr;
  }
  ss << "----------------------------------------------------------------------------------------------------------\n";
  dbtrx.commit();
  return ss.str();
}


/**
 *  This method must make sure of the following:
 *
 *  1) All applied_trx_ids are in the applied list.
 *  2) The result of applying those trx ids to the existing balance == new bal
 *  3) time > old balance time and less than current time and greater than (now - 5min)
 *  4) new_sig_nums is a subset of new_sig_ids()
 *  5) The owner sig reflects the new digest of the account.
 *
 */
void account::host_accept_balance( const signature& owner_sig, int64_t new_bal, const boost::posix_time::ptime& new_balance_date, 
                                   const std::vector<uint64_t>& new_sig_nums,
                                   const std::vector<sha1>& applied_trx_ids ) {
   if( !m_host->get_private_identity() ) {
      LTL_THROW( "No private identity know for host, %1%", %m_host->get_name() );
   }
  
   int64_t newbal; 
   sha1 digest; 
   std::set<uint64_t> open_sig_ids; 
   std::vector<uint64_t> open_new_sig_ids;
   mtrx_map mtrx;
  
   get_accept_balance_digest( new_balance_date, new_sig_nums, applied_trx_ids, newbal, digest, open_sig_ids, open_new_sig_ids, mtrx );
  
   if( newbal != new_bal ) {
      LTL_THROW( "Balance disagreement, host calculated %1% and owner calculated %2%",
                  %(newbal) %new_bal );
   }
   
   // validate the signature matches 
   if( !owner()->get_pub_key().verify( digest, owner_sig ) ) {
    LTL_THROW( "Invalid Owner Signature" );
   }
  
  
   // sign owner signature and store it as the server signature.
   scrypt::sha1_encoder enc;
   enc.write( owner_sig.data, sizeof(owner_sig.data) );
  
   signature host_sig;
   m_host->get_priv_key().sign( enc.result(), host_sig );
   
   // apply changes
   m_ohost_sig  = host_sig;
   m_oowner_sig = owner_sig;
   set_signature( m_owner_sig, owner_sig );
   set_signature( m_host_sig, host_sig );
   
   m_balance = new_bal;
   m_date    = to_milliseconds(new_balance_date);
   
   for( uint32_t i = 0; i < applied_trx_ids.size(); ++i ) {
     m_applied.erase( mtrx[ applied_trx_ids[i] ] ); 
   }
   
   // TODO: check all applied trx to see if refcount == 0, then erase!
    slog( "open_sig_ids %1%   open new sig ids %2%", open_sig_ids.size(), open_new_sig_ids.size() );
  
    const std::vector<uint64_t>& ccur_sids = sig_ids();
    std::vector<uint64_t>& cur_sids = *m_osig_ids;

    cur_sids.resize(0);
    cur_sids.insert( cur_sids.begin(), open_sig_ids.begin(), open_sig_ids.end() );
  
    m_onew_sig_ids = open_new_sig_ids;
    if( open_new_sig_ids.size() )
       m_new_sig_nums = scrypt::base64_encode( (const unsigned char*)&open_new_sig_ids.front(), open_new_sig_ids.size() * sizeof( uint64_t ) );
    else
       m_new_sig_nums = "";
   

    if( open_sig_ids.size() ) 
       m_sig_nums = scrypt::base64_encode( (const unsigned char*)&cur_sids.front(), cur_sids.size() * sizeof( uint64_t ) );
    else
       m_sig_nums = "";

    BOOST_ASSERT( owner_signed() );
}

void account::get_accept_balance_digest(  const boost::posix_time::ptime& new_balance_date, 
                                     const std::vector<uint64_t>& new_sig_nums, 
                                     const std::vector<sha1>& applied_trx_ids,
                                     int64_t& newbal, sha1& digest, 
                                     std::set<uint64_t>& open_sig_ids, 
                                     std::vector<uint64_t>& open_new_sig_ids,
                                     mtrx_map& mtrx )const
{ 
    if( balance_date() > new_balance_date ) {
       LTL_THROW( "Balance date %1% is older than most recent agreement date %2%", %new_balance_date %balance_date() );
    }
    if( new_balance_date > to_ptime( system_clock::now() ) ) {
       LTL_THROW( "Balance date %1% in the future, now: %2%", %new_balance_date %to_ptime(system_clock::now())) ;
    }
    if( new_balance_date < to_ptime( system_clock::now() - boost::chrono::seconds(60*5) ) ) {
       LTL_THROW( "Balance date %1% is more than 5 minutes in the past, now: %2%", %new_balance_date %to_ptime(system_clock::now())) ;
    }
   
    const std::vector<uint64_t>& nsids = new_sig_ids();
    // make sure new_sig_nums is a subset of new_sig_ids
    for( uint32_t i = 0; i < new_sig_nums.size(); ++i ) {
     // TODO: sig nums should always be stored in assending order... for hashing purposes
     if( std::find( nsids.begin(), nsids.end(), new_sig_nums[i] ) == nsids.end() ) {
       LTL_THROW( "Signature number %1% was not issued by host", %new_sig_nums[i] );
     }
     open_sig_ids.insert( new_sig_nums[i] );
     std::remove( open_new_sig_ids.begin(), open_new_sig_ids.end(), new_sig_nums[i] );
    }
   
    const std::vector<uint64_t>& cur_sids = sig_ids();
    for( uint32_t i = 0; i < cur_sids.size(); ++i )
     open_sig_ids.insert( cur_sids[i] );
   
    trx_collection::const_iterator itr = m_applied.begin();
    while( itr != m_applied.end() ) {
       mtrx[(*itr)->get_id()] = *itr; 
       ++itr;
    }
   
    int64_t delta_b = 0;
    // make sure all applied ids are known, and calculate delta balance
    for( uint32_t i = 0; i < applied_trx_ids.size(); ++i ) {
       mtrx_map::iterator mitr = mtrx.find( applied_trx_ids[i] );
       if( mitr == mtrx.end() ) {
         LTL_THROW( "Unknown applied transaction id %1%", %std::string(applied_trx_ids[i]) );
       }
       open_sig_ids.erase( *mitr->second->get_signature_num_for( get_id() ) );
       delta_b += mitr->second->apply( get_id() );
    }
    newbal = balance() + delta_b;
     
    // calculate the new digest based upon the new state.
    scrypt::sha1_encoder enc; 
    enc.write( (const char*)get_id().hash, sizeof(get_id().hash) );
    wlog( "%1%  %2% %3%", get_id(), m_balance, to_milliseconds( new_balance_date ) );
    enc << newbal;
    enc << to_milliseconds( new_balance_date );
    std::set<uint64_t>::iterator sitr = open_sig_ids.begin();
    while( sitr != open_sig_ids.end() ) {
     enc << *sitr;
     ++sitr;
    }
    digest = enc.result();
}

std::vector<std::string> get_trx_collection_ids( const account::trx_collection& trxs ){
  std::vector<std::string> r;
  account::trx_collection::const_iterator itr = trxs.begin();
  while( itr != trxs.end() ) {
    r.push_back( (*itr)->get_id() );
  }
  return r;
}

std::vector<std::string> account::get_inbox_ids()const {
  return get_trx_collection_ids( m_in_box );
}
std::vector<std::string> account::get_outbox_ids()const {
  return get_trx_collection_ids( m_out_box );
}
std::vector<std::string> account::get_applied_ids()const {
  return get_trx_collection_ids( m_applied );
}




} // namespace ltl
