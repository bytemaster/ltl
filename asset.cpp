#include <ltl/asset.hpp>
#include <ltl/error.hpp>
#include <ltl/identity.hpp>
#include <ltl/transaction.hpp>
#include <scrypt/base64.hpp>
#include <ltl/account.hpp>

#include <log/log.hpp>


namespace ltl {

  asset::asset( const std::string& _name, const std::string& _prop )
  :m_name(_name),m_properties(_prop) {
    scrypt::sha1_encoder enc;
    enc.write( m_name.c_str(), m_name.size() );
    enc.write( m_properties.c_str(), m_properties.size() );
    sha_id = enc.result();
    id = *sha_id;
  }

  
  const sha1& asset::get_id()const {
    if( !sha_id ) {
      sha_id = sha1(id);
      return *sha_id;
    }
    return *sha_id;
  }
  const std::string& asset::properties()const { return m_properties; }

  asset_note::asset_note( const dbo::ptr<identity>& issuer, const dbo::ptr<asset>& a,
                          const std::string& name, const std::string& props ) {
      m_asset_type = a;
      m_issuer     = issuer;
      m_name       = name;
      m_properties = props;
    

      scrypt::sha1_encoder enc;
      const sha1& iid = issuer->get_id();
      const sha1& aid = a->get_id();
      enc.write( (const char*)iid.hash, sizeof(iid.hash) );
      enc.write( (const char*)aid.hash, sizeof(aid.hash) );
      enc.write( m_name.c_str(), m_name.size() );
      enc.write( m_properties.c_str(), m_properties.size() );

      m_oid = enc.result();
      m_id = *m_oid;

      m_osig = signature();
      assert( issuer );
      issuer->get_priv_key().sign( *m_oid, *m_osig );
      set_signature( *m_osig );

      if( !is_valid() ) {
        LTL_THROW( "Invalid note properties '%1%'", %name );
      }
  }



  asset_note::asset_note( const dbo::ptr<identity>& issuer, const dbo::ptr<asset>& a,
                          const std::string& name, const std::string& props,
                          const signature& sig ) {
      m_asset_type = a;
      m_issuer     = issuer;
      m_name       = name;
      m_properties = props;
    
      set_signature( sig );

      scrypt::sha1_encoder enc;
      const sha1& iid = issuer->get_id();
      const sha1& aid = a->get_id();
      enc.write( (const char*)iid.hash, sizeof(iid.hash) );
      enc.write( (const char*)aid.hash, sizeof(aid.hash) );
      enc.write( m_name.c_str(), m_name.size() );
      enc.write( m_properties.c_str(), m_properties.size() );

      m_oid = enc.result();
      m_id = *m_oid;

      if( !is_valid() ) {
        LTL_THROW( "Invalid asset note signature '%1%'", %name );
      }
  }


  const sha1& asset_note::get_id()const {
    if( !m_oid ) { m_oid = sha1(m_id); }
    return *m_oid;
  }


  void asset_note::set_signature( const signature& sig ) {
      m_osig = sig;
      std::stringstream sssig;
      sssig <<  sig;
      m_issuer_sig = scrypt::base64_encode( sssig.str() );
  }
  const signature&  asset_note::get_signature()const {
    if( !m_osig ) {
      std::string pk_decode = scrypt::base64_decode( m_issuer_sig );
      std::stringstream ss( pk_decode  );
      m_osig = signature();
      ss >> *m_osig;
    }
    return *m_osig;
  }
  const std::string& asset_note::get_signature_b64()const { return m_issuer_sig; }

  /**
   *   asset( id == sha1( issuer.id + asset.id + name + props ) )
   *   asset( issuer.verify(id, sig) )
   */
  bool                     asset_note::is_valid()const {
      scrypt::sha1_encoder enc;
      const sha1& iid = m_issuer->get_id();
      const sha1& aid = m_asset_type->get_id();
      enc.write( (const char*)iid.hash, sizeof(iid.hash) );
      enc.write( (const char*)aid.hash, sizeof(aid.hash) );
      enc.write( m_name.c_str(), m_name.size() );
      enc.write( m_properties.c_str(), m_properties.size() );
      sha1 r = enc.result();
      if( get_id() != r )   
        return false;
      return m_issuer->get_pub_key().verify( r, get_signature() );
  }
  const std::string&       asset_note::properties()const {
    return m_properties;
  }
  const std::string&       asset_note::name()const {
    return m_name;
  }
  const dbo::ptr<identity>& asset_note::issuer()const {
    return m_issuer;
  }
  const dbo::ptr<asset>&    asset_note::asset_type()const {
    return m_asset_type;
  }

  const std::string&      asset::name()const {
    return m_name;
  }


} // namespace ltl
