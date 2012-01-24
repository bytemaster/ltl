#include <ltl/persist.hpp>
#include <ltl/error.hpp>
#include <scrypt/base64.hpp>

#include <boost/chrono.hpp>
#include <log/log.hpp>

namespace ltl {

      /**
       *  Construct an identity given required fields.
       *
       *  Throw if signature is not valid.
       */
      identity::identity( const public_key& pk, const std::string& _name,
                          uint64_t _date, const std::string& props,
                          const signature& sig, uint64_t _nonce )  {
          name       = _name;
          date       = _date;
          properties = props;
          nonce      = _nonce;
          
          set_public_key( pk );
          set_id();
          set_signature( sig );

          if( !is_valid() )
            LTL_THROW( "Invalid Signature creating identity '%1%'", %_name );
      }

      identity::identity( const public_key& pub, const dbo::ptr<private_identity>& pi,
                          const std::string& _name, const std::string& props, uint64_t _nonce ) {
        if( !pi ) {
            LTL_THROW( "Invalid Private Identity", %_name );
        }

        set_public_key(pub);
        set_id();
        using namespace boost::chrono;
        date       = duration_cast<microseconds>(system_clock::now().time_since_epoch()).count();
        nonce      = _nonce;
        name       = _name;
        properties = props;

     //   priv_key.insert(pi);
     //   sign();
      }

      void identity::set_id() {
          scrypt::sha1_encoder enc; enc  << get_pub_key();
          osha_id = enc.result(); 
          db_id   = *osha_id;
      }
      void identity::set_signature( const signature& sig ) {
        
        const sha1& i = get_id(); 
        scrypt::sha1_encoder sig_digest;
        sig_digest.write( (char*)i.hash, sizeof(i.hash) );
        sig_digest.write( name.c_str(), name.size() );
        sig_digest << date;
        sig_digest.write( properties.c_str(), properties.size() );

        scrypt::sha1 r = sig_digest.result();
        if( !get_pub_key().verify( r, sig ) ) {
          LTL_THROW( "Invalid signature for identity '%1%'", %std::string(i) );
        }

        osig = sig;
        id_sig = scrypt::to_base64( sig );
      }

      void identity::set_public_key( const public_key& pk ) {
          opub_key = pk;
          std::stringstream pkstr;
          pkstr << pk;
          pub_key = scrypt::base64_encode( pkstr.str() );
      }

      void identity::set_private_identity( dbo::ptr<private_identity>& pi ) {
        priv_key.insert(pi);
        sign();
        if( !is_valid() ) {
          LTL_THROW( "Private key signature not validated by public key" );
        }
      }

      dbo::ptr<private_identity> identity::get_private_identity()const {
          dbo::collection<dbo::ptr<private_identity> >::const_iterator itr = priv_key.begin();
          if( itr == priv_key.end() ) {
            return dbo::ptr<private_identity>();
          }
          return *itr;
      }
      const private_key& identity::get_priv_key()const {
          if( m_pi ) return m_pi->get_priv_key();
          dbo::collection<dbo::ptr<private_identity> >::const_iterator itr = priv_key.begin();
          if( itr == priv_key.end() ) {
            LTL_THROW( "No private key for identity '%1%'", %name );
          }
          m_pi = (*itr);
          return m_pi->get_priv_key();
      }

      /**
       *  Attempts to sign the identity using the private key, will
       *  throw an exception if there is no private key.
       */
      void identity::sign() {
        const sha1& i = get_id(); 
        scrypt::sha1_encoder sig_digest;
        sig_digest.write( (char*)i.hash, sizeof(i.hash) );
        sig_digest.write( name.c_str(), name.size() );
        sig_digest << date;
        sig_digest.write( properties.c_str(), properties.size() );

        scrypt::sha1 r = sig_digest.result();
        signature sig;
        get_priv_key().sign( r, sig );

        osig   = sig;
        id_sig = scrypt::to_base64(sig); 
      }
    

      const sha1& identity::get_id()const {
        if( !osha_id ) { osha_id = sha1(db_id); }
        return *osha_id;
      }

      const std::string& identity::get_name()const {
        return name;
      }

      const public_key&  identity::get_pub_key()const {
        if( !opub_key ) {
          std::string pk_decode = scrypt::base64_decode( pub_key );
          std::stringstream ss( pk_decode  );
          opub_key = public_key();
          ss >> *opub_key;
        }
        return *opub_key;
      }
      const std::string& identity::get_pub_key_b64()const    { return pub_key;    }
      uint64_t           identity::get_date()const           { return date;       }
      uint64_t           identity::get_nonce()const          { return nonce;      }
      const std::string& identity::get_properties()const     { return properties; }
      const std::string& identity::get_signature_b64()const  { return id_sig;     }

      const signature&  identity::get_signature()const {
        if( !osig ) {
          std::string pk_decode = scrypt::base64_decode( id_sig );
          std::stringstream ss( pk_decode  );
          osig = signature();
          ss >> *osig;
        }
        return *osig;
      }


      
      /**
       *  id must be sha1(pub_key)
       *  pub_key.verify( sha1( id, name, date, properties ), signature )
       */
      bool identity::is_valid()const {
          const sha1& i = get_id(); 
          scrypt::sha1_encoder sig_digest;
          sig_digest.write( (char*)i.hash, sizeof(i.hash) );
          sig_digest.write( name.c_str(), name.size() );
          sig_digest << date;
          sig_digest.write( properties.c_str(), properties.size() );

          return get_pub_key().verify( sig_digest.result(), get_signature() );
      }


      const private_key&  private_identity::get_priv_key()const {
        if( !opriv_key ) {
          std::stringstream ss(priv_key);
          opriv_key = private_key();
          ss >> (*opriv_key);
        }
        return *opriv_key;
      }

      private_identity::private_identity( const private_key& pk ) {
        set_private_key(pk);
      }
      void private_identity::set_private_key( const private_key& pk ) {
          std::stringstream ss; ss << pk;
          priv_key = ss.str();
          opriv_key = pk;
      }


} // namespace ltl
