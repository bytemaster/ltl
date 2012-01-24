#ifndef _LTL_IDENTITY_HPP_
#define _LTL_IDENTITY_HPP_
#include <ltl/crypto.hpp>
#include <ltl/dbo_traits.hpp>

namespace ltl {

  /**
   *  @ingroup ltl_dbo
   *
   *  Uniquely identifies a pseudonym that may or may not be linked to
   *  a real-world name/address.
   */
  class identity : public dbo::Dbo<identity>, public dbo::ptr<identity> {
    public:
      identity(){}

      identity( const public_key& pub, const dbo::ptr<private_identity>& priv_key,
                const std::string& name, const std::string& props, uint64_t _nonce = 0 );

      identity( const public_key& pk, 
                const std::string& name,
                uint64_t date,
                const std::string& props,
                const signature& sig, uint64_t _nonce = 0 );


      const sha1&        get_id()const;
      const std::string& get_name()const;
      const public_key&  get_pub_key()const;
      const private_key& get_priv_key()const;
      const signature&   get_signature()const;
      uint64_t           get_nonce()const;

      uint64_t           get_date()const;
      const std::string& get_properties()const;
      const std::string& get_pub_key_b64()const;
      const std::string& get_signature_b64()const;
      
      template<typename Action>
      void persist( Action& a );

      bool is_valid()const;

      dbo::collection<dbo::ptr<asset_note> >      issued_notes;

      void set_private_identity( dbo::ptr<private_identity>& pi );
      dbo::ptr<private_identity> get_private_identity()const;

    private:
      void sign();
      void set_public_key( const public_key& pk );
      void set_signature( const signature& sig );
      void set_id();

      // the database stores the ID as a string, but in the code
      // we often need the binary form.
      mutable boost::optional<sha1>       osha_id;
      mutable boost::optional<public_key> opub_key;
      mutable boost::optional<signature>  osig;

      dbo::collection<dbo::ptr<account> >          accounts;

      long long                                    nonce;
      std::string                                  db_id;
      std::string                                  name;
      std::string                                  properties;
      long long                                    date;
      std::string                                  id_sig;
      std::string                                  pub_key;
      dbo::collection<dbo::ptr<private_identity> > priv_key;
      mutable dbo::ptr<private_identity>           m_pi;
  };

  class private_identity : public dbo::ptr<private_identity> {
    public:
      private_identity(){};
      private_identity( const private_key& priv_key );
      
      const dbo::ptr<identity>& get_identity()const;
      const private_key&        get_priv_key()const;

      template<typename Action>
      void persist( Action& a );

    private:
      void set_private_key( const private_key& pk );
      dbo::ptr<identity>                    public_identity;
      std::string                           priv_key;
      mutable boost::optional<private_key>  opriv_key; // stores decoded private key, on demand
  };
  
} // namespace ltl

#endif // _LTL_IDENTITY_HPP_
