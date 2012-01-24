#ifndef _LTL_ASSET_HPP_
#define _LTL_ASSET_HPP_
#include <ltl/crypto.hpp>
#include <ltl/dbo_traits.hpp>

namespace ltl {

  class asset {
    public:
      asset( const std::string& name="", const std::string& prop = "" ); 

      const sha1& get_id()const;
      const std::string& name()const;
      const std::string& properties()const;

      dbo::collection<dbo::ptr<asset_note> > issuers;

      template<typename Action>
      void persist( Action& a );

    private:
      mutable boost::optional<sha1> sha_id; //id.fromhex
      std::string           id; // sha1( asset_type.id + issuer.id ).tohex
      std::string           m_name;
      std::string           m_properties;
  };

  class asset_note : public dbo::ptr<asset_note> {
    public:
      asset_note( const dbo::ptr<identity>& issuer, const dbo::ptr<asset>& a,
                  const std::string& name, const std::string& props,
                  const signature& issuer_sig );
      asset_note( const dbo::ptr<identity>& issuer, const dbo::ptr<asset>& a,
                  const std::string& name, const std::string& props );
      asset_note(){}

      const sha1&               get_id()const;
      const signature&          get_signature()const;
      const std::string&        get_signature_b64()const;
      bool                      is_valid()const;
      const std::string&        properties()const;
      const std::string&        name()const;
      const dbo::ptr<identity>& issuer()const;
      const dbo::ptr<asset>&    asset_type()const;

      template<typename Action>
      void persist( Action& a );

    private:
      void set_signature( const signature& );
      mutable boost::optional<sha1>       m_oid;
      mutable boost::optional<signature>  m_osig;

      dbo::ptr<asset>    m_asset_type;
      dbo::ptr<identity> m_issuer;
      std::string        m_id; // sha1( json(asset_type.id + issuer.id + name + properties + issuer_sig) )
      std::string        m_name;
      std::string        m_properties;
      std::string        m_issuer_sig; // issuer.sign( id, issuer_sig );
  };
} // namespace ltl

#endif
