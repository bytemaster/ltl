#ifndef _LTL_DBO_TRAITS_HPP_
#define _LTL_DBO_TRAITS_HPP_
#include <Wt/Dbo/Dbo>
#include <Wt/Dbo/WtSqlTraits>

namespace ltl {
  namespace dbo = Wt::Dbo;
  class account;
  class identity;
  class private_identity;
  class asset;
  class asset_note;
  class transaction;
}
namespace Wt { namespace Dbo {

  template<>
  struct dbo_traits<ltl::account> : public dbo_default_traits {
    typedef std::string IdType;
    static IdType invalidId() { return IdType(); }
    static const char* surrogateIdField() { return 0; }
  };
  
  template<>
  struct dbo_traits<ltl::identity> : public dbo_default_traits {
    typedef std::string IdType;
    static IdType invalidId() { return IdType(); }
    static const char* surrogateIdField() { return 0; }
  };

  template<>
  struct dbo_traits<ltl::private_identity> : public dbo_default_traits {
    typedef ptr<ltl::identity> IdType;
    static IdType invalidId() { return IdType(); }
    static const char* surrogateIdField() { return 0; }
  };

  template<>
  struct dbo_traits<ltl::asset> : public dbo_default_traits {
    typedef std::string IdType;
    static IdType invalidId() { return IdType(); }
    static const char* surrogateIdField() { return 0; }
  };

  template<>
  struct dbo_traits<ltl::asset_note> : public dbo_default_traits {
    typedef std::string IdType;
    static IdType invalidId() { return IdType(); }
    static const char* surrogateIdField() { return 0; }
  };

} }

#endif
