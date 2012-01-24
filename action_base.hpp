#ifndef _LTL_ACTION_BASE_HPP_
#define _LTL_ACTION_BASE_HPP_
#include <json/value.hpp>
#include <boost/function.hpp>
#include <boost/shared_ptr.hpp>

namespace ltl {
  class action_base;
  typedef boost::function< boost::shared_ptr<action_base>( const json::value& ) > action_creator;

  struct action_visitor {
      virtual ~action_visitor(){}
      virtual void apply( const action& a )const = 0;
  };

  template<typename T>
  struct action_target {
    virtual void apply( const T& )const = 0; 
  };

  class action_base {
    public:
      typedef boost::shared_ptr<action_base> ptr;

      virtual const std::string& type()const = 0;

      virtual ~action_base(){}
      virtual void apply( const action_visitor& ) = 0;

      json::value json()const;

      friend json::value&       operator<<(json::value& v, const action::ptr& s ) {
        if( !s ) return v;
        v = json::value(); 
        v["type"] = s->type();
        v["data"] = s->to_json();
        return v;
      }
      friend const json::value& operator>>(const json::value& v, action::ptr& s ) {
        s = action::create( v );
        return v;
      }
    
    private:
      virtual json::value               to_json()const                    = 0;

      // action factory
      static action::ptr create( const json::value& v );
      static void        register_type( const std::string& act, const action_creator& c );

  };

  template<typename DerivedT>
  struct action : public action_base {
     void apply( const base_visitor& b )const {
        const action_target<DerivedT>* tt = dynamic_cast< const action_target<DerivedT>* >(&b);
        if( tt )
          tt->apply( dynamic_cast<const DerivedT&>(*this) );
     }
  };
  
} // namespace ltl

#endif
