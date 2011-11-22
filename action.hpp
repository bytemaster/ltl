#ifndef _LTL_ACTION_HPP_
#define _LTL_ACTION_HPP_
#include <boost/shared_ptr.hpp>
#include <vector>
#include <scrypt/sha1.hpp>
#include <stdint.h>
#include <json/value.hpp>
#include <boost/function.hpp>

namespace ltl {
  typedef scrypt::sha1 sha1;
  class action;
  typedef boost::function< boost::shared_ptr<action>( const json::value& ) > action_creator;

  /**
   *  Base class for all actions.  
   */
  class action {
    public:
      typedef boost::shared_ptr<action> ptr;
      virtual ~action(){};

      json::value json()const;

      virtual const std::string& type()const                       = 0;
      virtual std::vector<sha1>  required_signatures()const        = 0;

      /**
       *  Applies this action to account and returns the delta balance.
       */
      virtual int64_t                   apply( const sha1& account )const = 0;

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

    protected:
      virtual json::value               to_json()const                    = 0;

      // action factory
      static action::ptr create( const json::value& v );
      static void        register_type( const std::string& act, const action_creator& c );
  };

  class transfer : public action {
    public:
      transfer( const json::value& v = json::value());
      transfer( int64_t amount, const sha1& _from, const sha1& _to );

      virtual const std::string&        type()const;
      virtual json::value               to_json()const;
      virtual std::vector<sha1>         required_signatures()const;
      virtual int64_t                   apply( const sha1& account )const;

      sha1        from;
      sha1        to;
      int64_t     amount;
  };

} // namespace ltl

#endif
