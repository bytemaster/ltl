#include "action.hpp"
#include <log/log.hpp>

namespace ltl {


  std::map<std::string,action_creator>& act_factory() {
    static std::map<std::string,action_creator> fact;
    return fact;
  }

  action::ptr action::create( const json::value& from_json ) {
    if( from_json.contains("type") && from_json.contains("data") ) 
        return act_factory()[from_json["type"]]( from_json["data"] );
    return action::ptr();
  }
  void register_type( const std::string& act, const action_creator& c ) {
    act_factory()[act] = c;
  }

  json::value action::json()const {
    json::value v;
    v["type"] = type();
    v["data"] = to_json();
    return v;
  }


  action::ptr create_transfer( const json::value& v ) { return boost::shared_ptr<action>(new transfer(v)); }

  bool action_factory_init() {
    act_factory()["transfer"] = create_transfer;
  }

  static bool init_action_factory = action_factory_init();
  

  transfer::transfer( const json::value& v ) {
    from     = sha1((const std::string&)(v["from"]));
    to       = sha1((const std::string&)(v["to"]));
    amount   = v["to"];
  }

  transfer::transfer( int64_t _amount, const sha1& _from, const sha1& _to )
  :amount(_amount),from(_from),to(_to){}

  json::value transfer::to_json()const {
    json::value v;
    v["from"]   = std::string(from);
    v["to"]     = std::string(to);
    v["amount"] = amount;
    return v; 
  }

  const std::string& transfer::type()const {
    static std::string t("transfer");
    return t;
  }
  
  std::vector<sha1> transfer::required_signatures()const {
    std::vector<sha1> req; 
    req.push_back(from); 
    req.push_back(to);
    return req;
  }
  int64_t           transfer::apply( const sha1& account )const {
    slog( "account %1%   from %2%  ", std::string(account), std::string(from) );
    if( account == from ) return -amount;
    return amount;
  }

}
