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
  action::ptr create_offer( const json::value& v ) { return boost::shared_ptr<action>(new offer(v)); }

  bool action_factory_init() {
    act_factory()["transfer"] = create_transfer;
    act_factory()["offer"] = create_offer;
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



  offer::offer( const json::value& v ) {
    order_type = (std::string)v["order_type"];
    asset_account = sha1(v["asset_account"]);
    currency_account = sha1(v["currency_account"]);
    amount  = v["ammount"];
    min_amount  = v["min_amount"];
    offer_price  = v["price"];
    start  = to_ptime( (uint64_t) v["start"] );
    end  = to_ptime( (uint64_t) v["end"] );
  }

  const std::string& offer::type()const {
    static std::string t("offer");
    return t;
  }
  json::value        offer::to_json()const {
    json::value v;
    v["order_type"] = order_type;
    v["asset_account"] = std::string( asset_account );
    v["currency_account"] = std::string( currency_account );
    v["amount"] = amount;
    v["min_amount"] = min_amount;
    v["price"] = offer_price;
    v["start"] = to_milliseconds(start);
    v["end"] = to_milliseconds(end);
    return v;
  } 
  std::vector<sha1>  offer::required_signatures()const {
    std::vector<sha1> sigs(2);
    sigs[0] = asset_account;
    sigs[1] = currency_account;
    return sigs;
  }
  int64_t            offer::apply( const sha1& account )const {
    if( account == currency_account ) {
      return -offer_price * amount;
    }
    return 0;
  }


}
