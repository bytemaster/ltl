#include <ltl/action_base.hpp>
#include <ltl/action.hpp>

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
}
