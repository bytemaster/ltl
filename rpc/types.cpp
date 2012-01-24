#include "types.hpp"
#include <scrypt/sha1.hpp>

namespace ltl { namespace rpc {
  asset::asset( const std::string& _name, const std::string& _props )
  :name(_name),properties(_props){
    scrypt::sha1_encoder enc;
    enc.write( name.c_str(), name.size() );
    enc.write( properties.c_str(), properties.size() );
    id = (std::string)enc.result();
  }

} } 
