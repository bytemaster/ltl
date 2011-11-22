#ifndef _LTL_CRYPTO_HPP_
#define _LTL_CRYPTO_HPP_
#include <scrypt/sha1.hpp>
#include <scrypt/scrypt.hpp>
namespace ltl {
  typedef scrypt::sha1              sha1;
  typedef scrypt::signature<2048>   signature;
  typedef scrypt::public_key<2048>  public_key;
  typedef scrypt::private_key<2048> private_key;
}
#endif
