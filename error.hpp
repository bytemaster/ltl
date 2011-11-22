#ifndef LTL_ERROR_HPP
#define LTL_ERROR_HPP
#include <boost/exception/all.hpp>
#include <boost/format.hpp>

typedef boost::error_info<struct err_msg_,std::string> err_msg;

struct ltl_exception : public virtual boost::exception, public virtual std::exception {
    const char* what()const throw()     { return "ltl_exception";                     }
    virtual void       rethrow()const   { BOOST_THROW_EXCEPTION(*this);                  } 
    const std::string& message()const   { return *boost::get_error_info<err_msg>(*this); }
};

/**
 *  Helper macro for throwing exceptions with a message:  THROW( "Hello World %1%, %2%", %"Hello" %"World" )
 */
#define LTL_THROW( MSG, ... ) \
  do { \
    BOOST_THROW_EXCEPTION( ltl_exception() << err_msg( (boost::format( MSG ) __VA_ARGS__ ).str() ) );\
  } while(0)

#endif
