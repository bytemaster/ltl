#ifndef _LTL_DATE_TIME_HPP_
#define _LTL_DATE_TIME_HPP_
#include <boost/date_time/posix_time/ptime.hpp>
#include <boost/chrono.hpp>

namespace ltl {
using boost::chrono::system_clock;
boost::posix_time::ptime to_ptime( const system_clock::time_point& t );
boost::posix_time::ptime to_ptime( uint64_t milliseconds_from_epoch = 0);
uint64_t                 to_milliseconds( const boost::posix_time::ptime& pt );
};
#endif
