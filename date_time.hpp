#ifndef _LTL_DATE_TIME_HPP_
#define _LTL_DATE_TIME_HPP_
#include <boost/date_time/posix_time/ptime.hpp>
#include <boost/chrono.hpp>

namespace ltl {
typedef boost::posix_time::ptime ptime;
using boost::chrono::system_clock;
ptime     to_ptime( const system_clock::time_point& t );
ptime     to_ptime( uint64_t milliseconds_from_epoch = 0);
uint64_t  to_milliseconds( const ptime& pt );
};
#endif
