#include <ltl/date_time.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

namespace ltl {
using boost::chrono::system_clock;
boost::posix_time::ptime to_ptime( uint64_t milliseconds_from_epoch ) {
    static boost::posix_time::ptime epoch(boost::gregorian::date(1970, boost::gregorian::Jan, 1));
    return epoch + boost::posix_time::seconds(long(milliseconds_from_epoch/1000)) + boost::posix_time::microseconds(long(milliseconds_from_epoch%1000));
}

boost::posix_time::ptime to_ptime( const system_clock::time_point& t ) {
    typedef boost::chrono::microseconds duration_t;
    typedef duration_t::rep rep_t;
    rep_t d = boost::chrono::duration_cast<duration_t>(t.time_since_epoch()).count();
    static boost::posix_time::ptime epoch(boost::gregorian::date(1970, boost::gregorian::Jan, 1));
    return epoch + boost::posix_time::seconds(long(d/1000000)) + boost::posix_time::microseconds(long(d%1000000));
}
uint64_t to_milliseconds( const boost::posix_time::ptime& pt ) {
    static boost::posix_time::ptime epoch(boost::gregorian::date(1970, boost::gregorian::Jan, 1));
    boost::posix_time::time_duration dur = (pt - epoch);
    return dur.ticks() / 1000;
}

}
