#define BOOST_TEST_MAIN TestISOT
#include <boost/test/unit_test.hpp>
#include <ParallelPcap/Time.hpp>

using namespace parallel_pcap;

BOOST_AUTO_TEST_CASE( test_utc_local_diff )
{
  long diff = local_utc_diff();
  // I believe the difference should always be a multiple of one hour in
  // seconds.
  BOOST_CHECK_EQUAL(diff % 3600, 0);
}

BOOST_AUTO_TEST_CASE( test_utc_seconds_from_datetime )
{
  std::string timestamp = "2016-12-08T20:40:49";
  std::string format = "%Y-%m-%dT%H:%M:%S";
  long seconds = utc_seconds_from_datetime(timestamp, format);
  BOOST_CHECK_EQUAL(seconds, 1481229649);
}
