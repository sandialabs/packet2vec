#define BOOST_TEST_MAIN TestISOT
#include <boost/test/unit_test.hpp>
#include <ParallelPcap/ISOT.hpp>

using namespace parallel_pcap;

BOOST_AUTO_TEST_CASE( test_timestamp_conversion)
{
  std::string classification = "benign";
  std::string timestamp = "2016-12-08T20:40:49.538528Z";
  std::string protocol = "tcp";
  std::string sourceIp = "142.104.64.196";
  unsigned int sourcePort = 514;
  std::string destIp = "172.16.1.23";
  unsigned int destPort = 55299;
  
  ISOTItem item(classification, timestamp, protocol, sourceIp, sourcePort,
                destIp, destPort);

  BOOST_CHECK_EQUAL(item.getTimestamp(), 1481229649538528);
}
