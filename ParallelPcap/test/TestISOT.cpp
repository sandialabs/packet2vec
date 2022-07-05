#define BOOST_TEST_MAIN TestISOT
#include <boost/test/unit_test.hpp>
#include <ParallelPcap/ISOT.hpp>
#include <ParallelPcap/PacketInfo.hpp>
#include <ParallelPcap/Pcap.hpp>

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

BOOST_AUTO_TEST_CASE( test_IOST_class )
{
  std::string label_file = "../test/resources/sample_isot_labels.csv";
  std::string dump_file = "../test/resources/sample_isot_tcp.dump";

  ISOT isot(label_file);
  Pcap pcap(dump_file);

  int numPackets = pcap.getNumPackets();

  for (int i = 0; i < numPackets; i++)
  {
    PacketHeader pkthdr = pcap.getPacketHeader(i);
    std::vector<unsigned char> pkt = pcap.getPacket(i);
    PacketInfo packetInfo = PacketInfo::parse_packet(
      pkthdr.getTimestampSeconds(), pkthdr.getTimestampUSeconds(), pkt);

    std::cout << isot.packet_event_type(packetInfo);
  }
}
