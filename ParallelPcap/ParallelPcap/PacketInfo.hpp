#ifndef PACKETINFO_HPP
#define PACKETINFO_HPP

#include <ParallelPcap/Packet.hpp> 
#include <iostream>
#include <vector>

// Packet includes
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

namespace parallel_pcap {

/**
 * Class to represent identifying information of a packet.
 */
class PacketInfo {
public:

  /**
   * Constructor with all the parameters considered sufficient to identify
   * a packet.
   */
  PacketInfo(unsigned int protocol, 
             std::string sourceIp, unsigned int sourcePort, 
             std::string destIp, unsigned int destPort, 
             uint32_t seconds, uint32_t useconds);
  ~PacketInfo();
  
  /**
   * Returns a PacketInfo object.  Parses the supplied packet data.
   * \param uint32_t seconds The number of seconds.
   * \param uint32_t useconds The number of microseconds.
   * \param packetVector A vector of chars representing the packet.
   * \param Returns a PacketInfo object.
   */
  static PacketInfo parse_packet(uint32_t seconds, uint32_t useconds,
                               std::vector<unsigned char> const &packetVector);

  unsigned int getProtocol() const { return this->protocol; }
  std::string getSourceIp() const { return this->sourceIp; }
  unsigned int getSourcePort() const { return this->sourcePort; }
  std::string getDestIp() const { return this->destIp; }
  unsigned int getDestPort() const { return this->destPort; }
  unsigned int getSeconds() const { return this->seconds; }
  unsigned int getUSeconds() const { return this->useconds; }

  std::string toString() const;

private:
  std::string sourceIp;
  std::string destIp;
  unsigned int protocol, sourcePort, destPort;
  uint32_t seconds;
  uint32_t useconds;
};

PacketInfo::PacketInfo(
  unsigned int protocol, 
  std::string sourceIp, 
  unsigned int sourcePort, 
  std::string destIp, 
  unsigned int destPort, 
  uint32_t seconds, 
  uint32_t useconds)
  : protocol(protocol), sourceIp(sourceIp), sourcePort(sourcePort), 
    destIp(destIp), destPort(destPort), seconds(seconds),
    useconds(useconds) { }

PacketInfo::~PacketInfo() { }

std::string PacketInfo::toString() const
{
  std::string s = "Protocol " + boost::lexical_cast<std::string>(protocol) + 
    " sourceIp " + sourceIp + 
    " sourcePort " + boost::lexical_cast<std::string>(sourcePort) +
    " destIp " + destIp +
    " destPort " + boost::lexical_cast<std::string>(destPort) +
    " seconds " + boost::lexical_cast<std::string>(seconds) +
    " useconds " + boost::lexical_cast<std::string>(useconds);
  return s;
}

PacketInfo PacketInfo::parse_packet(uint32_t seconds, uint32_t useconds,
                                 std::vector<unsigned char> const &packetVector)
{
  assert(useconds <= 999999); // Make sure useconds is microseconds.

  // Convert vector to char array
  unsigned const char* packet = &packetVector[0];

  const struct ether_header* ethernetHeader;
  const struct ip* ipHeader;
  const struct tcphdr* tcpHeader;
  const struct udphdr* udpHeader;

  unsigned int protocol;
  unsigned int sourcePort = 0;
  unsigned int destPort = 0;
  std::string sourceIp;
  std::string destIp;

  ethernetHeader = (struct ether_header*)packet;

  // Only want to parse IP packets
  if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP)
  {
    // Parse IP header
    ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
    std::string sourceIpString(inet_ntoa(ipHeader->ip_src));
    std::string destIpString(inet_ntoa(ipHeader->ip_dst));
    protocol = ntohs(ethernetHeader->ether_type);

    sourceIp = sourceIpString;
    destIp = destIpString;

    if (ipHeader->ip_p == IPPROTO_TCP) {
      tcpHeader = (tcphdr*)(packet + sizeof(struct ether_header) + 
                            sizeof(struct ip));
      sourcePort = ntohs(tcpHeader->source);
      destPort = ntohs(tcpHeader->dest);
    } else if (ipHeader->ip_p == IPPROTO_UDP) {
      udpHeader = (udphdr*)(packet + sizeof(struct ether_header) + 
                            sizeof(struct ip));
      sourcePort = ntohs(udpHeader->source);
      destPort = ntohs(udpHeader->dest);
    } else if (ipHeader->ip_p == IPPROTO_ICMP) {
      // Do nothing... don't care about this case
    }
  }

  // Create PacketInfo Object
  return PacketInfo(protocol, sourceIp, sourcePort, destIp, destPort, 
                    seconds, useconds);
}

}
#endif
