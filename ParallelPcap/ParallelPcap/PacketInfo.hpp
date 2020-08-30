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

class PacketInfo {
public:
  PacketInfo(unsigned int protocol, std::string sourceIp, unsigned int sourcePort, 
    std::string destIp, unsigned int destPort, unsigned int startTime);
  ~PacketInfo();
  
  /**
   * Returns a PacketInfo object.  Parses the supplied packet data.
   * \param pkthdr A integer packet header.
   * \param packetVector A vector of chars representing the packet.
   * \param Returns a PacketInfo object.
   */
  static PacketInfo parse_packet(unsigned int pkthdr, std::vector<unsigned char> const &packetVector);

  unsigned int getProtocol() { return this->protocol; }
  std::string getSourceIp() { return this->sourceIp; }
  unsigned int getSourcePort() { return this->sourcePort; }
  std::string getDestIp() { return this->destIp; }
  unsigned int getDestPort() { return this->destPort; }
  unsigned int getStartTime() { return this->startTime; }

private:
  std::string sourceIp;
  std::string destIp;
  unsigned int protocol, sourcePort, destPort, startTime;
};

PacketInfo::PacketInfo(
  unsigned int protocol, 
  std::string sourceIp, 
  unsigned int sourcePort, 
  std::string destIp, 
  unsigned int destPort, 
  unsigned int startTime
) : protocol(protocol), sourceIp(sourceIp), sourcePort(sourcePort), 
    destIp(destIp), destPort(destPort), startTime(startTime) { }

PacketInfo::~PacketInfo() { }

PacketInfo PacketInfo::parse_packet(unsigned int timestamp, std::vector<unsigned char> const &packetVector)
{
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
      tcpHeader = (tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
      sourcePort = ntohs(tcpHeader->source);
      destPort = ntohs(tcpHeader->dest);
    } else if (ipHeader->ip_p == IPPROTO_UDP) {
      udpHeader = (udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
      sourcePort = ntohs(udpHeader->source);
      destPort = ntohs(udpHeader->dest);
    } else if (ipHeader->ip_p == IPPROTO_ICMP) {
      // Do nothing... don't care about this case
    }
  }

  // Create PacketInfo Object
  return PacketInfo(protocol, sourceIp, sourcePort, destIp, destPort, timestamp);
}

}
#endif