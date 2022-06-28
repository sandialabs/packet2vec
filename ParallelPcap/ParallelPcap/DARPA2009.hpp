#ifndef DARPA2009_HPP
#define DARPA2009_HPP

#include <map>
#include <vector>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <time.h>

#include <ParallelPcap/PacketInfo.hpp>

namespace parallel_pcap {

/**
 * The DARPA 2009 dataset has a csv file, DARPA_Groundtruth_10_day_test.csv
 * (found here: http://www.darpa2009.netsec.colostate.edu/), that outlines
 * which packets are malicious.  Individual packets are not listed, but instead
 * the time period and relevant ips and ports involved in the malicious
 * traffic.  There are also event types:
 * 1) scan /usr/bin/nmap
 * 2) client compromise
 * 3) malware ddos
 * 4) ddos
 * 5) failed attack framework
 * 6) no precursor client compromise exfil/sams_launch_v
 * 7) out2in
 * 8) compromised server
 * 9) c2 + tcp control channel exfil - no precursor nc
 **/
class DARPA2009MaliciousItem
{
public:
  DARPA2009MaliciousItem(std::string eventType, 
                         std::string c2s, 
                         std::string sourceIp,
                         std::string sourcePort, 
                         std::string destIp, 
                         std::string destPort,
                         time_t startTime,
                         time_t stopTime) 
      : eventType(eventType), c2s(c2s), sourceIp(sourceIp), 
        sourcePort(sourcePort), destIp(destIp),
        destPort(destPort), startTime(startTime), stopTime(stopTime) { }
    
  ~DARPA2009MaliciousItem() { }

  std::string getEventType() { return this->eventType; }
  std::string getC2s() { return this->c2s; }
  std::string getSourceIp() { return this->sourceIp; }
  std::string getSourcePort() { return this->sourcePort; }
  std::string getDestIp() { return this->destIp; }
  std::string getDestPort() { return this->destPort; }
  time_t getStartTime() { return this->startTime; }
  time_t getStopTime() { return this->stopTime; }

private:
  std::string eventType, c2s, sourceIp, sourcePort, destIp, destPort;
  long int startTime, stopTime;
};

class DARPA2009 
{
public:
  /**
   * Constructor. Parses the data from each row of the groundtruth csv.
   * \param filename A path to the DARPA2009 groundtruth csv file.
   */
  DARPA2009(std::string filename);
  ~DARPA2009();

  /**
   * Returns a boolean which indicates whether or not a packet is considered
   * malicious according to the DARPA2009 groundtruth csv.
   * \param packetInfo The PacketInfo object corresponding to the packet
   *                   you want to test.
   * \return Returns a boolean. True if packet is considered malicious.
   */
  bool is_danger(PacketInfo packetInfo);

  /**
   * Returns the type of event (e.g. ddos or benign
   * \param packetInfo The PacketInfo object corresponding to the packet
   *                   you want to test.
   * \return Returns a string with the event category.
   */
  std::string packet_event_type(PacketInfo packetInfo);

private:
  std::multimap<std::string, DARPA2009MaliciousItem> sourceIpIndex;
  time_t stringToEpoch(const std::string s);
};

DARPA2009::DARPA2009(std::string filename)
{
  std::ifstream ip(filename);

  // Check if file is open
  if (!ip.is_open()) std::cout << "Error opening file." << std::endl;

  std::string eventType;
  std::string c2s;
  std::string sourceIp;
  std::string sourcePort;
  std::string destIp;
  std::string destPort;
  std::string startTime;
  std::string stopTime;

  while (ip.good()) // Process each line of the file
  {
    // Use getline with a comma as a delimiter to get each field
    std::getline(ip, eventType, ',');
    std::getline(ip, c2s, ',');
    std::getline(ip, sourceIp, ',');
    std::getline(ip, sourcePort, ',');
    std::getline(ip, destIp, ',');
    std::getline(ip, destPort, ',');
    std::getline(ip, startTime, ',');
    std::getline(ip, stopTime, '\n');
    
    this->sourceIpIndex.insert(std::make_pair(
      sourceIp, 
      DARPA2009MaliciousItem(
        eventType, 
        c2s, 
        sourceIp, 
        sourcePort, 
        destIp, 
        destPort, 
        this->stringToEpoch(startTime), 
        this->stringToEpoch(stopTime)
      )
    ));
  }

  // Close file
  ip.close();
}

DARPA2009::~DARPA2009() { }

bool DARPA2009::is_danger(PacketInfo packetInfo)
{
  if (this->sourceIpIndex.count(packetInfo.getSourceIp())) 
  {
    auto range = this->sourceIpIndex.equal_range(packetInfo.getSourceIp());

    for (auto i = range.first; i != range.second; ++i)
    { 
      if (i->second.getDestIp() == packetInfo.getDestIp()
      && (unsigned long int) packetInfo.getStartTime() >= 
         (unsigned long int) i->second.getStartTime()
      && (unsigned long int) packetInfo.getStartTime() <= 
         (unsigned long int) i->second.getStopTime()) 
      {
        return true;
      }
    }
  }
  return false;
}

std::string DARPA2009::packet_event_type(PacketInfo packetInfo)
{
  if (this->sourceIpIndex.count(packetInfo.getSourceIp())) 
  {
    auto range = this->sourceIpIndex.equal_range(packetInfo.getSourceIp());

    for (auto i = range.first; i != range.second; ++i)
    { 
      if (i->second.getDestIp() == packetInfo.getDestIp()
      && (unsigned long int) packetInfo.getStartTime() >= 
         (unsigned long int) i->second.getStartTime()
      && (unsigned long int) packetInfo.getStartTime() <= 
         (unsigned long int) i->second.getStopTime()) 
      {
        return i->second.getEventType();
      }
    }
  }
  return "Benign";
}

time_t DARPA2009::stringToEpoch(const std::string s)
{
  std::tm t = {};
  strptime(s.c_str(), "%m/%d/%Y %H:%M", &t);
  t.tm_hour += 5; // Change from EST to UTC

  // NOTE: timegm does not subtract server's timezone
  return timegm(&t);
}

}

#endif
