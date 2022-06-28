#ifndef ISOT_HPP
#define ISOT_HPP

#include <map>
#include <fstream>
#include <string>
#include <sstream>
#include <locale>
#include <iomanip>

#include <boost/lexical_cast.hpp>

#include <ParallelPcap/PacketInfo.hpp>

namespace parallel_pcap {

/**
 * Represents one line from a ISOT label file.  There are class member
 * variables for:
 * 
 * timestamp
 * protocol
 * sourceIp
 * sourcePort
 * destIp
 * destPort  
 *
 * There are other fields in the label file, but they are not used.
 */
class ISOTItem
{
public:
  ISOTItem(std::string timestamp, 
            std::string protocol,
            std::string sourceIp,
            std::string sourcePort,
            std::string destIp,
            std::string destPort) 
  : timestamp(timestamp), protocol(protocol),
    sourceIp(sourceIp), sourcePort(sourcePort),
    destIp(destIp), destPort(destPort)
  {}

  ~ISOTItem() {}

  //std::string getTimestamp() { return this->Timestamp; }
  std::string getProtocol() { return this->protocol; }
  std::string getSourceIp() { return this->sourceIp; }
  std::string getSourcePort() { return this->sourcePort; }
  std::string getDestIp() { return this->destIp; }
  std::string getDestPort() { return this->destPort; }


  /**
   * Converts the original timestamp, e.g. 2016-12-08T20:40:49.538528Z,
   * into a long that is the number of microseconds.
   */
  long getTimestamp();

private:
  std::string timestamp; // Going to represent timestamp as a string
  std::string protocol;
  std::string sourceIp;
  std::string sourcePort;
  std::string destIp;
  std::string destPort;

};

long ISOTItem::getTimestamp()
{

  int pos = this->timestamp.find('.');
  std::string datetime     = timestamp.substr(0, pos);
  std::string microseconds = timestamp.substr(pos + 1, 
                                              this->timestamp.length()-1);
  std::istringstream ss(datetime);
  std::tm t = {};
  ss >> std::get_time(&t, "%Y-%m-%dT%H:%M:S");
  long ms = 1000000 * std::mktime(&t);
  ms = ms + boost::lexical_cast<int>(microseconds);
  return 0;
}

class ISOT {
public:
  /**
   * Constructor. Parses the data from each row of the groundtruth csv.
   * \param filename A path to the ISOT groundtruth csv file.
   */
  ISOT(std::string filename);
  ~ISOT() {};

  std::string packet_event_type(PacketInfo packetInfo) {return "";};
  bool is_danger(PacketInfo packetInfo) {return false;};
private:
  // Mapping from timestamp as a string to the ISOT item
  std::map<std::string, ISOTItem> time2item;

};

ISOT::ISOT(std::string filename)
{
  std::ifstream csv(filename);

  if (!csv.is_open()) std::cout << "Error opening file." << std::endl;

  std::string dateTime;
  std::string protocol;
  std::string sourceIp;
  std::string sourcePort;
  std::string destIp;
  std::string destPort;
  std::string size;
  std::string fragmented;
  std::string seqNumber;
  std::string ackNumber;
  std::string flags;
  std::string classification;

  // The first line should be a list of column names
  std::string temp;
  std::getline(csv, temp, '\n'); 

  while (csv.good())
  {
    std::getline(csv, dateTime, ',');
    std::getline(csv, protocol, ',');
    std::getline(csv, sourceIp, ',');
    std::getline(csv, sourcePort, ',');
    std::getline(csv, destIp, ',');
    std::getline(csv, destPort, ',');
    std::getline(csv, size, ',');
    std::getline(csv, fragmented, ',');
    std::getline(csv, seqNumber, ',');
    std::getline(csv, ackNumber, ',');
    std::getline(csv, flags, ',');
    std::getline(csv, classification, '\n');

  }

}


} // end parallel_pcap namespace

#endif

