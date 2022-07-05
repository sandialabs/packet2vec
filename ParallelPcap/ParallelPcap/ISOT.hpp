#ifndef ISOT_HPP
#define ISOT_HPP

#include <map>
#include <fstream>
#include <string>
#include <sstream>
#include <locale>
#include <iomanip>
#include <ctime>

#include <boost/lexical_cast.hpp>

#include <ParallelPcap/PacketInfo.hpp>
#include <ParallelPcap/Time.hpp>

namespace parallel_pcap {

/**
 * Runtime error exception for ISOT processing.
 */
class ISOTException : public std::runtime_error {
public:
  ISOTException(char const * message) : std::runtime_error(message) { }
  ISOTException(std::string message) : std::runtime_error(message) { }
};

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
  ISOTItem( std::string classification,
            std::string timestamp, 
            std::string protocol,
            std::string sourceIp,
            unsigned int sourcePort,
            std::string destIp,
            unsigned int destPort) 
  : classification(classification), protocol(protocol),
    sourceIp(sourceIp), sourcePort(sourcePort),
    destIp(destIp), destPort(destPort)
  {
    this->timestamp = calcTimestamp(timestamp); 
  }

  ISOTItem() : classification(""), protocol(""),
    sourceIp(""), sourcePort(0),
    destIp(""), destPort(0), timestamp(0)
  {}

  ~ISOTItem() {}

  std::string getClassification() const { return this->classification; }
  unsigned long getTimestamp() const { return this->timestamp; }
  std::string getProtocol() const { return this->protocol; }
  std::string getSourceIp() const { return this->sourceIp; }
  unsigned int getSourcePort() const { return this->sourcePort; }
  std::string getDestIp() const { return this->destIp; }
  unsigned int getDestPort() const { return this->destPort; }


  /**
   * Converts the original timestamp, e.g. 2016-12-08T20:40:49.538528Z,
   * into a long that is the number of microseconds.
   */
  unsigned long calcTimestamp(std::string const&) const;

private:


  std::string classification;
  long timestamp; // A combo of seconds and microseconds
  std::string protocol;
  std::string sourceIp;
  unsigned int sourcePort;
  std::string destIp;
  unsigned int destPort;

};


unsigned long ISOTItem::calcTimestamp(std::string const& timestamp) const
{

  std::cout << "timestamp " << timestamp << std::endl;
  int pos = timestamp.find('.');
  std::string datetime     = timestamp.substr(0, pos);
  std::string microseconds = timestamp.substr(pos + 1, 6);
  std::string format = "%Y-%m-%dT%H:%M:%S";
  unsigned long seconds = utc_seconds_from_datetime(datetime, format);
  std::cout << "microseconds " << microseconds << std::endl;
  unsigned long ms = seconds * 1000000 + 
    boost::lexical_cast<unsigned long>(microseconds);

  return ms;
}

class ISOT {
public:
  /**
   * Constructor. Parses the data from each row of the groundtruth csv.
   * \param filename A path to the ISOT groundtruth csv file.
   */
  ISOT(std::string filename);
  ~ISOT() {};

  std::string packet_event_type(PacketInfo const& packetInfo) const; 
  bool is_danger(PacketInfo const& packetInfo) const; 
private:
  
  unsigned long combinedTime(PacketInfo const& packetInfo) const;
  
  // Mapping from timestamp as a string to the ISOT item
  std::map<long, ISOTItem> time2item;

};

unsigned long ISOT::combinedTime(PacketInfo const& packetInfo) const
{
  unsigned long micro_since_epoch = static_cast<long>(
    packetInfo.getSeconds()) *1000000 
    + static_cast<long>(packetInfo.getUSeconds());
  return micro_since_epoch;
}

std::string ISOT::packet_event_type(PacketInfo const& packetInfo) const
{
  unsigned long micro_since_epoch = combinedTime(packetInfo);
  auto search = time2item.find(micro_since_epoch);
  if (search != time2item.end()) {
    ISOTItem const& item = time2item.at(micro_since_epoch);
    return item.getClassification();
  } else {
    std::cout << "Couldn't find item for time " <<micro_since_epoch <<std::endl;
    return "";
  }
}

bool ISOT::is_danger(PacketInfo const& packetInfo) const 
{
  std::string type = packet_event_type(packetInfo);
  if (type == "malicious")
  {
    return true;
  } else if (type == "benign")
  {
    return false;
  } else
  {
    throw ISOTException("Unknown ISOT event type: " + type);
  }
}

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
  std::cout << "first line " << temp << std::endl;

  int i = 1;
  while (csv.good() && !csv.eof())
  {
    std::cout << "i " << i << std::endl;
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

    bool the_end = false;
    if (dateTime.length() < 1) the_end = true;
    if (protocol.length() < 1) the_end = true;
    if (sourceIp.length() < 1) the_end = true;
    if (sourcePort.length() < 1) the_end = true;
    if (destIp.length() < 1) the_end = true;
    if (destPort.length() < 1) the_end = true;
    if (size.length() < 1) the_end = true;
    if (fragmented.length() < 1) the_end = true;
    if (seqNumber.length() < 1) the_end = true;
    if (ackNumber.length() < 1) the_end = true;
    if (flags.length() < 1) the_end = true;
    if (classification.length() < 1) the_end = true;

    if (the_end) continue;
      

    std::cout << "dateTime " << dateTime << std::endl;
    std::cout << "classification " << classification << std::endl;
    std::cout << "sourcePort " << sourcePort << std::endl;
    std::cout << "destPort " << destPort << std::endl;

    std::cout << "Creating item " << std::endl;
    ISOTItem item(classification,
                  dateTime, 
                  protocol,
                  sourceIp,
                  boost::lexical_cast<unsigned int>(sourcePort),
                  destIp,
                  boost::lexical_cast<unsigned int>(destPort));

    unsigned long timestamp = item.getTimestamp();

    if (time2item.count(timestamp) > 0)
    {
      std::cout << "blah " << std::endl;
      throw ISOTException("Found a row in the label file that has a time"
        "stamp that has been seen before: " + 
        boost::lexical_cast<std::string>(timestamp));     
    } else
    {
      time2item[timestamp] = item;
    }
    i++;
  }
  csv.close();
  std::cout << "Done processing file." << std::endl;
}


} // end parallel_pcap namespace

#endif

