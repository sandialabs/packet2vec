#ifndef PARALLEL_PCAP_HPP
#define PARALLEL_PCAP_HPP

#include <string>
#include <thread>
#include <iostream>
#include <fstream>
#include <chrono>
#include <ParallelPcap/ByteManipulations.hpp>
#include <ParallelPcap/Util.hpp>
#include <ParallelPcap/Packet.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/python.hpp>
#include <boost/serialization/vector.hpp>
#include <mutex>
#include <vector>

namespace parallel_pcap {

/**
 * Callable object that is used to ngram a string.
 */
class NgramOperator
{
private:
  size_t n;
public:
  NgramOperator(size_t n) {
    this->n = n;
  }

  void operator()(Packet const& packet, 
             std::vector<std::string> & vec)
             const
  {
    // Start i at 38 to remove ip addresses and ports from the packet ngrammed
    // data
    for(size_t i = 38; i < packet.getIncludedLength() - n + 1; i++)
    {
      char ngram[n+1];
      ngram[n] = '\0';
      for(size_t j = 0; j < n; j++) {
        ngram[j] = packet.getElement(i + j);
      }
      std::string s(ngram);
      vec.push_back(s);
    }
  }
};

/**
 * The exception type generate by the Pcap class.
 */
class PcapException : public std::runtime_error {
public:
  PcapException(char const* message) : std::runtime_error(message) {}
  PcapException(std::string message) : std::runtime_error(message) {}
};

namespace details {

/**
 * Checks a sequence of indices into packet data to make sure that they
 * are all packets and that they are continguous from the first one.
 * \param candidates A list of indices into packetData.
 * \param transformUnsigned32 Transforms the bytes into an unsigned 32-bit
 *         integer.
 * \param packetData An unsigned char array that has the packet data.
 */
void checkSequence(std::vector<uint64_t> const& candidates,
                   AbstractUint32Transformer* transformUnsigned32,
                   unsigned char* packetData)
{
  auto it = candidates.begin();
  uint64_t index = *it;
  uint32_t packetLen = (*transformUnsigned32)(&packetData[index+8]);
  it++;
  while (it != candidates.end())
  {
    uint64_t expectedIndex =  index + (*transformUnsigned32)
                                    (&packetData[index+8]) + 16;
    uint64_t foundIndex = *it;
    if (expectedIndex != foundIndex) {
      std::string message = "Found multiple candidates.";
      throw PcapException(message);
    }
    it++;
    index = foundIndex;
  }
}

/**
 * Go through the first snaplen part of packetData, and see which of the 
 * the bytes could possibly be the start of a packet.  
 */
void createCandidates(std::vector<uint64_t>& candidates, 
                      size_t numDesired,
                      uint32_t beg,
                      uint32_t end,
                      uint32_t snaplen,
                      AbstractUint32Transformer* transformUnsigned32,
                      unsigned char* packetData,
                      uint32_t firstTimestamp,
                      size_t threadId)
{
 
  uint64_t end_of_packet = snaplen + beg;
  if (end_of_packet > end) {
    end_of_packet = end;
  }
  for (uint64_t i = beg; i < end_of_packet; i++)
  {
    uint32_t timestamp = (*transformUnsigned32)(&packetData[i]);
    if (timestamp >= firstTimestamp) {
      candidates.push_back(i); 
    }
  }

  for(auto it = candidates.begin(); it != candidates.end(); )
  {
    uint32_t previousTime = firstTimestamp; 
    uint64_t index = *it;
    int j = 0;
    bool success = true;
    while (j < numDesired && success) {
      uint32_t currentTime = (*transformUnsigned32)(&packetData[index]);

      if (currentTime >= previousTime) {
        // Get the candidate packetLen
        uint32_t packetLen = (*transformUnsigned32)
                              (&packetData[index+8]);
                                

        if (packetLen <= snaplen) {
          index = index + 4*sizeof(uint32_t) + packetLen; 
          if (index >= end) {
            success = false;
          }
        } else {
          success = false;
        }

        j++;
        previousTime = currentTime;
      } else {
        success = false;
      } 
    }
    if (success) {
      ++it;
    } else {
      it = candidates.erase(it);
    }
  }

  if (candidates.size() < 1) {
    std::cout << "Couldn't find data in the associated pcap file. " << std::endl;
    std::string message = "Trying to find the start of a packet in thread " +
      boost::lexical_cast<std::string>(threadId) + "'s data range was " + 
      "unsucessful.  Didn't find any candidates.";
    throw PcapException(message);
  }
}

} //end namespace details

class Pcap
{
private:
  //size_t numThreads; 
  uint64_t numBytes;

  // Pcap header fields
  uint32_t magicNumber;
  uint16_t majorVersion;
  uint16_t minorVersion;
  int32_t  timeZoneCorrection;
  uint32_t sigfigs;
  uint32_t snaplen;
  uint32_t network; 

  AbstractInt32Transformer* transformSigned32;
  AbstractUint32Transformer* transformUnsigned32;
  AbstractUint16Transformer* transformUnsigned16;

  unsigned char* data = 0;
  std::vector<Packet> packets;

  bool swapped;

  // Serialize
  friend class boost::serialization::access;
  template<class Archive>
  void serialize(Archive &ar, const unsigned int version) {
    ar &packets &numBytes &magicNumber &majorVersion &minorVersion &timeZoneCorrection &sigfigs &snaplen &network;
  }
public:
  // Offset in bytes to pcap header fields
  static const uint64_t MAGIC_NUMBER_POS  = 0; ///> Offset to magic number
  static const uint64_t VERSION_MAJOR_POS = 4; ///> Offset to major version #
  static const uint64_t VERSION_MINOR_POS = 6; ///> OFfset to minor version #
  static const uint64_t THISZONE_POS      = 8; ///> 
  static const uint64_t SIGFIGS_POS       = 12;
  static const uint64_t SNAPLEN_POS       = 16; 
  static const uint64_t NETWORK_POS       = 20;
  static const uint64_t PACKET_DATA_POS   = 24; ///> Offset to packet data
  //static const uint64_t PACKET_DATA_POS   = 38; // Exclude ip addresses from data

  Pcap(std::string const& filename);
  //Pcap(std::string const& filename, size_t numThreads);
  Pcap() { }
  ~Pcap();

  size_t getNumPackets() const { return packets.size(); }

  template<typename Operator, typename OutputType>
  void applyOperator(Operator op, 
                     std::vector<OutputType>& vec) const;

  void applyNgramOperator(size_t ngramSize, 
                          std::vector<std::vector<std::string>>& vec) const;

  /**
   * Gets the packet header of the ith packet.
   * \param i The index of the packet.
   */
  PacketHeader getPacketHeader(size_t i) const {
    return packets[i].getHeader();
  }
  
  std::vector<unsigned char> getPacket(size_t i) const {
    return packets[i].getData();
  }

  void setRestored(bool restored);
private:
  bool restored;
  void readFile(std::string const& filename);
  void readHeader(unsigned char* data);
  void readPackets(unsigned char* data);
};

inline void Pcap::setRestored(bool restored)
{
  this->restored = restored;
}

inline Pcap::Pcap(std::string const& filename)//, size_t numThreads) 
{
  this->restored = false;
  std::cout << "Processing pcap file " << filename << std::endl;
  readFile(filename);
}

inline Pcap::~Pcap()
{
  // Is this solution the best?
  if (!this->restored) {
    delete transformSigned32;
    delete transformUnsigned32;
    delete transformUnsigned16;
    delete[] data;
  }
}

inline void Pcap::readFile(std::string const& filename)
{
  std::ifstream myfile;

  // Open the file in binary at the end of the file.
  myfile.open(filename, std::ios::binary | std::ios::ate);


  if (myfile.is_open()) 
  {
    // get the number of bytes in the file
    numBytes = myfile.tellg();
    
    // go back to the beginning of the file
    myfile.seekg(0, std::ios::beg);

    // load the data into memory
    data = new unsigned char[numBytes];
    myfile.read(reinterpret_cast<char*>(data), numBytes);
    myfile.close();

  } else {
    throw PcapException("Could not open file " + filename);
  }

  readHeader(data);
  readPackets(data);
  
  
}

inline void Pcap::readHeader(unsigned char* data)
{
#ifdef DEBUG
  std::cout << "Reading header" << std::endl;
#endif
  // this->data should have been populated by now.
  
  // Looking at the magic number to determine which byte converter to use.
  unsigned char* dataPtr = data;
  if (data[0] == 0xa1 && data[1] == 0xb2 && data[2] == 0xc3 && data[3] == 0xd4)
  {
    transformSigned32 = new Int32Transformer();
    transformUnsigned32 = new Uint32Transformer();
    transformUnsigned16 = new Uint16Transformer(); 
    swapped = false;
  } else
  if (data[0] == 0xd4 && data[1] == 0xc3 && data[2] == 0xb2 && data[3] == 0xa1)
  {
    transformSigned32 = new Int32TransformerSwapped();
    transformUnsigned32 = new Uint32TransformerSwapped();
    transformUnsigned16 = new Uint16TransformerSwapped(); 
    swapped = true;
  } else {
    throw PcapException("Tried to get the magic number but it wasn't"
      "0xa1b2c3d4 or 0xd4c3b2a1");
  }

  magicNumber = (*transformUnsigned32)(dataPtr);
  dataPtr += 4;
  majorVersion = (*transformUnsigned16)(dataPtr);
  dataPtr += 2;
  minorVersion = (*transformUnsigned16)(dataPtr);
  dataPtr += 2;
  timeZoneCorrection = (*transformSigned32)(dataPtr);
  dataPtr += 4;
  sigfigs = (*transformUnsigned32)(dataPtr);
  dataPtr += 4;
  snaplen = (*transformUnsigned32)(dataPtr);
  dataPtr += 4;
  network = (*transformUnsigned32)(dataPtr); 
  dataPtr += 4;

}

inline void Pcap::readPackets(unsigned char* data)
{
#ifdef DEBUG
  std::cout << "Reading packets" << std::endl;
#endif
  unsigned char* packetData = data + PACKET_DATA_POS;
  uint64_t numPacketBytes = numBytes - PACKET_DATA_POS;

  // Getting the first timestamp of the first packet.
  uint32_t firstTimestamp = (*transformUnsigned32)(packetData);

  std::mutex lock;

  auto parseFile = [packetData, numPacketBytes, this,
                    firstTimestamp, &lock]
                   (size_t threadId, size_t mythreadCount)
  {
    uint64_t beg = getBeginIndex(numPacketBytes, threadId, mythreadCount);
    uint64_t end = getEndIndex(numPacketBytes, threadId, mythreadCount);
#ifdef DEBUG
    std::cout << "threadId " << threadId << " mythreadCount " 
              << mythreadCount << " numPacketBytes "
              << numPacketBytes << " beg " << beg 
              << " end " << end << std::endl;
#endif

    // We go through the first part of the data and find candidates
    // of what we think could be timestamps (i.e. the begining of a
    // packet).  We do this by assuming that all timestamps will be
    // greater than firstTimestamp
    std::vector<uint64_t> candidates; 

    // number of times in a row the guess has to be correct before
    // we consider that initial guess was correct.
    size_t numDesired = 10;

    // We know the largest a packet can be is snaplen long.  So we find
    // candidates over that range.  However, for now we throw an exception
    // if our range over the data is smaller than snaplen
    //if ( end - beg < snaplen) {
    //  std::string message = "Pcap::readPackets(): in thread looking at data"
    //    "beg-end < snaplen, which we don't handle currently.  Implement a"
    //    " better approach or reduce the number of threads. " 
    //    "Beg: " + boost::lexical_cast<std::string>(beg) +
    //    " End: " + boost::lexical_cast<std::string>(end) +
    //    " snaplen: " + boost::lexical_cast<std::string>(snaplen);
    //  throw PcapException(message);
    //}

    try {
      // Go through the first snaplen part of packetData, and see which of the 
      // the bytes could possibly be the start of a packet.  
      details::createCandidates(candidates, numDesired, beg, end, snaplen, 
                        this->transformUnsigned32, packetData,
                        firstTimestamp, threadId);

      // Check to make sure the first candidate explains the rest and that we
      // don't have multiple candidates to choose from.  Throws an exception
      // if the sequence is off.
      details::checkSequence(candidates, this->transformUnsigned32, packetData);

      // Process all the packets
      uint64_t index = *(candidates.begin());
      while (index < end) {
    
        lock.lock();
        packets.push_back(Packet(&packetData[index],this->transformUnsigned32));
        lock.unlock();
        uint32_t lengthPacket = (*this->transformUnsigned32)
                                (&packetData[index + 8]);
        index = index + lengthPacket + 16;
      }
    } catch (PcapException e) {
      std::cout << "Error with file." << std::endl;
    }
    
  };

  
  //size_t mythreadCount = globalNumThreads;
  // Force mythreadCount = 1 
  // Having more threads didn't seem to speed up anything.  Just use one thread
  size_t mythreadCount = 1;
  
  // Reducing thread count if we have too many requested for the size of the 
  // problem
  if (numPacketBytes / mythreadCount < snaplen) {
    mythreadCount = numPacketBytes / (snaplen + 1);
  
  }
  if (mythreadCount < 1) mythreadCount = 1;
  std::thread* threads = new std::thread[mythreadCount];
  for(size_t i = 0; i < mythreadCount; i++) {
    threads[i] = std::thread(parseFile, i, mythreadCount);
  }

  for(size_t i = 0; i < mythreadCount; i++) {
    threads[i].join();
  }


  delete[] threads;

}

void 
Pcap::applyNgramOperator(size_t ngramSize, 
                         std::vector<std::vector<std::string>>& vec) const 
                         
{
  NgramOperator op = NgramOperator(ngramSize);
  applyOperator<NgramOperator, std::vector<std::string>>(op, vec);
}

template<typename Operator, typename OutputType>
void
Pcap::applyOperator(Operator op, 
                    std::vector<OutputType>& vec) const
{
  size_t mythreadCount = globalNumThreads;

  if (vec.size() < this->getNumPackets()) {
    vec.resize(this->getNumPackets());
  }

  auto applyFunction = [this, &vec, mythreadCount, op](size_t threadId)
  {
    auto t1 = std::chrono::high_resolution_clock::now();
    uint64_t beg = getBeginIndex(this->getNumPackets(), threadId, 
                                 mythreadCount);
    uint64_t end = getEndIndex(this->getNumPackets(), threadId, 
                                 mythreadCount);

    for(uint64_t i = beg; i < end; i++) 
    {
      op( packets[i], vec[i] ); 
    }
    auto t2 = std::chrono::high_resolution_clock::now();
  };

  std::thread* threads = new std::thread[mythreadCount];
  for(size_t i = 0; i < mythreadCount; i++) {
    threads[i] = std::thread(applyFunction, i);
  }

  for(size_t i = 0; i < mythreadCount; i++) {
    threads[i].join();
  }

  delete[] threads;
  
}

}

#endif
