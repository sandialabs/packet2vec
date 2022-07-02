#ifndef PARALLELPCAP_PACKET_HPP
#define PARALLELPCAP_PACKET_HPP

#include <iostream>
#include <boost/serialization/vector.hpp>
#include <ParallelPcap/ByteManipulations.hpp>

namespace parallel_pcap {

class PacketHeader
{
private:
  uint32_t timestampSeconds = 0; ///>timestamp in seconds since epoch
  uint32_t timestampUseconds = 0; ///> microseconds (or nanoseconds)
  uint32_t includedLength = 0; ///> how much of the packet is included in bytes
  uint32_t originalLength = 0; ///> how long the packet was originally

  friend class boost::serialization::access;

  template<class Archive>
  void serialize(Archive &ar, const unsigned int version) {
    ar &timestampSeconds &timestampUseconds &includedLength &originalLength;
  }

public:
  PacketHeader() {}

  PacketHeader(uint32_t timestampSeconds,
               uint32_t timestampUseconds,
               uint32_t includedLength,
               uint32_t originalLength) 
  {
    this->timestampSeconds = timestampSeconds; 
    this->timestampUseconds = timestampUseconds;
    this->includedLength = includedLength;
    this->originalLength = originalLength;
  }
      
  inline uint32_t getTimestampSeconds() const { return timestampSeconds; }
  inline uint32_t getTimestampUSeconds() const { return timestampUseconds; }
  inline uint32_t getIncludedLength() const { return includedLength; }
  inline uint32_t getOriginalLength() const { return originalLength; } 
};

class Packet
{
private:

  /// The packet data (non-header).  This data is owned by the Pcap class.
  /// we don't copy the data over or delete it in this class.
  std::vector<unsigned char> data;

  /// Converts unsigned char array to uint32
  AbstractUint32Transformer* transform; 

  /// The packet header info.
  PacketHeader header;
  
  friend class boost::serialization::access;

  template<class Archive>
  void serialize(Archive &ar, const unsigned int version) {
    ar &header &data;
  }

public:
  
  Packet() {} 
  Packet(unsigned char const* array, AbstractUint32Transformer* transform);
  ~Packet();

  /**
   * Gets the unsigned char at position i in the packet data.  If 
   * an element is requested that is beyond the end of the array, an
   * std::out_of_range exception is thrown.
   * \param i The position of the element.
   * \return Returns the element at position i.
   */
  unsigned char getElement(size_t i) const {
    if (i < header.getIncludedLength()) {
      return data[i];
    }
    throw std::out_of_range("Tried to get data element in packet that is out"
      "of range");
  }

  /**
   * Returns the header associated with this packet.
   */
  PacketHeader getHeader() const {
    return header;
  }

  std::vector<unsigned char> getData() const {
    return data;
  }

  uint32_t getTimestampSeconds() const { 
    return header.getTimestampSeconds(); 
  }
  
  uint32_t getTimestampUSeconds() const { 
    return header.getTimestampUSeconds(); 
  }

  uint32_t getIncludedLength() const { 
    return header.getIncludedLength(); 
  }

  uint32_t getOriginalLength() const { 
    return header.getOriginalLength(); 
  } 

};

Packet::Packet(unsigned char const* array, AbstractUint32Transformer* transform)
{
  this->transform = transform;
  uint32_t timestampSeconds = (*transform)(array);
  array = array + 4;
  uint32_t timestampUseconds = (*transform)(array);
  array = array + 4;
  uint32_t includedLength = (*transform)(array);
  array = array + 4;
  uint32_t originalLength = (*transform)(array);
  array = array + 4;

  header = PacketHeader(timestampSeconds,
                        timestampUseconds,
                        includedLength,
                        originalLength);

  // Store in vector as opposed to char array for seralization
  for (int i = 0; i < includedLength; i++) 
    this->data.push_back(array[i]);

}

Packet::~Packet() { }

}

#endif
