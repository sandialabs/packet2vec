#ifndef PACKET_2_VEC_HPP
#define PACKET_2_VEC_HPP

#include <ParallelPcap/PacketInfo.hpp>
#include <ParallelPcap/DARPA2009.hpp>
#include <ParallelPcap/Pcap.hpp>
#include <ParallelPcap/Util.hpp>
#include <stdexcept>
#include <iostream>
#include <vector>
#include <chrono>
#include <iostream>

// Boost
#include <boost/python.hpp>
#include <boost/python/numpy.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/filesystem.hpp>

namespace ba = boost::archive;
namespace bf = boost::filesystem;
namespace np = boost::python::numpy;
namespace p = boost::python;

namespace parallel_pcap {

template <typename Labeler>
class Packet2Vec
{

private:
  Labeler labeler;

  np::ndarray X;
  np::ndarray y;
  np::ndarray embeddings;
  Messenger msg;

  void assignLabel(Pcap const &pcap, p::ssize_t i);
  
  // Figure these out
  static np::ndarray convertToVector(np::ndarray &embeddings, 
                                      std::vector<size_t>& ngrammedPacket);

public:
  /**
   * Constructor. Initializes the member variables required to generate X and Y matrices
   * \param embeddings A numpy array that has the embeddings.
   * \param labelfile The file with the label info.
   * \bool debug Whether debugging is turned on.
   */
  Packet2Vec(np::ndarray &_embeddings, std::string labelfile, bool debug) :
    labeler(Labeler(labelfile)), 
    X(np::array(p::list())), 
    y(np::array(p::list())), 
    embeddings(_embeddings), msg(debug) { }

  Packet2Vec(std::string labelfile, bool debug) : 
    labeler(Labeler(labelfile)),
    X(np::array(p::list())),
    y(np::array(p::list())),
    embeddings(np::array(p::list())), msg(debug) { }

  ~Packet2Vec() { }

  /**
   * Returns the constructed X ndarray.  Each row has the features for an
   * individual packet.
   * \param token_path This is the path to the file with the vector of vector 
   *                   of ints.
   * \param Returns an numpy ndarray with the X matrix.
   */
  np::ndarray generateX(std::string token_path);

  /**
   * Returns the constructed X ndarray containing integer tokens.
   * Each row has the tokens for an individual packet.
   * \param token_path This is the path to the file with the vector of vector 
   *                   of ints.
   * \param Returns an numpy ndarray with the feature vector.
   */

  np::ndarray generateXTokens(std::string token_path);

  /**
   * Returns the constructed X ndarray.  Each row has the features for an
   * individual packet. This static method is used to construct the ndarray
   * during testing.
   * \param embeddings A numpy array that has the embeddings.
   * \param tokens A python list of tokens to translate to embeddings.
   * \param Returns an numpy ndarray with the feature vector.
   */
  static np::ndarray translateX(np::ndarray &embeddings, 
                                std::vector<std::vector<size_t>> &tokens, 
                                bool debug);

  /**
   * Returns the constructed y ndarray.  It reads the pcap object file.  The 
   * object is found in Pcap.hpp. Static method used to construct labels during
   * testing.
   * \param pcapFile The path location of the the pcap object file.
   */
  static np::ndarray translateY(Pcap const &pcap, Labeler &labeler, bool debug); 

  /**
   * Returns the constructed y ndarray.  It reads the pcap object file.  The 
   * object is found in Pcap.hpp.
   * \param pcapFile The path location of the pcap object file.
   */
  np::ndarray generateY(std::string pcapFile);

  /**
   * Returns a list of attacks present in a given pcap file.
   * \param pcapFile The path location of the pcap object file.
   */
  p::list attacks(std::string pcapFile);
  
};

template <typename Labeler>                 
np::ndarray Packet2Vec<Labeler>::convertToVector(
  np::ndarray &embeddings, 
  std::vector<size_t>& ngrammedPacket
) {
  // Ngrammed packet now each integer vector?
  int shape = embeddings.shape(1);

  // Allocate allwordvec
  np::ndarray allwordvec = np::zeros(p::make_tuple(shape), 
                                     np::dtype::get_builtin<float>());

  // Get float pointers to treat ndarrays as regular arrays
  float *allwordvec_ptr = reinterpret_cast<float *>(allwordvec.get_data());
  float *embeddings_ptr = reinterpret_cast<float*>(embeddings.get_data());

  // Total number of words
  int numwords = ngrammedPacket.size();

  // Iterate over all words and add their vectors
  for (int i = 0; i < numwords; i++)
  {
    int position = ngrammedPacket[i];
    int start = shape * position;
    for (int j = 0; j < shape; j++)
    {
      allwordvec_ptr[j] = allwordvec_ptr[j] + embeddings_ptr[start + j];
    }
  }

  // Divide vectors elementwise by number of words
  for (int i = 0; i < shape; i++)
  {
    allwordvec_ptr[i] = allwordvec_ptr[i] / numwords;
  }

  return allwordvec;
}

template <typename Labeler>                 
void Packet2Vec<Labeler>::assignLabel(Pcap const &pcap, p::ssize_t i)
{
  PacketHeader pkthdr = pcap.getPacketHeader(i);
  std::vector<unsigned char> pkt = pcap.getPacket(i);

  // Refactor packet info to accomodate char vector instead
  PacketInfo packetInfo = PacketInfo::parse_packet(pkthdr.getTimestampSeconds(),
                                                   pkt);

  if (this->labeler.is_danger(packetInfo)) {
    this->y[i] = 1;
  } else {
    this->y[i] = 0;
  }
}

template <typename Labeler>
np::ndarray Packet2Vec<Labeler>::generateX(std::string token_path)
{
  std::vector<std::vector<size_t>> packets;
  {
    std::ifstream ifs(token_path);
    ba::text_iarchive ar(ifs);

    ar >> packets;
  }

  // Number of packets should be the size of the 
  // outside token vector
  int numPackets = packets.size();

  // Initialize vectors
  this->X = np::zeros(p::make_tuple(numPackets, this->embeddings.shape(1)), 
                      np::dtype::get_builtin<float>());
  std::string message = "Initialized X - Shape: (" + std::to_string(this->X.shape(0))
                  + ", " + std::to_string(this->X.shape(1)) + ")"; 
  this->msg.printMessage(message);

  this->msg.printMessage("Converting Packets to Vectors");

  for (p::ssize_t i = 0; i < numPackets; i++)
  {
    if (i % 50000 == 0) { 
      message = std::to_string(i) + " of " + std::to_string(numPackets) + " converted";
      this->msg.printMessage(message);
    }

    // Figure this out later.
    // get i'th ngrammed packet - now each inside integer vector?
    std::vector<size_t> ngrammedPacket = packets[i];

    // vstack the vector onto X
    this->X[i] = this->convertToVector(this->embeddings, ngrammedPacket);

  }
  this->msg.printMessage("Finished Loop");

  return this->X;
}

template <typename Labeler>
np::ndarray Packet2Vec<Labeler>::translateX(
  np::ndarray &embeddings, 
  std::vector<std::vector<size_t>> &packets,
  bool debug) 
{
  Messenger msg(debug);
  // Number of packets should be the size of the 
  // outside token vector
  int numPackets = packets.size();

  // Initialize vectors
  auto t1 = std::chrono::high_resolution_clock::now();
  np::ndarray X = np::zeros(p::make_tuple(numPackets, embeddings.shape(1)), 
                      np::dtype::get_builtin<float>());
  std::string message = "Initialized X - Shape: (" + std::to_string(X.shape(0))
                  + ", " + std::to_string(X.shape(1)) + ")"; 
  msg.printMessage(message);
  auto t2 = std::chrono::high_resolution_clock::now();
  msg.printDuration("Packet2Vec::translateX: Time to create X with zeros: ", 
                t1, t2);

  msg.printMessage("Converting Packets to Vectors");

  //TODO could be parallelized
  t1 = std::chrono::high_resolution_clock::now();
  for (p::ssize_t i = 0; i < numPackets; i++)
  {
    if (i % 50000 == 0) { 
      message = std::to_string(i) + " of " + std::to_string(numPackets) + " converted";
      msg.printMessage(message);
    }

    // Figure this out later.
    // get i'th ngrammed packet - now each inside integer vector?
    std::vector<size_t> ngrammedPacket = packets[i];

    // vstack the vector onto X
    X[i] = Packet2Vec::convertToVector(embeddings, ngrammedPacket);

  }
  t2 = std::chrono::high_resolution_clock::now();
  msg.printDuration("Packet2Vec::translateX: Time for for loop: ", t1, t2);

  return X;
}

template <typename Labeler>
np::ndarray Packet2Vec<Labeler>::generateXTokens(std::string token_path) 
{
  std::vector<std::vector<size_t>> packets;
  {
    std::ifstream ifs(token_path);
    ba::text_iarchive ar(ifs);

    ar >> packets;
  }

  // Number of packets should be the size of the 
  // outside token vector
  int numPackets = packets.size();

  // Find the largest packet and zero-pad the other items
  // Is this ok? Zero-padding
  auto find_longest = [](const std::vector<size_t> &A, const std::vector<size_t> &B) 
  {
    return A.size() < B.size();
  };

  int largest_size = std::max_element(packets.begin(), packets.end(), find_longest)->size();

  // Initialize vectors
  this->X = np::zeros(p::make_tuple(numPackets, largest_size), 
                      np::dtype::get_builtin<int>());
  std::string message = "Initialized X - Shape: (" + std::to_string(this->X.shape(0))
                  + ", " + std::to_string(this->X.shape(1)) + ")"; 
  this->msg.printMessage(message);

  this->msg.printMessage("Converting Packets to Vectors");
  for (p::ssize_t i = 0; i < numPackets; i++)
  {
    if (i % 50000 == 0) { 
      message = std::to_string(i) + " of " + std::to_string(numPackets) + " moved";
      this->msg.printMessage(message);
    }

    std::vector<size_t> ngrammedPacket = packets[i];

    np::ndarray tokenvec = np::zeros(p::make_tuple(largest_size), 
                                     np::dtype::get_builtin<int>());

    for (p::ssize_t j = 0; j < ngrammedPacket.size(); ++j)
    {
      tokenvec[j] = ngrammedPacket[j];
    }

    this->X[i] = tokenvec;
  }
  this->msg.printMessage("Finished Loop");

  return this->X;
}

template <typename Labeler>
np::ndarray Packet2Vec<Labeler>::generateY(std::string pcapFile)
{
  // Restore pcap from file
  Pcap restoredPcap;
  {
    std::ifstream ifs(pcapFile);
    ba::text_iarchive ar(ifs);

    ar >> restoredPcap;
    restoredPcap.setRestored(true);
  }

  int numPackets = restoredPcap.getNumPackets();

  this->y = np::zeros(p::make_tuple(numPackets), 
                      np::dtype::get_builtin<int>());
  std::string message = "Initialized y - Shape: (" + std::to_string(this->y.shape(0))
                        + ")";
  this->msg.printMessage(message);

  // some loop to assign the labels
  for (p::ssize_t i = 0; i < numPackets; i++)
    this->assignLabel(restoredPcap, i);
  

  return this->y;
}

template <typename Labeler>                 
np::ndarray Packet2Vec<Labeler>::translateY(Pcap const &pcap, Labeler &labeler, bool debug) 
{
  Messenger msg(debug);
  int numPackets = pcap.getNumPackets();

  np::ndarray y = np::zeros(p::make_tuple(numPackets),
                            np::dtype::get_builtin<float>());
  std::string message = "Initialized y - Shape: (" + std::to_string(y.shape(0))
                        + ")";
  msg.printMessage(message);
  
  for (p::ssize_t i = 0; i < numPackets; i++) {
    PacketHeader pkthdr = pcap.getPacketHeader(i);
    std::vector<unsigned char> pkt = pcap.getPacket(i);

    // Refactor packet info to accomodate char vector instead
    PacketInfo packetInfo=PacketInfo::parse_packet(pkthdr.getTimestampSeconds(),
                                                    pkt);

    if (labeler.is_danger(packetInfo)) {
      y[i] = 1;
    } else {
      y[i] = 0;
    }
  }

  return y;
}

template <typename Labeler>                 
p::list Packet2Vec<Labeler>::attacks(std::string pcapFile) 
{
  // Restore pcap from file
  Pcap restoredPcap;
  {
    std::ifstream ifs(pcapFile);
    ba::text_iarchive ar(ifs);

    ar >> restoredPcap;
    restoredPcap.setRestored(true);
  }

  int numPackets = restoredPcap.getNumPackets();
  p::list l;

  // Generate the packet event types
  for (p::ssize_t i = 0; i < numPackets; i++) {
    PacketHeader pkthdr = restoredPcap.getPacketHeader(i);
    std::vector<unsigned char> pkt = restoredPcap.getPacket(i);

    // Refactor packet info to accomodate char vector instead
    PacketInfo packetInfo = PacketInfo::parse_packet(pkthdr.getTimestampSeconds(),
                                                    pkt);

    l.append(this->labeler.packet_event_type(packetInfo));
  }

  return l;
}

}

#endif
