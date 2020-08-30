#ifndef TEST_PCAP
#define TEST_PCAP

#include <iostream>
#include <vector>
#include <map>
#include <ParallelPcap/Pcap.hpp>
#include <ParallelPcap/CountDictionary.hpp>
#include <ParallelPcap/Packet2Vec.hpp>
#include <ParallelPcap/DARPA2009.hpp>
#include <ParallelPcap/Util.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/python.hpp>
#include <boost/python/numpy.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/vector.hpp>

namespace ba = boost::archive;
namespace bp = boost::python;
namespace np = boost::python::numpy;

namespace parallel_pcap {

// Dictionary type
typedef CountDictionary<std::string, StringHashFunction> DictionaryType;

class TestPcap {

private:
  /// Mapping from keys to the assigned integer key.
  DictionaryType _d;

  /// This holds the list of ngram sizes that we want to compute
  bp::list _ngrams;

  /// This holds the ndarray containing the embeddings
  np::ndarray _embeddings;

  /// This holds the DARPA2009 object used for labeling
  DARPA2009 _darpa;

  /// Messenger for printing to std out
  Messenger _msg;

  /// This holds the current label matrix 
  np::ndarray _labels;

public:
  /**
   * Constructor. Initializes the required data to generate feature vectors.
   * Also restores the CountDictionary saved on disk from ReadPcap.
   * \param dictPath A path to the dictionary archive.
   * \param embeddings A numpy array that has the embeddings.
   * \param ngrams A python list of ngrams to generate.
   */
  TestPcap(
    std::string dictPath, 
    np::ndarray &embeddings, 
    bp::list &ngrams,
    std::string darpafile,
    bool debug
  ) : _d(0), _ngrams(ngrams), _embeddings(embeddings), _darpa(DARPA2009(darpafile)), 
      _labels(np::array(p::list())), _msg(debug) { 
    // Restore the dictionary
    std::ifstream ifs(dictPath);
    ba::text_iarchive ar(ifs);
    ar >> this->_d;
  }

  ~TestPcap() { }

  np::ndarray labelVector() {
    return this->_labels;
  }

  /**
   * Returns a feature vector generated from a raw pcap file
   * using pre-trained embeddings.
   * \param file A path to the raw pcap file.
   * \param Returns a numpy array which contains the feature
   *        vector representing the supplied packet.
   */
  np::ndarray featureVector(std::string file) {
    // Create Pcap object
    auto time_everything1 = std::chrono::high_resolution_clock::now();

    auto t1 = std::chrono::high_resolution_clock::now();
    //this->_pcap = Pcap(file);
    Pcap pcap(file);
    auto t2 = std::chrono::high_resolution_clock::now();
    this->_msg.printDuration("TestPcap::featureVector: Time to create pcap object: ", 
                  t1, t2);

    // Print number of packets
    this->_msg.printMessage("Num packets: " + std::to_string(pcap.getNumPackets()));

    std::vector<std::vector<std::string>> ngramVector;
    typedef std::vector<std::string> OutputType;

    t1 = std::chrono::high_resolution_clock::now();
    // Calculate ngrams
    for (size_t i = 0; i < bp::len(this->_ngrams); ++i) {
      size_t ngram = bp::extract<size_t>(this->_ngrams[i]);

      NgramOperator ngramOperator(ngram);
      pcap.applyOperator<NgramOperator, OutputType>(ngramOperator,
                                                      ngramVector);
    }
    t2 = std::chrono::high_resolution_clock::now();
    this->_msg.printDuration("TestPcap::featureVector: Time to create ngram: ", t1, t2);

    // create final vector
    t1 = std::chrono::high_resolution_clock::now();
    std::vector<std::vector<size_t>> vvtranslated = 
      this->_d.translate(ngramVector);
    t2 = std::chrono::high_resolution_clock::now();
    this->_msg.printDuration("TestPcap::featureVector: Time to translate: ", t1, t2);

    t1 = std::chrono::high_resolution_clock::now();
    np::ndarray features = Packet2Vec::translateX(
      this->_embeddings,
      vvtranslated,
      this->_msg.isDebug()
    );
    t2 = std::chrono::high_resolution_clock::now();
    this->_msg.printDuration("TestPcap::featureVector: Time to create features: ", t1, t2);

    auto time_everything2 = std::chrono::high_resolution_clock::now();
    this->_msg.printDuration("TestPcap::featureVector: Time for everything: ", 
     time_everything1, time_everything2);
    this->_labels = Packet2Vec::translateY(pcap, this->_darpa, this->_msg.isDebug());  

    return features;
  }
};

}

#endif
