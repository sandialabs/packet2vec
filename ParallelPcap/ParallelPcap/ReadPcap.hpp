#ifndef READ_PCAP_HPP
#define READ_PCAP_HPP
#define DETAIL_TIMING

#include <ParallelPcap/Pcap.hpp>
#include <ParallelPcap/Util.hpp>
#include <ParallelPcap/CountDictionary.hpp>
#include <boost/program_options.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/filesystem.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/vector.hpp>
#include <iostream>
#include <fstream>
#include <chrono>

namespace bp = boost::python;
namespace po = boost::program_options;
namespace ba = boost::archive;
namespace bf = boost::filesystem;

namespace parallel_pcap {

class ReadPcap {

public:
  ReadPcap(
    std::string inputDir,
    bp::list &ngrams,
    size_t vocabSize,
    std::string outputDir,
    bool debug
  ) : _ngrams(ngrams), _vocabSize(vocabSize), 
    _filePrefixIntVector("intVector"),
    _filePrefixIntVectorVector("intVectorVector"),
    _outputDir(outputDir), _msg(debug) { this->processFiles(inputDir); }

  ReadPcap(
    std::string inputDir,
    bp::list &ngrams,
    size_t vocabSize,
    std::string filePrefixIntVector,
    std::string filePrefixIntVectorVector,
    std::string outputDir,
    bool debug
  ) : _ngrams(ngrams), _vocabSize(vocabSize), 
      _filePrefixIntVector(filePrefixIntVector),
      _filePrefixIntVectorVector(filePrefixIntVectorVector), 
      _outputDir(outputDir), _msg(debug) { this->processFiles(inputDir); }
  ~ReadPcap() { }

private:
  /// Vector of files to read
  std::vector<std::string> _files;

  /// This holds the list of ngram sizes that we want to compute
  bp::list _ngrams;

  /// The top vocabSize ngrams are given integer ids. The uncommon ones
  /// are assigned the UNK (unknown) symbol.
  size_t _vocabSize;

  /// Prefix to use for the files that have the vector of int data.
  std::string _filePrefixIntVector;

  /// Prefix to use for the files that have the vector of vector of int data.
  std::string _filePrefixIntVectorVector;

  /// The path to the output directory where files are written.
  std::string _outputDir;

  /// Messenger for printing
  Messenger _msg;

  void processFiles(std::string &inputfile);

  void createDirectories();
};

void ReadPcap::createDirectories()
{
  // Add slash to outputDir string if not there
  if (this->_outputDir.back() != '/') 
    this->_outputDir.push_back('/'); 
  
  // intVector
  if (!bf::exists(this->_outputDir + "intVector/"))
    bf::create_directory(this->_outputDir + "intVector/");

  // intVectorVector
  if (!bf::exists(this->_outputDir + "intVectorVector/"))
    bf::create_directory(this->_outputDir + "intVectorVector/");

  // pcaps
  if (!bf::exists(this->_outputDir + "pcaps/"))
    bf::create_directory(this->_outputDir + "pcaps/");

  // dictionary
  if (!bf::exists(this->_outputDir + "dict/"))
    bf::create_directory(this->_outputDir + "dict/");
}

void ReadPcap::processFiles(std::string &inputDir) 
{
  auto everythingt1 = std::chrono::high_resolution_clock::now();
  typedef CountDictionary<std::string, StringHashFunction> DictionaryType;

  // Create directories
  this->createDirectories();

  // Read the list of files to be read
  for (bf::directory_iterator itr(inputDir); itr!=bf::directory_iterator(); ++itr)
  {
      this->_files.push_back(itr->path().string());
  }

  // Create the dictionary
  DictionaryType d(this->_vocabSize);

  this->_msg.printMessage("Total numer of files " + std::to_string(this->_files.size()));

  /// We run through all the pcap files.  In this first pass we
  /// 1) Create a pcap object from each file and save that to disk using
  ///    Boost serialize.
  /// 2) Create a vector of all the string ngrams found in the pcap file.
  /// 3) Feed that vector of string ngrams into the dictionary object to
  ///    iteratively update the dictionary counts for each ngram. 
  for (size_t i = 0; i < this->_files.size(); i++) 
  {
    std::string message = "First pass: Processing pcap file " 
                          + this->_files[i]
                          + " number " + std::to_string(i + 1) 
                          + " out of " + std::to_string(this->_files.size());
    this->_msg.printMessage(message);
    
    auto t1 = std::chrono::high_resolution_clock::now();
    Pcap pcap(this->_files[i]);
    auto t2 = std::chrono::high_resolution_clock::now();
    
    this->_msg.printDuration("Time to create pcap object:", t1, t2);

    /// Save pcap file on first pass for later use
    bf::path p(this->_files[i]);
    std::string save_path = this->_outputDir + "pcaps/" + 
                            p.stem().string() + ".bin";
    std::ofstream ofs(save_path);
    ba::text_oarchive ar(ofs);
    ar << pcap;

    // Calculate the ngrams
    std::vector<std::vector<std::string>> ngramVector;
    typedef std::vector<std::string> OutputType;
    this->_msg.printMessage("Calculating Ngrams");

    for (size_t i = 0; i < bp::len(this->_ngrams); ++i) {
      size_t ngram = bp::extract<size_t>(this->_ngrams[i]);

      t1 = std::chrono::high_resolution_clock::now();
      NgramOperator ngramOperator(ngram);
      pcap.applyOperator<NgramOperator, OutputType>(ngramOperator,
                                                      ngramVector);
      t2 = std::chrono::high_resolution_clock::now();

      this->_msg.printDuration("Time to create ngram: ", t1, t2);
    }

    t1 = std::chrono::high_resolution_clock::now();
    std::vector<std::string> allNgrams = flatten(ngramVector);
    t2 = std::chrono::high_resolution_clock::now();
    this->_msg.printDuration("Time to flatten ngram: ", t1, t2);
  
    t1 = std::chrono::high_resolution_clock::now();
    d.processTokens(allNgrams);
    t2 = std::chrono::high_resolution_clock::now();
    this->_msg.printDuration("Time for dictionary.processTokens: ", t1, t2);
  }

  /// The dictionary has all the counts for all the ngrams in all the files.
  /// It is time to finalize the mapping string2int and int2string.
  auto t1 = std::chrono::high_resolution_clock::now();
  d.finalize();
  auto t2 = std::chrono::high_resolution_clock::now();
  this->_msg.printDuration("Time for dictionary.finalize: ", t1, t2);

  // In this pass we 
  /// 1) read in the pcap files again,
  /// 2) translate the pcap file into a single vector of integers, and
  /// 3) also create a vector of vector of integers where the first dimension
  ///    indexes the packet.
  for (size_t i = 0; i < this->_files.size(); i++) 
  {
    bf::path p(this->_files[i]);
    std::string message = "2nd pass: Processing pcap file " 
                        + this->_files[i]
                        + " number " + std::to_string(i + 1)
                        + " out of " + std::to_string(this->_files.size());
    this->_msg.printMessage(message);

    auto t1 = std::chrono::high_resolution_clock::now();
    Pcap pcap(this->_files[i]);
    auto t2 = std::chrono::high_resolution_clock::now();
    this->_msg.printDuration("Time to create pcap object:", t1, t2);
    this->_msg.printMessage("Num packets: " + std::to_string(pcap.getNumPackets()));

    // Calculate the ngrams
    std::vector<std::vector<std::string>> ngramVector;
    typedef std::vector<std::string> OutputType;

    this->_msg.printMessage("Calculating ngrams");

    for (size_t i = 0; i < bp::len(this->_ngrams); ++i) {
      size_t ngram = bp::extract<size_t>(this->_ngrams[i]);
      
      t1 = std::chrono::high_resolution_clock::now();
      NgramOperator ngramOperator(ngram);
      pcap.applyOperator<NgramOperator, OutputType>(ngramOperator, 
                                                      ngramVector);
      t2 = std::chrono::high_resolution_clock::now();
      this->_msg.printDuration("Time to create ngram: ", t1, t2);
    }

    t1 = std::chrono::high_resolution_clock::now();
    std::vector<std::string> allNgrams = flatten(ngramVector);
    t2 = std::chrono::high_resolution_clock::now();
    this->_msg.printDuration("Time to flatten ngram: ", t1, t2);
 
    /// We translate the entire vector of strings to a vector of ints and 
    /// write that out to disk. 
    t1 = std::chrono::high_resolution_clock::now();
    std::vector<size_t> translated = d.translate(allNgrams);
    t2 = std::chrono::high_resolution_clock::now();
    this->_msg.printDuration("Time for dictionary.translate (one file): ", t1, t2);

    std::string path = this->_outputDir + "intVector/" + 
      this->_filePrefixIntVector + "_" + p.stem().string() + ".bin";
    writeBinary(translated, path);

    /// Translate the vector of vector of strings into a vector of vector
    /// of ints.
    t1 = std::chrono::high_resolution_clock::now();
    std::vector<std::vector<size_t>> vvtranslated = d.translate(ngramVector); 
    t2 = std::chrono::high_resolution_clock::now();
    this->_msg.printDuration("Time for dictionary.translate (vector of vectors): ", t1, t2);

    path = this->_outputDir + "intVectorVector/" + 
      this->_filePrefixIntVectorVector + "_" + p.stem().string() + ".bin";
    std::ofstream ofs(path);
    boost::archive::text_oarchive oa(ofs);
    oa << vvtranslated;
  }

  // Save dictionary to disk for later use
  std::string dict_path = this->_outputDir + "dict/dictionary.bin";
  std::ofstream d_ofs(dict_path);
  ba::text_oarchive d_ar(d_ofs);
  d_ar << d;

  auto everythingt2 = std::chrono::high_resolution_clock::now();
  this->_msg.printDuration("Time for everything: ", everythingt1, everythingt2);
}

}


#endif
