#ifndef PARALLELPCAP_UTIL_HPP
#define PARALLELPCAP_UTIL_HPP

#include <iostream>
#include <fstream>
#include <vector>
#include <atomic>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <boost/serialization/serialization.hpp>
#include <boost/serialization/version.hpp>
#include <boost/serialization/split_free.hpp>


class Messenger
{
  public:
    Messenger(bool debug) : _debug(debug) { }
    ~Messenger() { }
    template <typename TimeType>
    void printDuration(std::string message, TimeType const& t1, TimeType const& t2) 
    {
      if (this->_debug) {
        std::cout << message 
          << static_cast<double>(std::chrono::duration_cast
              <std::chrono::milliseconds>(t2-t1).count()) / 1000
          << " seconds" << std::endl;
      }
    }

    void printMessage(std::string message) {
      if (this->_debug) {
        std::cout << message << std::endl;
      }
    }

    bool isDebug(void) {
      return this->_debug;
    }
  
  private:
    bool _debug;
};


#ifdef DETAIL_TIMING
auto t1 = std::chrono::high_resolution_clock::now();
auto t2 = std::chrono::high_resolution_clock::now();
#endif

#ifdef DETAIL_TIMING
#define DETAIL_TIMING_BEG \
  t1 = std::chrono::high_resolution_clock::now();
#else
#define DETAIL_TIMING_BEG 
#endif

#ifdef DETAIL_TIMING
#define DETAIL_TIMING_END(message) \
  t2 = std::chrono::high_resolution_clock::now(); \
  printDuration(std::string("DETAIL: ") + message, t1, t2);
#else
#define DETAIL_TIMING_END(message) 
#endif

/// Global variable indicating how many threads to use in for loops.
size_t globalNumThreads = 1;

/**
 * Sets the globalNumThreads variable.
 */
void setGlobalNumThreads(size_t t) {
  globalNumThreads = t;
}

/**
 * Used to partition an array of size num_elements into equal size portions
 * to num_streams thread.  This gives the beginning element.
 * \param num_elements Number of elements in the array.
 * \param stream_id The id of the stream (from 0 to n-1 for n threads).
 * \param num_streams The number of threads.
 */
inline
uint64_t getBeginIndex(uint64_t num_elements, size_t stream_id, 
                       size_t num_streams)
{
  return static_cast<uint64_t>((static_cast<double>(num_elements) / 
                                num_streams) * stream_id);
}

/**
 * Used to partition an array of size num_elements into equal size portions
 * to num_streams thread.  This gives the ending element (using <).
 * \param num_elements Number of elements in the array.
 * \param stream_id The id of the stream (from 0 to n-1 for n threads).
 * \param num_streams The number of threads.
 */
inline
uint64_t getEndIndex(uint64_t num_elements, 
                   size_t stream_id, 
                   size_t num_streams)
{

  return (stream_id + 1 < num_streams) ?
    static_cast<uint64_t>((static_cast<double>(num_elements) / num_streams) *
                       (stream_id + 1)) :
    num_elements;
 
}


inline
uint64_t hashFunction(std::string const& key)
{
  uint64_t hash = 0;

  for (size_t i = 0; i < key.size(); i++) {
    hash = key[i] + (hash << 6) + (hash << 16) - hash;
  }

  return hash;
}

class StringHashFunction
{
public:
  inline
  uint64_t operator()(std::string const& s) const {
    return hashFunction(s);
  }
};

class StringEqualityFunction
{
public:
  inline
  bool operator()(std::string const& s1, std::string const& s2) const
  {
    return s1.compare(s2) == 0;
  }
};


/**
 * Takes a vector of vectors of KeyType, and flattens them to be just one
 * vector of KeyType.  For example, you can have a bunch of packets that 
 * are vectors of strings.  The result of calling this function would be to
 * combine all the strings of all the packets into one big vector.
 */
template <typename KeyType>
std::vector<KeyType> flatten(std::vector<std::vector<KeyType>> const& vec)
{
  DETAIL_TIMING_BEG
  std::vector<KeyType> rvec;

  size_t numThreads = globalNumThreads;
  std::thread* threads = new std::thread[numThreads];  
  
  // First we get the total number of ngrams so that we can allocate
  // the vector to be of that size.
  std::atomic<uint64_t> totalNumNgrams( 0 );  

  auto countFunction = [&vec, numThreads, &totalNumNgrams](size_t threadId) {
    
    uint64_t beg = getBeginIndex(vec.size(), threadId, numThreads); 
    uint64_t end = getEndIndex(vec.size(), threadId, numThreads); 

    size_t localCount = 0;

    for(size_t i = beg; i < end; i++) {
      localCount += vec[i].size();
    }

    totalNumNgrams.fetch_add(localCount);
  };

  for(size_t i = 0; i < numThreads; i++) { 
    threads[i] = std::thread(countFunction, i);
  }

  for(size_t i = 0; i < numThreads; i++) { threads[i].join(); }
  DETAIL_TIMING_END("flatten: Time to count ngrams: ");

  
  DETAIL_TIMING_BEG
  rvec.resize(totalNumNgrams); 
  DETAIL_TIMING_END("flatten: Time to resize rvec: ")

  DETAIL_TIMING_BEG
  totalNumNgrams = 0;  

  auto flattenFunction = [&vec, &rvec, numThreads, 
                          &totalNumNgrams](size_t threadId) {
    
    uint64_t beg = getBeginIndex(vec.size(), threadId, numThreads); 
    uint64_t end = getEndIndex(vec.size(), threadId, numThreads); 

    size_t localCount = 0;

    for(size_t i = beg; i < end; i++) {
      localCount += vec[i].size();
    }

    size_t start = totalNumNgrams.fetch_add(localCount);
    for(size_t i = beg; i < end; i++) {
      for(auto s : vec[i]) {
        rvec[start] = s;
        start++;
      }
    }
  };

  for(size_t i = 0; i < numThreads; i++) { 
    threads[i] = std::thread(flattenFunction, i);
  }
  for(size_t i = 0; i < numThreads; i++) { threads[i].join(); }

  delete[] threads;
  DETAIL_TIMING_END("flatten: Time to fill up rvec: ")

  return rvec;
}

/**
 * Takes a vector and writes it in binary form to a file.
 *
 * \param v The vector to be written.
 * \param path Where the file should be written.
 */
template <typename T>
void writeBinary(std::vector<T> v, std::string path)
{
  std::ofstream stream;
  stream.open(path, std::ios::binary);

  for ( T item : v )
  {
    stream.write(reinterpret_cast<char*>(&item), sizeof(item));
  }
  
  stream.close();
}

/**
 * Reads a binary file and returns a vector of the values in the file.
 *
 * \param path The location of the binary file.
 * \return Returns a vector of values found in the binary file.
 */
template <typename T>
std::vector<T> readBinary(std::string path)
{
  std::vector<T> v;

  std::ifstream stream;
  stream.open(path, std::ios::binary);

  if (stream) {
    stream.seekg(0, stream.end);
    int length = stream.tellg();
    stream.seekg(0, stream.beg);

    for(size_t i = 0; i < length / sizeof(T); i++) {
      size_t value;
      stream.read(reinterpret_cast<char*>(&value), sizeof(T));
      v.push_back(value); 
    }
  }
  return v; 
}

/**
 * Serialization for std::atomic
 */

namespace boost {
  namespace serialization {
    template<class Archive, class T>
    inline void save(Archive& ar, const std::atomic<T>& t, const unsigned int){
        // only the raw pointer has to be saved
        const T value = t.load();
        ar << value;
    }

    template<class Archive, class T>
    inline void load(Archive& ar, std::atomic<T>& t, const unsigned int){
        T value;
        ar >> value;
        t = value;
    }

    template<class Archive, class T>
    inline void serialize(Archive& ar, std::atomic<T>& t,
            const unsigned int file_version){
        boost::serialization::split_free(ar, t, file_version);
    }
  }
}

  
#endif
