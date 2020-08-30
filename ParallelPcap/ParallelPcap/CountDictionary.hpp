#ifndef COUNT_DICTIONARY
#define COUNT_DICTIONARY

#include <stdlib.h>
#include <set>
#include <vector>
#include <thread>
#include <mutex>
#include <map>
#include <atomic>
#include <boost/python.hpp>
#include <boost/serialization/serialization.hpp>
#include <ParallelPcap/Util.hpp>

#define DICTIONARY_SIZE_FACTOR 2.0 

namespace ba = boost::archive;

namespace parallel_pcap {

class CountDictionaryException : public std::runtime_error {
public:
  CountDictionaryException(char const * message) : std::runtime_error(message) 
  {}
  CountDictionaryException(std::string message) : std::runtime_error(message)
  {}
};

template <typename KeyType, typename HF>
class CountDictionary
{
private:
  // Total number of keys found in the provided data.
  std::atomic<size_t> numKeys;

  // How many of the most frequent keys are assigned ids.
  size_t vocabSize;

  /// The hash function to use on the keys.
  HF hash;

  /// How many hash slots there are.  Set by estimateCapacity.
  size_t capacity = 0;

  /// An array of mutexes.  The array size is capacity.
  std::mutex* mutexes = 0;  

  /// Mapping from keys to how often the key occurs.  
  /// The array is of size capacity.
  std::vector<std::map<KeyType, size_t>> counts;

  /// Mapping from keys to the assigned integer key.
  std::vector<std::map<KeyType, size_t>> word2Int;

  /// Used to indicate if data structures have been allocated
  bool initialized = false;

  /// Used to indicate that the word2int mapping is complete
  bool finalized = false;

public:

  static const size_t UNK = 0;

  /**
   * Copy constructor. 
   */
  CountDictionary( CountDictionary<KeyType, HF> const& other);

  /**
   * The constructor.  Only vocabSize most frequent tokens get a unique
   * identifier.
   *
   * \param vocabSize Size of vocabulary.
   */
  CountDictionary(size_t vocabSize);

  /**
   * The constructor takes a vector of KeyType, gets the count for each
   * KeyType, and then prunes the keys to be of size vocabSize.  Each of the
   * vocabSize most frequent keys is assigned an integer.  All other keys
   * are assigned a UNK symbol (unknown).
   * \param v The vector of all the keys.
   * \param vocabSize We assign ids to the vocabSize most frequent keys.
   */

  ~CountDictionary();

  size_t getCapacity() const { return capacity; } 

  /**
   * Returns the frequency of the provided key.
   * \param key The key we are asking about.
   * \return Returns the total count of how many times the key occurred.
   */
  size_t getCount(KeyType key) const;

  /**
   * Returns the integer id of the provided key.  If the key does not
   * have an id, the function returns the UNK (unknown) id.
   * \param key The key that we are asking about.
   * \return Returns the integer id associated with the key.
   */
  size_t getWord2Int(KeyType key) const;

  /**
   * Returns the total number of keys found in the data.
   */
  size_t getNumKeys() const { return numKeys; }

  /**
   * Creates the word2int mapping.
   * This should be called after all processTokens() calls have been completed.
   * The processTokens() calls create an exact count of how many times each
   * token occurred.  When there is no more tokens to process, this call
   * creates the mapping from token to integer representation.
   */
  void finalize();

  /**
   * Takes a vector of tokens and keeps track of the total count for each
   * unique token.
   */ 
  void processTokens(std::vector<KeyType> const& v);

  /**
   * Takes the vector of tokens and translates it into the integer 
   * representations.  Finalize must be called before this can be called.
   */
  std::vector<size_t> translate(std::vector<KeyType> const& v);

  /**
   * Takes the vector of vector of tokens and translates it into the integer 
   * representations.  Finalize must be called before this can be called.
   */
  std::vector<std::vector<size_t>> 
  translate(std::vector<std::vector<KeyType>> const& v);

  /**
   * Setup for boost serialize
   */
  friend class boost::serialization::access;
  template<class Archive>
  void serialize(Archive &ar, const unsigned int version) {
    ar &numKeys &vocabSize &capacity &counts &word2Int &initialized &finalized;
  }


private:
  /**
   * Takes a sample of the data and estimates how many unique keys there are.
   * Based on that, it returns a recommended size for the hash table.
   * Note: Now that we are accepting data iteratively, this is only called for
   * the first call to processTokens.  This could cause problems if the 
   * initial batch of data doesn't provide a good estimate on the total
   * number of keys.  The hash table could fill and cause lots of linear
   * searches and impact performance.
   * \param v A vector of tokens.
   */
  size_t estimateCapacity( std::vector<KeyType> const& v );

};

template <typename KeyType, typename HF>
void
CountDictionary<KeyType, HF>::
finalize()
{
  size_t numThreads = globalNumThreads;
 
  DETAIL_TIMING_BEG
  // Create an array of threads
  std::thread* threads = new std::thread[numThreads];

  // Create a vector that will hold all the key/value pairs to be 
  // sorted.
  std::vector<std::pair<KeyType, size_t>> sortedKeys;
  sortedKeys.resize(numKeys);
  DETAIL_TIMING_END("CountDictionary::fillWord2Int time to resize sortedKeys: ")

  DETAIL_TIMING_BEG
  std::atomic<size_t> keyCounter(0);

  auto fillFunction = [this, &sortedKeys, &keyCounter, numThreads]
    (size_t threadId)
  {
    size_t beg = getBeginIndex(this->capacity, threadId, numThreads);
    size_t end = getEndIndex(this->capacity, threadId, numThreads);

    size_t localNumKeys = 0;

    for(size_t i = beg; i < end; i++) {
      localNumKeys += counts[i].size();
    }

    size_t startIndex = keyCounter.fetch_add(localNumKeys);

    for(size_t i = beg; i < end; i++) 
    {
      for (auto it = counts[i].begin(); it != counts[i].end(); ++it)
      {
        sortedKeys[startIndex] = *it;
        startIndex++;    
      }
    }
  };
 
  for(size_t i = 0; i < numThreads; i++) {
    threads[i] = std::thread(fillFunction, i);
  }

  for(size_t i = 0; i < numThreads; i++) {
    threads[i].join();
  }
  DETAIL_TIMING_END("CountDictionary::fillWord2Int time to fill sortedKeys: ")

  DETAIL_TIMING_BEG
  auto sortbysec = [](std::pair<KeyType, size_t> const& a,
                      std::pair<KeyType, size_t> const& b)
  {
    return (a.second > b.second);
  };

  std::sort(sortedKeys.begin(), sortedKeys.end(), sortbysec);
  DETAIL_TIMING_END("CountDictionary::fillWord2Int time to sort sortedKeys: ")

  DETAIL_TIMING_BEG
  auto assignIdFunction = [this, &sortedKeys, numThreads](size_t threadId)
  {
    size_t numItems = sortedKeys.size() < this->vocabSize ? 
                        sortedKeys.size() : this->vocabSize;

    size_t beg = getBeginIndex(numItems, threadId, numThreads);
    size_t end = getEndIndex(numItems, threadId, numThreads);

    for(size_t i = beg; i < end; i++) {
      sortedKeys[i].second = i + 1;
    }
  };


  for(size_t i = 0; i < numThreads; i++) {
    threads[i] = std::thread(assignIdFunction, i);
  }

  for(size_t i = 0; i < numThreads; i++) {
    threads[i].join();
  }
  DETAIL_TIMING_END("CountDictionary::fillWord2Int time to assign ids: ")

  DETAIL_TIMING_BEG
  auto fillWord2IntFunction = [this, &sortedKeys, numThreads](size_t threadId)
  {
    size_t numItems = sortedKeys.size() < this->vocabSize ? 
                        sortedKeys.size() : this->vocabSize;

    size_t beg = getBeginIndex(numItems, threadId, numThreads);
    size_t end = getEndIndex(numItems, threadId, numThreads);

    for(size_t i = beg; i < end; i++) {
      size_t index = hash(sortedKeys[i].first) % capacity;
      this->mutexes[index].lock();
      this->word2Int[index][sortedKeys[i].first] = sortedKeys[i].second;
      this->mutexes[index].unlock();
    }
  };

  for(size_t i = 0; i < numThreads; i++) {
    threads[i] = std::thread(fillWord2IntFunction, i);
  }

  for(size_t i = 0; i < numThreads; i++) {
    threads[i].join();
  }

  DETAIL_TIMING_END("CountDictionary::fillWord2Int time to create word2int: ")

  finalized = true;
  delete[] threads; 
}

template <typename KeyType, typename HF>
std::vector<std::vector<size_t>>
CountDictionary<KeyType, HF>::
translate(std::vector<std::vector<KeyType>> const& v)
{
  if (!finalized) {
    throw CountDictionaryException("Tried to translate vector but finalized"
      " has not been called.");
  }

  DETAIL_TIMING_BEG
  size_t numThreads = globalNumThreads;
  std::thread* threads = new std::thread[numThreads];
  std::vector<std::vector<size_t>> data;
  data.resize(v.size());
  DETAIL_TIMING_END("CountDictionary::translate time to resize data: ")

  DETAIL_TIMING_BEG
  auto translateDataFunction = [this, &v, &data, numThreads](size_t threadId)
  {
    size_t beg = getBeginIndex(v.size(), threadId, numThreads);
    size_t end = getEndIndex(v.size(), threadId, numThreads);

    for(size_t i = beg; i < end; i++) {
      data[i].resize(v[i].size());
      for(size_t j = 0; j < v[i].size(); j++) {
        data[i][j] = this->getWord2Int(v[i][j]);
      }
    }
  };

  for(size_t i = 0; i < numThreads; i++) {
    threads[i] = std::thread(translateDataFunction, i);
  }

  for(size_t i = 0; i < numThreads; i++) {
    threads[i].join();
  }

  DETAIL_TIMING_END("CountDictionary::translate time to translate data: ")

  finalized = true;
  delete[] threads; 
  return data; 


}


template <typename KeyType, typename HF>
std::vector<size_t> 
CountDictionary<KeyType, HF>::
translate(std::vector<KeyType> const& v)
{
  if (!finalized) {
    throw CountDictionaryException("Tried to translate vector but finalized"
      " has not been called.");
  }
 
  DETAIL_TIMING_BEG
  size_t numThreads = globalNumThreads;
  std::thread* threads = new std::thread[numThreads];
  std::vector<size_t> data;
  data.resize(v.size());
  DETAIL_TIMING_END("CountDictionary::translate time to resize data: ")

  DETAIL_TIMING_BEG
  auto translateDataFunction = [this, &v, &data, numThreads](size_t threadId)
  {
    size_t beg = getBeginIndex(v.size(), threadId, numThreads);
    size_t end = getEndIndex(v.size(), threadId, numThreads);

    for(size_t i = beg; i < end; i++) {
      data[i] = this->getWord2Int(v[i]);
    }
  };

  for(size_t i = 0; i < numThreads; i++) {
    threads[i] = std::thread(translateDataFunction, i);
  }

  for(size_t i = 0; i < numThreads; i++) {
    threads[i].join();
  }

  DETAIL_TIMING_END("CountDictionary::translate time to translate data: ")

  finalized = true;
  delete[] threads; 
  return data; 
}

template <typename KeyType, typename HF>
CountDictionary<KeyType, HF>::
CountDictionary( 
  CountDictionary<KeyType, HF> const& other)
{
  numKeys = other.numKeys.load();
  capacity = other.capacity;
  mutexes = new std::mutex[capacity];
  counts.resize(capacity);
  word2Int.resize(capacity);

  for (size_t i = 0; i < capacity; i++) {
    counts[i] = other.counts[i];
    word2Int[i] = other.word2Int[i];
  }
}

template <typename KeyType, typename HF>
CountDictionary<KeyType, HF>::
CountDictionary(size_t _vocabSize)
: vocabSize(_vocabSize), numKeys(0)
{}

template <typename KeyType, typename HF>
void
CountDictionary<KeyType, HF>::
processTokens(std::vector<KeyType> const& v)
{
  if (!initialized) 
  {
    DETAIL_TIMING_BEG
    this->capacity = estimateCapacity(v);
    DETAIL_TIMING_END("CountDictionary::CountDictionary time to estimate: ")
    mutexes = new std::mutex[capacity];
    counts.resize(capacity);
    word2Int.resize(capacity);

    initialized = true;
  }

  size_t numThreads = globalNumThreads;

  // Create an array of threads
  std::thread* threads = new std::thread[numThreads];

  DETAIL_TIMING_BEG
  // Function passed the threads
  auto f = [this, &v, numThreads](size_t threadId)
  {

    size_t size = v.size();
    size_t beg = getBeginIndex(size, threadId, numThreads);
    size_t end = getEndIndex(size, threadId, numThreads);

    for (size_t i = beg; i < end; i++) {
      KeyType key = v[i]; 

      // Find the slot by hashing the key
      size_t index = hash(key) % capacity;
      
      // Lock out the slot
      mutexes[index].lock();
      
      if (counts[index].count(key) < 1) {
        counts[index].insert(std::make_pair(key, 1));
        numKeys.fetch_add(1);
      } else {
        counts[index][key] += 1;
      }

      // Done with lock
      mutexes[index].unlock();     
    }
  };
  
  for(size_t i = 0; i < numThreads; i++) {
    threads[i] = std::thread(f, i);
  }

  for(size_t i = 0; i < numThreads; i++) {
    threads[i].join();
  }
  DETAIL_TIMING_END("CountDictionary::CountDictionary Time to fill counts: ");

  delete[] threads;


}

template <typename KeyType, typename HF>
CountDictionary<KeyType, HF>::
~CountDictionary()
{
  if (mutexes) delete[] mutexes;
  //if (counts)  delete[] counts;
  //if (word2Int) delete[] word2Int;
}

template <typename KeyType, typename HF>
size_t
CountDictionary<KeyType, HF>::
estimateCapacity( std::vector<KeyType> const& v )
{
  // We are going to sample the data to see about how many keys there are.
  double samplePercent = 0.05;
  size_t size = v.size();
  size_t sampleSize = samplePercent * size; // Use a 5% sample

  // We create an array of sets where the size of the array is simply
  // the sample size
  std::set<KeyType>* sampleValues = new std::set<KeyType>[sampleSize];
  
  int numThreads = globalNumThreads;

  // Create an array of threads
  std::thread* threads = new std::thread[numThreads];
  
  // Each array has its own mutex
  std::mutex* mutexes = new std::mutex[sampleSize];

  // Keeps track of how many unique keys we've seen while we sample
  std::atomic<size_t> numUnique(0);
  
  // Function passed the threads
  auto f = [this, sampleValues, size, sampleSize, numThreads, &v,
            mutexes](size_t threadId, std::atomic<size_t>& numUnique)
                                 
  {
    // We don't actually need block indexing since we grab samples at random,
    // but this still load balances the work for us.
    size_t beg = getBeginIndex(sampleSize, threadId, numThreads);
    size_t end = getEndIndex(sampleSize, threadId, numThreads);

    for (size_t i = beg; i < end; i++) {
      // Grab a random key (with replacement) from the vector
      KeyType key = v[rand() % size]; 

      // Find the slot by hashing the key
      size_t index = hash(key) % sampleSize;
      
      // Lock out the slot
      mutexes[index].lock();
      
      // If no in the slot's set, add it and increment numUnique.
      if (sampleValues[index].count(key) < 1) {
        sampleValues[index].insert(key);
        numUnique.fetch_add(1);
      } 

      // Done with lock
      mutexes[index].unlock();     
    }
  };
  
  for(size_t i = 0; i < numThreads; i++) {
    threads[i] = std::thread(f, i, std::ref(numUnique));
  }

  for(size_t i = 0; i < numThreads; i++) {
    threads[i].join();
  }
  
  delete[] threads;
  delete[] sampleValues;
  delete[] mutexes;

  return DICTIONARY_SIZE_FACTOR * 
    static_cast<size_t>(static_cast<double>(numUnique) / samplePercent) ;

}

template <typename KeyType, typename HF>
size_t
CountDictionary<KeyType, HF>::
getCount(KeyType key) const
{
  size_t index = hash(key) % capacity;
  if (counts[index].count(key) > 0) {
    return counts[index].at(key);
  }
  return 0;
}

template <typename KeyType, typename HF>
size_t
CountDictionary<KeyType, HF>::
getWord2Int(KeyType key) const
{
  size_t index = hash(key) % capacity;
  if (word2Int[index].count(key) > 0) {
    size_t id = word2Int[index].at(key);
    if (id < vocabSize) {
      return word2Int[index].at(key);
    }
  }
  return UNK;
}
}
#endif
