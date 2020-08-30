#ifndef PARALLELPCAP_BYTE_MANIPULATIONS_HPP
#define PARALLELPCAP_BYTE_MANIPULATIONS_HPP

namespace parallel_pcap {

template <typename OutputType>
class ByteTransformer
{
public:
  static size_t const sizeOutputType = sizeof(OutputType);
  OutputType operator()(unsigned char const* array) const
  {
    OutputType out = 0;
    size_t offset = (sizeOutputType - 1) * 8;
    for(int i = 0; i < sizeOutputType; i++) {
      out |= (OutputType) array[i] << offset; 
      offset -= 8;
    }
    return out;
  }
};

template <typename OutputType>
class ByteTransformerSwapped
{
public:
  static size_t const sizeOutputType = sizeof(OutputType);
  OutputType operator()(unsigned char const* array) const
  {
    OutputType out = 0;
    size_t offset = 0;
    for(int i = 0; i < sizeOutputType; i++) {
      out |= (OutputType) array[i] << offset; 
      offset += 8;
    }
    return out;
  }
};

class AbstractUint32Transformer {
public:
  virtual uint32_t operator()(unsigned char const* array) const = 0;
};

class Uint32Transformer : public ByteTransformer<uint32_t>, 
  public AbstractUint32Transformer 
{
public:
  uint32_t operator()(unsigned char const* array) const {
    return ByteTransformer<uint32_t>::operator()(array);
  }
};

class Uint32TransformerSwapped : public ByteTransformerSwapped<uint32_t>,
  public AbstractUint32Transformer 
{
public:
  uint32_t operator()(unsigned char const* array) const {
    return ByteTransformerSwapped<uint32_t>::operator()(array);
  }
};

class AbstractUint16Transformer {
public:
  virtual uint16_t operator()(unsigned char const* array) const = 0;
};

class Uint16Transformer : public ByteTransformer<uint16_t>, 
  public AbstractUint16Transformer 
{
public:
  uint16_t operator()(unsigned char const* array) const {
    return ByteTransformer<uint16_t>::operator()(array);
  }
};

class Uint16TransformerSwapped : public ByteTransformerSwapped<uint16_t>,
  public AbstractUint16Transformer 
{
public:
  uint16_t operator()(unsigned char const* array) const {
    return ByteTransformerSwapped<uint16_t>::operator()(array);
  }
};

class AbstractInt32Transformer {
public:
  virtual int32_t operator()(unsigned char const* array) const = 0;
};

class Int32Transformer : public ByteTransformer<int32_t>, 
  public AbstractInt32Transformer 
{
public:
  int32_t operator()(unsigned char const* array) const {
    return ByteTransformer<int32_t>::operator()(array);
  }
};

class Int32TransformerSwapped : public ByteTransformerSwapped<int32_t>,
  public AbstractInt32Transformer 
{
public:
  int32_t operator()(unsigned char const* array) const {
    return ByteTransformerSwapped<int32_t>::operator()(array);
  }
};







}

#endif
