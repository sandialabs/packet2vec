#include <boost/python.hpp>
#include <boost/python/numpy.hpp>
#include <ParallelPcap/Pcap.hpp>
#include <ParallelPcap/Util.hpp>
#include <ParallelPcap/CountDictionary.hpp>
#include <ParallelPcap/Packet.hpp>
#include <ParallelPcap/Packet2Vec.hpp>
#include <ParallelPcap/PacketInfo.hpp>
#include <ParallelPcap/DARPA2009.hpp>
#include <ParallelPcap/ISOT.hpp>
#include <ParallelPcap/ReadPcap.hpp>
#include <ParallelPcap/TestPcap.hpp>
#include <vector>

BOOST_PYTHON_MODULE(parallelpcap)
{
  using namespace parallel_pcap;
  using namespace boost::python;

  // Initialization
  Py_Initialize();
  boost::python::numpy::initialize();

  class_<Pcap>("Pcap", init<std::string>())
    .def("getNumPackets", &Pcap::getNumPackets)
    .def("applyNgramOperator", &Pcap::applyNgramOperator)
  ;

  class_<std::vector<std::vector<std::string>>>("TwoDStringVector");


  def("flatten", flatten<std::string>);

  def("setParallelPcapThreads", setGlobalNumThreads);

  class_<PacketHeader>("PacketHeader", 
    init<uint32_t, uint32_t, uint32_t, uint32_t>())
      .def("getTimestampSeconds", &PacketHeader::getTimestampSeconds)
      .def("getTimestampUseconds", &PacketHeader::getTimestampUseconds)
      .def("getIncludedLength", &PacketHeader::getIncludedLength)
      .def("getOriginalLength", &PacketHeader::getOriginalLength)
  ;

  /**
   * Adds the Packet2Vec with DARPA2009 labeler class to our parallelpcap module
   * "return_value_policy" tells boost that our methods are returning pointers
   */
  class_<Packet2Vec<DARPA2009>>("Packet2Vec_DARPA2009", 
    init<numpy::ndarray&, std::string, bool>())
      .def(init<std::string, bool>())
      .def("generateX", &Packet2Vec<DARPA2009>::generateX)
      .def("generateY", &Packet2Vec<DARPA2009>::generateY)
      .def("generateXTokens", &Packet2Vec<DARPA2009>::generateXTokens)
      .def("attacks", &Packet2Vec<DARPA2009>::attacks)
  ;

  /**
   * Adds the Packet2Vec with ISOT labeler class to our parallelpcap module
   * "return_value_policy" tells boost that our methods are returning pointers
   */
  class_<Packet2Vec<ISOT>>("Packet2Vec_ISOT", 
    init<numpy::ndarray&, std::string, bool>())
      .def(init<std::string, bool>())
      .def("generateX", &Packet2Vec<ISOT>::generateX)
      .def("generateY", &Packet2Vec<ISOT>::generateY)
      .def("generateXTokens", &Packet2Vec<ISOT>::generateXTokens)
      .def("attacks", &Packet2Vec<ISOT>::attacks)
  ;


  class_<ReadPcap>("ReadPcap", 
    init<std::string, list&, size_t, std::string, bool>())
      .def(init<std::string,
                list&, 
                size_t,
                std::string, 
                std::string, 
                std::string,
                bool>()
      )
  ;

  class_<TestPcap>("TestPcap", 
    init<std::string, numpy::ndarray&, list&, std::string, bool>())
      .def("featureVector", &TestPcap::featureVector)
      .def("labelVector", &TestPcap::labelVector)
  ;

}
