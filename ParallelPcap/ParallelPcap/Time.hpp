#ifndef PARALLEL_PCAP_TIME_HPP
#define PARALLEL_PCAP_TIME_HPP

#include <ctime>
#include <iomanip>

namespace parallel_pcap {

/**
 * Calculates the difference in seconds between local time and utc. 
 */
long local_utc_diff()
{
  time_t rawtime;
  time(&rawtime);
  time_t gtm = std::mktime(gmtime(&rawtime));
  time_t ltm = std::mktime(localtime(&rawtime));
  time_t difference = ltm-gtm;
  return difference;
}

/**
 * Converts a datetime string to utc seconds since epoch. An example format is
 * "%Y-%m-%dT%H:%M:%S".
 *
 * \param datetime The datetime as a string.
 * \param format The format string.
 *
 * \return A long with the seconds since epoch.
 */
long utc_seconds_from_datetime(std::string datetime , std::string format)
{
  std::istringstream ss(datetime);
  long difference = local_utc_diff(); 
  std::tm t = {};
  ss >> std::get_time(&t, "%Y-%m-%dT%H:%M:%S");
  time_t seconds = std::mktime(&t);
  //std::cout << "seconds " << seconds << std::endl;
  //std::tm* gm = std::gmtime(&seconds);
  //long secondsgm = std::mktime(gm);
  seconds = seconds + difference;
  return seconds;

  //std::cout << "seconds after gm " << seconds << std::endl;
  //long ms = 1000000 * seconds;
  //std::cout << "microseconds " << microseconds << std::endl;
  //std::cout << "ms " << ms << std::endl;
  //ms = ms + boost::lexical_cast<int>(microseconds);
}



} // end namespace parallel_pcap

#endif
