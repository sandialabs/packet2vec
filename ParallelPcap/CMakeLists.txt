project(ParallelPcap)
cmake_minimum_required (VERSION 2.8.12)

ENABLE_LANGUAGE(CXX)

# This optimization level will vectorize loops
set(GCC_COVERAGE_COMPILE_FLAGS "-g -O2 -std=c++11 -pthread -Wl,--no-as-needed -ftree-vectorize -msse2 -fopt-info-vec-optimized")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS}")

find_package(Threads)

find_package(Boost REQUIRED unit_test_framework program_options 
                            system python3 numpy3 filesystem serialization)

find_package(PythonLibs)

message("Boost " ${Boost_INCLUDE_DIR})
message("Boost " ${Boost_LIBRARIES})
include_directories(${Boost_INCLUDE_DIR})

include_directories(./)

##################### ParallelPcapLib header only ###############
# Define ParallelPcap as library using INTERFACE keyword, which is used
# for header only libraries.
add_library(ParallelPcapLib INTERFACE)
target_include_directories(ParallelPcapLib INTERFACE ./)

###################### Python extensions ###############
find_package( PythonLibs 3 REQUIRED)
include_directories( ${PYTHON_INCLUDE_DIRS} )
file (GLOB PYTHON_EXT "PythonExtensions/*.cpp")
source_group("PythonExtensions" FILES ${PYTHON_EXT})
add_library(parallelpcap SHARED ${PYTHON_EXT})
set_target_properties(parallelpcap PROPERTIES PREFIX "" )
set_target_properties(parallelpcap PROPERTIES LIBRARY_OUTPUT_DIRECTORY "bin")
target_link_libraries(parallelpcap ${Boost_LIBRARIES})
install(TARGETS parallelpcap DESTINATION lib)

####################### Executables #####################
file (GLOB EXE_SRCS ExecSource/*.cpp)

foreach(exeSrc ${EXE_SRCS})
  get_filename_component(exeName ${exeSrc} NAME_WE)

  add_executable(${exeName} ${exeSrc})

  target_link_libraries(${exeName} ${CMAKE_THREAD_LIBS_INIT})  
  target_link_libraries(${exeName} ParallelPcapLib)
  target_link_libraries(${exeName} ${Boost_LIBRARIES})
  target_link_libraries(${exeName} ${PYTHON_LIBRARY})
  
  set_target_properties(${exeName} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "bin")

endforeach(exeSrc)
