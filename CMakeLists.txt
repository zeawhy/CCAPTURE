cmake_minimum_required(VERSION 3.5)
project(CPCAP)

set(CMAKE_CXX_STANDARD 11)
set(PCAP_INC_DIR pcap/include)
set(PCAP_LINK_DIR pcap/lib)
include_directories(${PCAP_INC_DIR} )
link_directories(${PCAP_LINK_DIR})
link_libraries("pcap")

add_executable(CPCAP main.cpp)
target_link_libraries(CPCAP pcap)

