cmake_minimum_required(VERSION 3.12)
project(pcap-pkt-converter)

# Set C++20
set(CMAKE_CXX_STANDARD 20)

# popen()/pclose() are not C++ standards
set(CMAKE_CXX_EXTENSIONS ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Setup pcapplusplus
find_package(PcapPlusPlus REQUIRED HINTS /usr/lib/pcapplusplus/cmake/pcapplusplus)

# Create executable
add_executable("${PROJECT_NAME}" src/main.cpp)
target_include_directories("${PROJECT_NAME}" PRIVATE include)

# We want to have the binary compiled in the same folder as the .cpp to be near the PCAP file
set_target_properties("${PROJECT_NAME}" PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/build")

# Link with Pcap++ libraries
target_link_libraries("${PROJECT_NAME}" PUBLIC PcapPlusPlus::Pcap++)
