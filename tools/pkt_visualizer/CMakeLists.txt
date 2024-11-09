cmake_minimum_required(VERSION 3.12)
project(pkt-visualizer)

# Set C++20
set(CMAKE_CXX_STANDARD 20)

# popen()/pclose() are not C++ standards
set(CMAKE_CXX_EXTENSIONS ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Add the common utilities directory
add_subdirectory(../common common_build)

# Create executable
add_executable("${PROJECT_NAME}" src/main.cpp)

# Link the common utilities library with the main application
target_link_libraries("${PROJECT_NAME}" PRIVATE common_utilities)

target_include_directories("${PROJECT_NAME}" PRIVATE include)

# We want to have the binary compiled in the same folder as the .cpp to be near the PCAP file
set_target_properties("${PROJECT_NAME}" PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/build")
