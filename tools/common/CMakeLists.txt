# tools/common/CMakeLists.txt

# Set the project name
project(common_utilities)

# Set the C++ standard to C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Collect all source files (assuming they are in the src directory)
file(GLOB_RECURSE COMMON_SRC_FILES src/*.cpp)

# Collect all header files (assuming they are in the include directory)
file(GLOB_RECURSE COMMON_HEADER_FILES include/*.h)

# Define the library using the project name
add_library(${PROJECT_NAME} STATIC ${COMMON_SRC_FILES} ${COMMON_HEADER_FILES})

# Include directories for this library
target_include_directories(${PROJECT_NAME} PUBLIC include)
