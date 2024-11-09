# PCAP to PKT Converter

This tool converts a PCAP capture file to a custom PKT format.

This is used as part of the pre-processing pipeline for the EUCLID experiments.

## Dependencies

- [CMake](https://cmake.org/)

- [Pcap++](https://github.com/seladb/PcapPlusPlus/)

## How to compile

**Note**: If the installation directory of the Pcap++ is not under ```/usr/lib/pcapplusplus/```, you should configure it accordingly in the ```CMakeLists.txt``` file or provide its path during generation on the second step accordingly.

1. Setup and create the build directory
```sh
mkdir build && cd build
```

2. Generate the build files using cmake
```sh
cmake ..
```
Example providing the location of Pcap++:
```sh
cmake .. -DPcapPlusPlus_ROOT=/usr/lib/pcapplusplus/cmake/pcapplusplus
```

3. Compile the tool
```sh
make
```

## How to use the tool

For the execution of the tool, there are only two parameters required:
1. The input pcap file to be converted
2. The output path for the PKT file

Example:
```sh
pcap-pkt-converter -i /path/to/input.pcap -o /path/to/output.pkt
```
