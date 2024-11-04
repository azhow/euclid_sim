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

## PKT File Format

The PKT file format is a format that simplifies the input data for the EUCLID experiments by reducing the data to only what is required for the EUCLID system - the source and destination IPs. This allows the experiments to execute faster.

The PKT file format is a simple binary format which consists of:
1. A few metadata fields:
    - 7 bytes - "PKTV001" -> Indicating the PKTV001 file format - Literal ASCII
    - 4 bytes - uint64_t -> Number of entries in the file
2. For each of the ```n``` entries in the file:
    - 4 bytes - uint32_t -> The non-network ordered source IP address
    - 4 bytes - uint32_t -> The non-network ordered destination IP address
    - 4 bytes - uint32_t -> Reserved field 1 - **More info below**
    - 4 bytes - uint32_t -> Reserved field 2 - **More info below**

### Reserved fields

#### Reserved field 1

Empty for now.

#### Reserved field 2

The first bit indicates if the source IP address is a known malicious source.
