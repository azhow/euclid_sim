# PKT Mixer

This tool mixes a legitimate and a malicious PKT file.

The output of this tool is used as input for the actual experiments.

## Dependencies

- [CMake](https://cmake.org/)

## How to compile

1. Setup and create the build directory
```sh
mkdir build && cd build
```

2. Generate the build files using cmake
```sh
cmake ..
```

3. Compile the tool
```sh
make
```

## How to use the tool

For the execution of the tool, there are only five parameters required:
1. The legitimate pkt file.
2. The malicious pkt file.
3. The value ```n``` for the number of packets in the detection portion of the experiment.
4. The value ```p``` as the percentage of malicious traffic to be mixed in with legitimate data. It is within [0,1.0]
5. The output directory path for the newly created dataset.

Example:
```sh
pkt-mixer -m /path/to/malicious.pkt -l /path/to/legitimate.pkt -o /path/to/output.pkt -n 134217728 -p 0.10
```
